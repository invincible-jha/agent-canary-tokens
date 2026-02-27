# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
PipelineLocator — supply chain breach localisation for agent pipelines.

When a canary token is detected in external text, the pipeline locator
uses the token's metadata (specifically: which pipeline stage it was
injected at) combined with the detection context to narrow down where
in the agent pipeline the data leaked.

The localisation is rule-based and static — it uses the injection stage
recorded in the token's metadata to derive the most likely breach stage.
No machine learning or probabilistic inference is applied.

Usage:
    from agent_canary.pipeline_locator import PipelineLocator, PipelineStage

    locator = PipelineLocator(store)
    result = locator.locate_breach(
        token_id="some-uuid-string",
        detection_context={"detected_in": "llm_output", "source": "output_filter"},
    )
    print(result.stage, result.confidence_note)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID

from agent_canary.store import CanaryStore
from agent_canary.types import CanaryToken

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pipeline stage enum
# ---------------------------------------------------------------------------


class PipelineStage(str, Enum):
    """Logical stages within a typical agent data pipeline.

    INPUT         — Raw user input before any processing.
    RETRIEVAL     — RAG or memory retrieval step.
    PROCESSING    — Intermediate transformation or tool call handling.
    GENERATION    — LLM generation / inference step.
    OUTPUT        — Post-generation output filtering and formatting.
    STORAGE       — Writing results to a database, cache, or file.
    EXTERNAL_API  — Outbound call to a third-party API or service.
    """

    INPUT = "input"
    RETRIEVAL = "retrieval"
    PROCESSING = "processing"
    GENERATION = "generation"
    OUTPUT = "output"
    STORAGE = "storage"
    EXTERNAL_API = "external_api"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class LocatorResult:
    """The outcome of a pipeline breach localisation attempt.

    Attributes:
        stage:            The pipeline stage identified as the most likely
                          breach point based on token metadata and context.
        confidence_note:  A human-readable explanation of why this stage was
                          selected.  Not a numeric score — no numeric
                          thresholds are applied.
        canary_token_id:  The token ID that triggered the breach.
        detected_at:      UTC timestamp when the localisation was performed.
    """

    stage: PipelineStage
    confidence_note: str
    canary_token_id: str
    detected_at: datetime


# ---------------------------------------------------------------------------
# Stage derivation rules
# ---------------------------------------------------------------------------

# Maps the injection context label (token.context) to the pipeline stage
# that most likely produced the breach.  The heuristic is: if a canary was
# injected at stage X and detected externally, the breach occurred at or
# after stage X.  The rules below pick the *earliest plausible* stage.

_CONTEXT_TO_STAGE: dict[str, PipelineStage] = {
    "input": PipelineStage.INPUT,
    "user_message": PipelineStage.INPUT,
    "system_prompt": PipelineStage.INPUT,
    "retrieval": PipelineStage.RETRIEVAL,
    "rag": PipelineStage.RETRIEVAL,
    "memory": PipelineStage.RETRIEVAL,
    "tool_output": PipelineStage.PROCESSING,
    "tool_call": PipelineStage.PROCESSING,
    "processing": PipelineStage.PROCESSING,
    "llm_output": PipelineStage.GENERATION,
    "generation": PipelineStage.GENERATION,
    "output": PipelineStage.OUTPUT,
    "response": PipelineStage.OUTPUT,
    "storage": PipelineStage.STORAGE,
    "database": PipelineStage.STORAGE,
    "external_api": PipelineStage.EXTERNAL_API,
    "webhook": PipelineStage.EXTERNAL_API,
}

# Detection context keys that refine stage beyond the injection stage
_DETECTION_SOURCE_TO_STAGE: dict[str, PipelineStage] = {
    "llm_output_filter": PipelineStage.GENERATION,
    "output_filter": PipelineStage.OUTPUT,
    "memory_scan": PipelineStage.STORAGE,
    "api_monitor": PipelineStage.EXTERNAL_API,
    "input_scan": PipelineStage.INPUT,
    "retrieval_scan": PipelineStage.RETRIEVAL,
}


def _derive_stage(
    token: CanaryToken,
    detection_context: dict[str, object],
) -> tuple[PipelineStage, str]:
    """Apply static rules to derive the most likely breach stage.

    Parameters
    ----------
    token:
        The CanaryToken whose context label records where it was injected.
    detection_context:
        Caller-supplied dict with optional keys:
        ``detected_in`` (str) — which component found the token.
        ``source`` (str)      — the detection source label.

    Returns
    -------
    tuple[PipelineStage, str]:
        The derived stage and a human-readable note explaining the
        selection rationale.
    """
    injection_context = token.context.lower()
    injection_stage = _CONTEXT_TO_STAGE.get(injection_context)

    # If the detection context specifies a source, use it to refine the stage
    detected_source = str(detection_context.get("source", "")).lower()
    detected_in = str(detection_context.get("detected_in", "")).lower()

    detection_stage = (
        _DETECTION_SOURCE_TO_STAGE.get(detected_source)
        or _CONTEXT_TO_STAGE.get(detected_in)
    )

    # Rule 1: if both injection and detection stage are known, use detection
    #         stage (it represents where the data was observed externally,
    #         which is the more specific signal).
    if detection_stage is not None:
        note = (
            f"Breach detected at stage '{detection_stage.value}' "
            f"(detection source: '{detected_source or detected_in}'). "
            f"Token was injected at context '{token.context}'."
        )
        return detection_stage, note

    # Rule 2: fall back to injection stage if detection context is sparse
    if injection_stage is not None:
        note = (
            f"No precise detection source available. "
            f"Breach localised to injection stage '{injection_stage.value}' "
            f"based on token context '{token.context}'. "
            "The actual breach may be at a later stage in the pipeline."
        )
        return injection_stage, note

    # Rule 3: no mapping — default to PROCESSING as the unknown midpoint
    note = (
        f"Token context '{token.context}' does not map to a known pipeline stage. "
        f"Defaulted to '{PipelineStage.PROCESSING.value}'. "
        "Review the token metadata and re-run localisation with a richer context."
    )
    return PipelineStage.PROCESSING, note


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------


class PipelineLocator:
    """Localises canary token breaches to a specific agent pipeline stage.

    Uses the canary token's recorded injection context alongside the
    caller-supplied detection context to apply static derivation rules.
    No ML inference is performed.

    Parameters
    ----------
    store:
        The CanaryStore holding all registered tokens.  The locator
        looks up the token by ID to retrieve its metadata.

    Example
    -------
    >>> from agent_canary.store import CanaryStore
    >>> store = CanaryStore()
    >>> locator = PipelineLocator(store)
    """

    def __init__(self, store: CanaryStore) -> None:
        self._store = store

    def locate_breach(
        self,
        token_id: str,
        detection_context: dict[str, object],
    ) -> LocatorResult | None:
        """Locate the pipeline stage where a canary breach most likely occurred.

        Parameters
        ----------
        token_id:
            String representation of the UUID for the triggered canary token.
        detection_context:
            Dict with optional keys:
            ``source`` (str)       — label from the detecting component.
            ``detected_in`` (str)  — label for what surface the token was
                                     found in (e.g. ``"llm_output"``).

        Returns
        -------
        LocatorResult | None:
            A LocatorResult when the token is found in the store; None when
            the token ID is not recognised.
        """
        try:
            parsed_id = UUID(token_id)
        except ValueError:
            logger.warning(
                "PipelineLocator.locate_breach: invalid UUID string %r", token_id
            )
            return None

        token = self._store.get(parsed_id)
        if token is None:
            logger.warning(
                "PipelineLocator.locate_breach: token %s not found in store", token_id
            )
            return None

        stage, note = _derive_stage(token, detection_context)

        result = LocatorResult(
            stage=stage,
            confidence_note=note,
            canary_token_id=token_id,
            detected_at=datetime.now(tz=timezone.utc),
        )

        logger.info(
            "PipelineLocator: breach for token %s localised to stage '%s'.",
            token_id,
            stage.value,
        )

        return result

    def all_stage_labels(self) -> list[str]:
        """Return all pipeline stage label strings in definition order."""
        return [stage.value for stage in PipelineStage]
