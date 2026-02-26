# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
Strategy: FakeDocumentStrategy

Generates synthetic document references (titles, document IDs, internal
classification labels) that embed a traceable fingerprint.  If these
references surface in agent output or retrieved context, a canary has leaked.
"""

from __future__ import annotations

import random
from uuid import UUID

from agent_canary.strategies.base import CanaryStrategy
from agent_canary.types import CanaryFact, CanaryToken

_PREFIXES: tuple[str, ...] = (
    "Project", "Initiative", "Program", "Operation", "Directive",
    "Assessment", "Evaluation", "Review", "Proposal", "Blueprint",
)

_SUBJECTS: tuple[str, ...] = (
    "Nightfall", "Irongate", "Coldstream", "Ashveil", "Brightmoor",
    "Thornwall", "Ravenmark", "Duskfield", "Steelhaven", "Glassbridge",
)

_DOCTYPE: tuple[str, ...] = (
    "Internal Memo", "Technical Specification", "Architecture Proposal",
    "Security Brief", "Incident Report", "Status Update", "Risk Assessment",
    "Feasibility Study", "Operational Plan", "Audit Summary",
)

_CLASSIFICATIONS: tuple[str, ...] = (
    "SYNTHETIC-INTERNAL",
    "SYNTHETIC-CONFIDENTIAL",
    "SYNTHETIC-RESTRICTED",
    "SYNTHETIC-EYES-ONLY",
)


class FakeDocumentStrategy(CanaryStrategy):
    """
    Produces synthetic document references that embed a canary fingerprint
    in the document identifier field.

    The document ID is constructed so that the fingerprint appears verbatim,
    making it trivially scannable while looking like a plausible internal
    document tracking number.

    Parameters
    ----------
    seed:
        Optional random seed for reproducible generation in tests.
    """

    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)

    @property
    def name(self) -> str:
        return "fake_document"

    def make_fingerprint(self, token_id: UUID) -> str:
        """
        Build a document-ID-style fingerprint from the UUID.

        Example: ``DOC-A1B2-C3D4-E5F6``
        """
        hex_str = str(token_id).replace("-", "").upper()
        segment_a = hex_str[:4]
        segment_b = hex_str[4:8]
        segment_c = hex_str[8:12]
        return f"DOC-{segment_a}-{segment_b}-{segment_c}"

    def generate(self, token: CanaryToken) -> CanaryFact:
        """
        Return a CanaryFact whose `.value` is a formatted document reference.

        The document ID embeds the fingerprint so that a plain-text scan
        will locate it.
        """
        prefix = self._rng.choice(_PREFIXES)
        subject = self._rng.choice(_SUBJECTS)
        dtype = self._rng.choice(_DOCTYPE)
        classification = self._rng.choice(_CLASSIFICATIONS)
        year = 2026
        revision = self._rng.randint(1, 5)

        title = f"{prefix} {subject} — {dtype}"
        doc_id = token.fingerprint
        revision_label = f"v{revision}.0"

        value = (
            f"Document Title: {title}\n"
            f"Document ID: {doc_id}\n"
            f"Revision: {revision_label}\n"
            f"Year: {year}\n"
            f"Classification: {classification}"
        )

        return CanaryFact(
            token=token,
            value=value,
            category="document",
            description=(
                f"Synthetic document reference '{title}' (ID: {doc_id}). "
                "Appearance outside the planted location signals a data leak."
            ),
        )
