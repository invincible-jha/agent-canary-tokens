# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
Semantic similarity detection for canary tokens.

Detects paraphrased or semantically equivalent canary content by comparing
embedding vectors. Falls back to normalized string matching when no embedding
model is available, ensuring the detector always works without optional
dependencies.

Example
-------
>>> detector = SemanticCanaryDetector(threshold=0.85)
>>> canary_value = "Contact Alice at fake-alice-canary@example.com"
>>> detector.add_canary("tok_abc123", canary_value)
>>> matches = detector.scan("Reach out to Alice via fake-alice-canary@example.com")
>>> len(matches) > 0
True
"""

from __future__ import annotations

import logging
import math
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Callable, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Embedding model protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class EmbeddingModel(Protocol):
    """Protocol for any embedding model that produces float vectors.

    Compatible with sentence-transformers, OpenAI embeddings, and any
    model that follows this interface. The library never imports or
    hard-codes a specific model — callers inject their preferred model.
    """

    def encode(self, texts: list[str]) -> list[list[float]]:
        """Encode a list of texts into embedding vectors.

        Parameters
        ----------
        texts:
            Strings to embed.

        Returns
        -------
        list[list[float]]:
            One float vector per input text.
        """
        ...


# ---------------------------------------------------------------------------
# Match result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SemanticMatch:
    """A canary detected via semantic similarity or string fallback.

    Attributes:
        canary_id:    Identifier of the matched canary.
        canary_text:  The original canary text that was matched.
        match_method: Either ``"embedding"`` or ``"string_fallback"``.
        similarity:   Cosine similarity score (0.0–1.0).
        detected_in:  A snippet of the scanned text where the match occurred.
    """

    canary_id: str
    canary_text: str
    match_method: str
    similarity: float
    detected_in: str

    def __post_init__(self) -> None:
        if not (0.0 <= self.similarity <= 1.0):
            raise ValueError(
                f"similarity must be in [0.0, 1.0], got {self.similarity!r}"
            )


# ---------------------------------------------------------------------------
# Cosine similarity helper
# ---------------------------------------------------------------------------


def _cosine_similarity(vec_a: list[float], vec_b: list[float]) -> float:
    """Compute cosine similarity between two vectors.

    Returns 0.0 if either vector has zero magnitude (avoids divide-by-zero).
    """
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    mag_a = math.sqrt(sum(a * a for a in vec_a))
    mag_b = math.sqrt(sum(b * b for b in vec_b))
    if mag_a == 0.0 or mag_b == 0.0:
        return 0.0
    return dot / (mag_a * mag_b)


# ---------------------------------------------------------------------------
# String normalisation for fallback matching
# ---------------------------------------------------------------------------

_WHITESPACE_RE = re.compile(r"\s+")
_NON_ALNUM_RE = re.compile(r"[^\w\s]", re.UNICODE)


def _normalize_text(text: str) -> str:
    """Normalize *text* for string-fallback comparison.

    Steps applied:
    1. Unicode NFC normalization
    2. Lowercase
    3. Strip punctuation
    4. Collapse whitespace
    """
    normalized = unicodedata.normalize("NFC", text).lower()
    normalized = _NON_ALNUM_RE.sub(" ", normalized)
    return _WHITESPACE_RE.sub(" ", normalized).strip()


def _string_similarity(text_a: str, text_b: str) -> float:
    """Compute a simple token-overlap similarity between two strings.

    Uses Jaccard similarity over word token sets. Returns a float in [0.0, 1.0].
    """
    tokens_a = set(_normalize_text(text_a).split())
    tokens_b = set(_normalize_text(text_b).split())
    if not tokens_a and not tokens_b:
        return 1.0
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = tokens_a & tokens_b
    union = tokens_a | tokens_b
    return len(intersection) / len(union)


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class SemanticCanaryDetector:
    """Detect paraphrased canary content using embedding similarity.

    When an embedding model is provided, uses cosine similarity between
    embeddings. When no model is available, falls back to token-overlap
    Jaccard similarity, which catches partial paraphrasing such as word
    reordering, minor substitutions, or synonym replacement.

    Parameters
    ----------
    threshold:
        Minimum similarity score to consider a match. Default 0.85.
    embedding_model:
        Optional model following the ``EmbeddingModel`` protocol. If ``None``,
        the detector uses the string-similarity fallback.

    Example
    -------
    >>> sdetector = SemanticCanaryDetector(threshold=0.80)
    >>> sdetector.add_canary("c1", "secret project code name: chimera")
    >>> matches = sdetector.scan("The project code name is chimera, which is secret")
    >>> matches[0].canary_id
    'c1'
    """

    def __init__(
        self,
        threshold: float = 0.85,
        embedding_model: EmbeddingModel | None = None,
    ) -> None:
        if not (0.0 <= threshold <= 1.0):
            raise ValueError(
                f"threshold must be in [0.0, 1.0], got {threshold!r}"
            )
        self._threshold = threshold
        self._model: EmbeddingModel | None = embedding_model
        # canary_id -> (canary_text, embedding_or_None)
        self._canaries: dict[str, tuple[str, list[float] | None]] = {}

    @property
    def threshold(self) -> float:
        """Configured similarity threshold."""
        return self._threshold

    def add_canary(self, canary_id: str, canary_text: str) -> None:
        """Register a canary for semantic scanning.

        If an embedding model is configured, the canary text is embedded
        immediately so that subsequent ``scan`` calls only embed the query.

        Parameters
        ----------
        canary_id:
            Unique identifier for this canary (e.g., the token fingerprint).
        canary_text:
            The full canary text that should be detected in scanned content.
        """
        embedding: list[float] | None = None
        if self._model is not None:
            try:
                embedding = self._model.encode([canary_text])[0]
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "SemanticCanaryDetector: failed to embed canary '%s' — %s. "
                    "String fallback will be used.",
                    canary_id,
                    exc,
                )
        self._canaries[canary_id] = (canary_text, embedding)

    def remove_canary(self, canary_id: str) -> None:
        """Deregister a canary by ID."""
        self._canaries.pop(canary_id, None)

    def scan(self, text: str) -> list[SemanticMatch]:
        """Scan *text* for semantic matches against all registered canaries.

        Parameters
        ----------
        text:
            The text to check, e.g. an LLM response or retrieved context.

        Returns
        -------
        list[SemanticMatch]:
            All canaries whose similarity with *text* meets or exceeds the
            configured threshold. Sorted by similarity (descending).
        """
        if not text or not self._canaries:
            return []

        # Compute query embedding once (if model is available)
        query_embedding: list[float] | None = None
        if self._model is not None:
            try:
                query_embedding = self._model.encode([text])[0]
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "SemanticCanaryDetector: failed to embed query text — %s. "
                    "Falling back to string similarity for all canaries.",
                    exc,
                )

        matches: list[SemanticMatch] = []

        for canary_id, (canary_text, canary_embedding) in self._canaries.items():
            if query_embedding is not None and canary_embedding is not None:
                similarity = _cosine_similarity(query_embedding, canary_embedding)
                method = "embedding"
            else:
                similarity = _string_similarity(text, canary_text)
                method = "string_fallback"

            if similarity >= self._threshold:
                snippet = text[:200] if len(text) > 200 else text
                matches.append(
                    SemanticMatch(
                        canary_id=canary_id,
                        canary_text=canary_text,
                        match_method=method,
                        similarity=round(similarity, 6),
                        detected_in=snippet,
                    )
                )

        return sorted(matches, key=lambda m: m.similarity, reverse=True)
