# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
Abstract base class for all canary generation strategies.

Each strategy is responsible for:
1. Generating a unique fingerprint string that can be scanned in raw text.
2. Producing a CanaryFact whose `.value` embeds that fingerprint.
"""

from __future__ import annotations

import abc
from uuid import UUID

from agent_canary.types import CanaryFact, CanaryToken


class CanaryStrategy(abc.ABC):
    """
    Abstract base for all canary generation strategies.

    Subclasses must implement `generate`, which accepts an already-constructed
    CanaryToken and returns a fully formed CanaryFact.  The token carries the
    UUID and fingerprint; the strategy is responsible only for building a
    realistic-looking synthetic value that embeds the fingerprint.

    Example
    -------
    >>> class MyStrategy(CanaryStrategy):
    ...     @property
    ...     def name(self) -> str:
    ...         return "my_strategy"
    ...
    ...     def make_fingerprint(self, token_id: UUID) -> str:
    ...         return f"MYTOKEN-{str(token_id)[:8].upper()}"
    ...
    ...     def generate(self, token: CanaryToken) -> CanaryFact:
    ...         return CanaryFact(
    ...             token=token,
    ...             value=f"synthetic value containing {token.fingerprint}",
    ...             category="my_category",
    ...         )
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Unique name identifying this strategy."""

    @abc.abstractmethod
    def make_fingerprint(self, token_id: UUID) -> str:
        """
        Derive a short, scannable fingerprint from *token_id*.

        The fingerprint must:
        - Be deterministic given the same token_id.
        - Be unique enough that false positives are negligible.
        - Appear verbatim inside the synthetic fact value returned by
          `generate`, so that a plain-text scan can find it.

        Parameters
        ----------
        token_id:
            The UUID that will be associated with the CanaryToken.

        Returns
        -------
        str
            A short string that will be embedded in the fact value.
        """

    @abc.abstractmethod
    def generate(self, token: CanaryToken) -> CanaryFact:
        """
        Produce a CanaryFact using the supplied pre-built token.

        The returned fact's `.value` MUST contain `token.fingerprint`
        verbatim so that the detector can locate it via plain-text scan.

        Parameters
        ----------
        token:
            A fully constructed CanaryToken whose `fingerprint` was produced
            by this strategy's `make_fingerprint` method.

        Returns
        -------
        CanaryFact
            A synthetic fact ready to be planted in agent context.
        """
