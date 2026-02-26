# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
CanaryGenerator — the primary entry point for planting canary tokens.

CanaryGenerator coordinates strategy selection, token construction, and
store registration.  Callers request a CanaryFact via ``plant()``, which
they then embed into agent context, memory, or any monitored text surface.
"""

from __future__ import annotations

import logging
import random
from datetime import datetime, timezone
from typing import Sequence
from uuid import uuid4

from agent_canary.store import CanaryStore
from agent_canary.strategies.base import CanaryStrategy
from agent_canary.strategies.fake_contact import FakeContactStrategy
from agent_canary.strategies.fake_url import FakeURLStrategy
from agent_canary.types import CanaryFact, CanaryStatus, CanaryToken

logger = logging.getLogger(__name__)


def _default_strategies() -> list[CanaryStrategy]:
    """Return the default strategy set: FakeContactStrategy + FakeURLStrategy."""
    return [FakeContactStrategy(), FakeURLStrategy()]


class CanaryGenerator:
    """
    Creates and registers canary tokens using pluggable strategies.

    Parameters
    ----------
    strategies:
        Ordered list of CanaryStrategy instances to draw from.  When
        ``plant()`` is called without an explicit strategy name, one is
        chosen at random.  Defaults to ``[FakeContactStrategy(), FakeURLStrategy()]``.
    store:
        The CanaryStore where newly created tokens are registered.
        Defaults to a fresh in-memory store.
    seed:
        Optional seed for strategy selection randomness.  Pass an integer
        for reproducible sequences (useful in tests).

    Raises
    ------
    ValueError
        If *strategies* is empty.
    """

    def __init__(
        self,
        strategies: Sequence[CanaryStrategy] | None = None,
        store: CanaryStore | None = None,
        seed: int | None = None,
    ) -> None:
        resolved_strategies = list(strategies) if strategies else _default_strategies()
        if not resolved_strategies:
            raise ValueError("CanaryGenerator requires at least one strategy.")

        # Verify uniqueness of strategy names
        seen_names: set[str] = set()
        for strategy in resolved_strategies:
            if strategy.name in seen_names:
                raise ValueError(
                    f"Duplicate strategy name '{strategy.name}'. "
                    "Each strategy must have a unique name."
                )
            seen_names.add(strategy.name)

        self._strategies: dict[str, CanaryStrategy] = {
            s.name: s for s in resolved_strategies
        }
        self._strategy_names: list[str] = [s.name for s in resolved_strategies]
        self._store: CanaryStore = store if store is not None else CanaryStore()
        self._rng = random.Random(seed)

    @property
    def store(self) -> CanaryStore:
        """The underlying CanaryStore managed by this generator."""
        return self._store

    @property
    def strategy_names(self) -> list[str]:
        """Names of all registered strategies."""
        return list(self._strategy_names)

    def plant(
        self,
        context: str = "default",
        strategy_name: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> CanaryFact:
        """
        Generate and register a new canary fact.

        Steps:
        1. Select a strategy (randomly if *strategy_name* is None).
        2. Allocate a UUID for the token.
        3. Ask the strategy to produce a fingerprint from the UUID.
        4. Construct the CanaryToken and register it in the store.
        5. Ask the strategy to produce the CanaryFact.

        Parameters
        ----------
        context:
            Arbitrary label describing where the canary is being planted
            (e.g., ``"system_prompt"``, ``"tool_output"``, ``"user_session_42"``).
        strategy_name:
            Name of a specific strategy to use.  If None, a strategy is
            chosen at random from the registered pool.
        metadata:
            Optional extra key-value data stored alongside the token in the
            store.  Useful for correlating canaries with request IDs, user
            sessions, or deployment labels.

        Returns
        -------
        CanaryFact
            A synthetic fact whose ``.value`` should be embedded verbatim
            in the target context.  The fact's ``.token`` is registered in
            the store and is immediately active.

        Raises
        ------
        ValueError
            If *strategy_name* is specified but not found in the registered
            strategy pool.
        """
        if strategy_name is not None:
            strategy = self._strategies.get(strategy_name)
            if strategy is None:
                raise ValueError(
                    f"Unknown strategy '{strategy_name}'. "
                    f"Available: {self._strategy_names}"
                )
        else:
            chosen_name = self._rng.choice(self._strategy_names)
            strategy = self._strategies[chosen_name]

        token_id = uuid4()
        fingerprint = strategy.make_fingerprint(token_id)

        token = CanaryToken(
            token_id=token_id,
            fingerprint=fingerprint,
            strategy_name=strategy.name,
            context=context,
            planted_at=datetime.now(tz=timezone.utc),
            status=CanaryStatus.ACTIVE,
            metadata=dict(metadata) if metadata else {},
        )

        self._store.register(token)

        fact = strategy.generate(token)

        logger.info(
            "CanaryGenerator: planted token %s via strategy '%s' in context '%s'.",
            token_id,
            strategy.name,
            context,
        )

        return fact
