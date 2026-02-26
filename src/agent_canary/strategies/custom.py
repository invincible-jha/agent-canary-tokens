# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
Strategy: CustomStrategy

Allows callers to supply their own generator function without subclassing
CanaryStrategy.  Useful for quick one-off canaries or domain-specific
synthetic data that does not warrant a full strategy class.
"""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

from agent_canary.strategies.base import CanaryStrategy
from agent_canary.types import CanaryFact, CanaryToken

# Signature for user-supplied fingerprint builders
FingerprintFn = Callable[[UUID], str]

# Signature for user-supplied fact generators
FactGeneratorFn = Callable[[CanaryToken], CanaryFact]


class CustomStrategy(CanaryStrategy):
    """
    A strategy that delegates generation to caller-supplied functions.

    This lets users define ad-hoc canaries inline without subclassing::

        from agent_canary.strategies.custom import CustomStrategy
        from agent_canary.types import CanaryFact

        strategy = CustomStrategy(
            strategy_name="my_internal_canary",
            fingerprint_fn=lambda uid: f"MY-{str(uid)[:8].upper()}",
            generator_fn=lambda token: CanaryFact(
                token=token,
                value=f"Secret project code: PROJ-{token.fingerprint}",
                category="project_code",
            ),
        )

    Parameters
    ----------
    strategy_name:
        A unique name for this custom strategy instance.
    fingerprint_fn:
        Callable that accepts a ``UUID`` and returns a fingerprint string.
        The string must appear verbatim in the value returned by
        ``generator_fn``.
    generator_fn:
        Callable that accepts a ``CanaryToken`` and returns a ``CanaryFact``.
        The fact's ``.value`` must contain ``token.fingerprint``.
    """

    def __init__(
        self,
        strategy_name: str,
        fingerprint_fn: FingerprintFn,
        generator_fn: FactGeneratorFn,
    ) -> None:
        self._strategy_name = strategy_name
        self._fingerprint_fn = fingerprint_fn
        self._generator_fn = generator_fn

    @property
    def name(self) -> str:
        return self._strategy_name

    def make_fingerprint(self, token_id: UUID) -> str:
        """Delegate to the caller-supplied fingerprint function."""
        return self._fingerprint_fn(token_id)

    def generate(self, token: CanaryToken) -> CanaryFact:
        """Delegate to the caller-supplied generator function."""
        fact = self._generator_fn(token)
        if token.fingerprint not in fact.value:
            raise ValueError(
                f"CustomStrategy '{self._strategy_name}': the CanaryFact value "
                f"returned by generator_fn must contain the fingerprint "
                f"'{token.fingerprint}' verbatim so the detector can find it."
            )
        return fact
