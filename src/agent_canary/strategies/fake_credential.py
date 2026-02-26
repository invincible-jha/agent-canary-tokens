# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
Strategy: FakeCredentialStrategy

Generates synthetic API keys and credentials that embed a traceable
fingerprint.  These look like plausible keys but are structurally
marked as synthetic so they can never be mistaken for real secrets.
If they appear in agent output or logs, a canary has leaked.
"""

from __future__ import annotations

import random
import string
from uuid import UUID

from agent_canary.strategies.base import CanaryStrategy
from agent_canary.types import CanaryFact, CanaryToken

# Alphabet for padding characters around the fingerprint
_PADDING_CHARS: str = string.ascii_letters + string.digits

# Prefixes that mimic common API key formats while being clearly synthetic
_KEY_PREFIXES: tuple[str, ...] = (
    "cnry_sk_",
    "cnry_pk_",
    "cnry_api_",
    "cnry_tok_",
    "cnry_sec_",
)


def _random_suffix(rng: random.Random, length: int) -> str:
    return "".join(rng.choices(_PADDING_CHARS, k=length))


class FakeCredentialStrategy(CanaryStrategy):
    """
    Produces synthetic credential strings that embed a canary fingerprint
    between a recognisable prefix and random padding.

    The structure is::

        <prefix><fingerprint><random-suffix>

    This makes the full key value scannable via the fingerprint while
    looking superficially like a real secret token.

    Parameters
    ----------
    key_prefix:
        Override the key prefix.  Defaults to a randomly selected
        entry from the built-in synthetic prefix pool.
    suffix_length:
        Number of random padding characters appended after the fingerprint.
    seed:
        Optional random seed for reproducible generation in tests.
    """

    def __init__(
        self,
        key_prefix: str | None = None,
        suffix_length: int = 16,
        seed: int | None = None,
    ) -> None:
        self._rng = random.Random(seed)
        self._key_prefix = key_prefix
        self._suffix_length = suffix_length

    @property
    def name(self) -> str:
        return "fake_credential"

    def make_fingerprint(self, token_id: UUID) -> str:
        """
        Derive a fingerprint from the first 16 hex chars of the UUID.

        Example: ``A1B2C3D4E5F6A7B8``
        """
        return str(token_id).replace("-", "").upper()[:16]

    def generate(self, token: CanaryToken) -> CanaryFact:
        """
        Return a CanaryFact whose `.value` is a synthetic credential block.

        Both the key value and the service description embed the fingerprint
        to maximise scannability.
        """
        prefix = self._key_prefix or self._rng.choice(_KEY_PREFIXES)
        suffix = _random_suffix(self._rng, self._suffix_length)
        api_key = f"{prefix}{token.fingerprint}{suffix}"

        service_name = f"SyntheticService-{token.fingerprint[:6]}"

        value = (
            f"Service: {service_name}\n"
            f"API Key: {api_key}\n"
            f"Note: SYNTHETIC CANARY — not a real credential"
        )

        return CanaryFact(
            token=token,
            value=value,
            category="credential",
            description=(
                f"Synthetic API key for '{service_name}'. "
                "This credential is structurally marked as synthetic and "
                "cannot authenticate with any real service. Its appearance "
                "outside the planted location is a canary breach signal."
            ),
        )
