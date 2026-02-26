# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
Strategy: FakeContactStrategy

Generates synthetic contact details (name, email, phone) that embed
a traceable fingerprint.  If any of these details appear in agent
output or tool responses, a canary has leaked.
"""

from __future__ import annotations

import random
from uuid import UUID

from agent_canary.strategies.base import CanaryStrategy
from agent_canary.types import CanaryFact, CanaryToken

# Pools of plausible-but-obviously-synthetic name parts
_FIRST_NAMES: tuple[str, ...] = (
    "Aldric", "Brienne", "Calyx", "Daevon", "Elowyn",
    "Farryn", "Gavrel", "Hylia", "Irwyn", "Jorvyn",
    "Kessia", "Lorren", "Maevra", "Naldor", "Orvyn",
    "Pyriel", "Quessa", "Raedyn", "Sylvra", "Threon",
)

_LAST_NAMES: tuple[str, ...] = (
    "Ashvale", "Brynmor", "Coldfen", "Dawnridge", "Edgewood",
    "Frostholm", "Greyveil", "Hollowmere", "Ironwick", "Jadefall",
    "Kesthorn", "Larchwood", "Moonvale", "Northfen", "Oakmere",
    "Pebbleton", "Quietmoor", "Ravenshire", "Stoneholt", "Thornwick",
)

_DOMAINS: tuple[str, ...] = (
    "canary-test.invalid",
    "synthetic-ops.invalid",
    "phantom-data.invalid",
    "trace-watch.invalid",
    "honeypot-mail.invalid",
)

_AREA_CODES: tuple[str, ...] = (
    "555", "556", "557", "558", "559",
)


class FakeContactStrategy(CanaryStrategy):
    """
    Produces synthetic contact cards that embed a canary fingerprint
    in the email address.

    The fingerprint is embedded as the local part of the email address,
    making it scannable via simple substring search while appearing
    realistic in agent context.

    Parameters
    ----------
    seed:
        Optional random seed for reproducible generation in tests.
    """

    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)

    @property
    def name(self) -> str:
        return "fake_contact"

    def make_fingerprint(self, token_id: UUID) -> str:
        """
        Build a short fingerprint from the first 12 hex chars of the UUID.

        Example: ``cnry-a1b2c3d4e5f6``
        """
        short = str(token_id).replace("-", "")[:12]
        return f"cnry-{short}"

    def generate(self, token: CanaryToken) -> CanaryFact:
        """
        Return a CanaryFact whose `.value` is a formatted contact card.

        The email address embeds the fingerprint as its local part so that
        scanning for the fingerprint in raw text will find it.
        """
        first = self._rng.choice(_FIRST_NAMES)
        last = self._rng.choice(_LAST_NAMES)
        domain = self._rng.choice(_DOMAINS)
        area = self._rng.choice(_AREA_CODES)
        line_number = self._rng.randint(100_0000, 999_9999)
        phone = f"+1-{area}-{line_number:07d}"[:16]

        email = f"{token.fingerprint}@{domain}"
        full_name = f"{first} {last}"

        value = (
            f"Contact: {full_name}\n"
            f"Email: {email}\n"
            f"Phone: {phone}"
        )

        return CanaryFact(
            token=token,
            value=value,
            category="contact",
            description=(
                f"Synthetic contact for {full_name}. "
                "Any appearance of this record outside its planted location "
                "indicates a memory breach."
            ),
        )
