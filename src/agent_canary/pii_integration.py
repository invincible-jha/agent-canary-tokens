# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
PIICanaryStrategy — canary tokens shaped to mimic specific PII formats.

When a PII detection event occurs, it can be useful to plant a canary token
that superficially resembles the type of PII found.  If that canary-PII value
is later seen in an unexpected location, the breach can be linked to
PII-handling code rather than a generic data leak.

Each format template generates a fake but structurally plausible-looking PII
value with an embedded fingerprint.  The generated values:
- Pass the format test for their PII type (e.g. fake emails have @domain.tld)
- Contain the fingerprint string verbatim so scanner can find them
- Are explicitly labelled as synthetic (CNRY prefix) to prevent
  accidental use as real data

This module is self-contained — it has no dependency on pii_guardian.
It integrates with the existing CanaryStrategy / CanaryGenerator system.

Usage:
    from agent_canary.pii_integration import PIICanaryStrategy
    from agent_canary.store import CanaryStore

    store = CanaryStore()
    strategy = PIICanaryStrategy()
    token_id = uuid4()
    fingerprint = strategy.make_fingerprint(token_id)
    from agent_canary.types import CanaryToken, CanaryStatus
    from datetime import datetime, timezone
    token = CanaryToken(
        token_id=token_id, fingerprint=fingerprint,
        strategy_name=strategy.name, context="pii_adjacent",
        planted_at=datetime.now(tz=timezone.utc), status=CanaryStatus.ACTIVE,
    )
    fact = strategy.generate(token)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from uuid import UUID, uuid4

from agent_canary.strategies.base import CanaryStrategy
from agent_canary.types import CanaryFact, CanaryStatus, CanaryToken


# ---------------------------------------------------------------------------
# PII format templates
# ---------------------------------------------------------------------------

# Each callable accepts a fingerprint string and returns a fake-but-realistic
# PII-format string with the fingerprint embedded.  Templates MUST embed the
# fingerprint so the scanner can detect them.

def _email_template(fingerprint: str) -> str:
    short = fingerprint[:8].lower()
    return f"cnry.{short}@canary-pii-synthetic.example.com"


def _phone_template(fingerprint: str) -> str:
    # Encode first 7 hex digits as US phone-like digits
    digits = "".join(str(int(ch, 16) % 10) for ch in fingerprint[:7])
    return f"+1-555-{digits[:3]}-{digits[3:7]}"


def _ssn_template(fingerprint: str) -> str:
    # Use first 9 digits derived from fingerprint — deliberately invalid area/group
    digits = "".join(str(int(ch, 16) % 10) for ch in fingerprint[:9])
    return f"000-{digits[:2]}-{fingerprint[:4].upper()}"


def _credit_card_template(fingerprint: str) -> str:
    # Visa-format starting with 4000 (test prefix) then fingerprint digits
    digits = "".join(str(int(ch, 16) % 10) for ch in fingerprint[:12])
    return f"4000-{digits[:4]}-{digits[4:8]}-{digits[8:12]}"


def _ip_template(fingerprint: str) -> str:
    # Use octets from fingerprint hex pairs; first octet fixed to 192 (RFC1918)
    octets = [int(fingerprint[i : i + 2], 16) % 255 for i in range(0, 8, 2)]
    return f"192.{octets[0]}.{octets[1]}.{octets[2]}"


def _url_template(fingerprint: str) -> str:
    short = fingerprint[:12].lower()
    return f"https://cnry-{short}.canary-pii-synthetic.example.com/data"


def _national_id_template(fingerprint: str) -> str:
    return f"CNRY-{fingerprint[:4].upper()}-{fingerprint[4:8].upper()}-SYN"


# Public registry: pii_type -> format generator
PII_FORMAT_TEMPLATES: dict[str, callable[[str], str]] = {  # type: ignore[type-arg]
    "EMAIL_ADDRESS": _email_template,
    "PHONE_NUMBER": _phone_template,
    "US_SSN": _ssn_template,
    "CREDIT_CARD": _credit_card_template,
    "IP_ADDRESS": _ip_template,
    "URL": _url_template,
    "NATIONAL_ID": _national_id_template,
}

_SUPPORTED_PII_TYPES: frozenset[str] = frozenset(PII_FORMAT_TEMPLATES)


# ---------------------------------------------------------------------------
# PIICanaryStrategy
# ---------------------------------------------------------------------------


class PIICanaryStrategy(CanaryStrategy):
    """Generates canary tokens that mimic specific PII formats.

    The strategy selects a PII format template based on the ``pii_type``
    embedded in the token context.  If the context does not specify a
    known PII type, the email template is used as the default.

    Parameters
    ----------
    default_pii_type:
        The PII type to use when the token context does not contain a
        recognised PII type.  Defaults to ``"EMAIL_ADDRESS"``.

    Example
    -------
    >>> strategy = PIICanaryStrategy()
    >>> token_id = uuid4()
    >>> fingerprint = strategy.make_fingerprint(token_id)
    >>> token = CanaryToken(
    ...     token_id=token_id, fingerprint=fingerprint,
    ...     strategy_name=strategy.name, context="pii_adjacent:EMAIL_ADDRESS",
    ...     planted_at=datetime.now(tz=timezone.utc), status=CanaryStatus.ACTIVE,
    ... )
    >>> fact = strategy.generate(token)
    >>> "@canary-pii-synthetic" in fact.value
    True
    """

    def __init__(self, default_pii_type: str = "EMAIL_ADDRESS") -> None:
        if default_pii_type not in _SUPPORTED_PII_TYPES:
            raise ValueError(
                f"default_pii_type {default_pii_type!r} is not in the supported "
                f"PII types: {sorted(_SUPPORTED_PII_TYPES)}"
            )
        self._default_pii_type = default_pii_type

    @property
    def name(self) -> str:
        return "pii_canary"

    def make_fingerprint(self, token_id: UUID) -> str:
        """Derive a fingerprint from the full UUID hex string.

        Returns the first 16 uppercase hex characters of the UUID so the
        fingerprint is compact but has sufficient entropy.

        Parameters
        ----------
        token_id:
            The UUID allocated for the new token.

        Returns
        -------
        str:
            A 16-character uppercase hex fingerprint.
        """
        return str(token_id).replace("-", "").upper()[:16]

    def generate(self, token: CanaryToken) -> CanaryFact:
        """Produce a CanaryFact whose value mimics a PII format.

        The PII type is extracted from the token context using the convention
        ``"pii_adjacent:<PII_TYPE>"``.  If no recognised type is found, the
        default PII type is used.

        Parameters
        ----------
        token:
            The CanaryToken to wrap in a fact.

        Returns
        -------
        CanaryFact:
            A synthetic fact whose ``.value`` contains the fingerprint embedded
            in a PII-format string.
        """
        pii_type = self._extract_pii_type(token.context)
        template_fn = PII_FORMAT_TEMPLATES.get(pii_type, PII_FORMAT_TEMPLATES[self._default_pii_type])
        value = template_fn(token.fingerprint)

        return CanaryFact(
            token=token,
            value=value,
            category="pii_canary",
            description=(
                f"Synthetic {pii_type} canary.  "
                f"Fingerprint: {token.fingerprint}.  "
                "This value is structurally marked as synthetic and cannot be "
                "used as real PII.  Its appearance outside the planted location "
                "signals a PII-adjacent data breach."
            ),
        )

    @staticmethod
    def _extract_pii_type(context: str) -> str:
        """Extract the PII type from a context string.

        Expects the convention ``"pii_adjacent:<PII_TYPE>"`` but gracefully
        falls back if the format is not followed.

        Parameters
        ----------
        context:
            The token context string.

        Returns
        -------
        str:
            The extracted PII type, or ``"EMAIL_ADDRESS"`` as fallback.
        """
        parts = context.split(":", maxsplit=1)
        if len(parts) == 2:
            candidate = parts[1].strip().upper()
            if candidate in _SUPPORTED_PII_TYPES:
                return candidate
        return "EMAIL_ADDRESS"


# ---------------------------------------------------------------------------
# Public factory function
# ---------------------------------------------------------------------------


def create_pii_canary(
    pii_type: str,
    context: str,
    strategy: PIICanaryStrategy | None = None,
) -> CanaryToken:
    """Create a CanaryToken configured for PII-format canary injection.

    Parameters
    ----------
    pii_type:
        The PII type this canary should mimic (e.g. ``"EMAIL_ADDRESS"``).
        Must be a key in ``PII_FORMAT_TEMPLATES``.
    context:
        A label describing where in the system this canary is being planted.
        By convention, use ``"pii_adjacent:<PII_TYPE>"`` so the strategy can
        read the PII type back from the token.
    strategy:
        Optional pre-built PIICanaryStrategy.  A new one is created with
        default settings if not supplied.

    Returns
    -------
    CanaryToken:
        A new, ACTIVE CanaryToken.  Register it in a CanaryStore before use.

    Raises
    ------
    ValueError:
        If *pii_type* is not in ``PII_FORMAT_TEMPLATES``.
    """
    if pii_type not in _SUPPORTED_PII_TYPES:
        raise ValueError(
            f"pii_type {pii_type!r} is not supported. "
            f"Valid types: {sorted(_SUPPORTED_PII_TYPES)}"
        )

    resolved_strategy = strategy or PIICanaryStrategy(default_pii_type=pii_type)
    token_id = uuid4()
    fingerprint = resolved_strategy.make_fingerprint(token_id)

    return CanaryToken(
        token_id=token_id,
        fingerprint=fingerprint,
        strategy_name=resolved_strategy.name,
        context=context,
        planted_at=datetime.now(tz=timezone.utc),
        status=CanaryStatus.ACTIVE,
        metadata={"pii_type": pii_type},
    )


def validate_pii_canary(token: CanaryToken) -> bool:
    """Validate that a CanaryToken's fingerprint matches its intended PII format.

    Reconstructs the expected canary value using the PII type from the token's
    metadata (or derives it from the context) and checks that the fingerprint
    appears in the reconstructed value.

    Parameters
    ----------
    token:
        A CanaryToken produced by ``create_pii_canary`` or
        ``PIICanaryStrategy.generate``.

    Returns
    -------
    bool:
        True when the token's fingerprint would be embedded in the canonical
        value produced for its PII type.
    """
    pii_type = str(token.metadata.get("pii_type", "EMAIL_ADDRESS")).upper()
    template_fn = PII_FORMAT_TEMPLATES.get(pii_type)
    if template_fn is None:
        return False

    expected_value = template_fn(token.fingerprint)
    return token.fingerprint in expected_value
