# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
HoneypotMemory — fake but realistic-looking agent memory entries with
embedded canary tokens.

Honeypot entries are planted in an agent's accessible memory alongside real
data.  Each entry contains an embedded canary token.  If the canary token
appears in monitored output or external text, the honeypot was accessed —
indicating that an agent or external process read memory it should not have.

Design constraints
------------------
- Configuration is static only (set at construction, never modified at runtime).
- Entries are created at operator request; no adaptive or automatic generation.
- Access checking is a pure scan — no automatic response is triggered.
- Each entry is a frozen dataclass; no mutable state per entry.

Usage:
    config = HoneypotConfig(
        categories=["credentials", "api_keys"],
        entries_per_category=2,
        rotation_interval_hours=24,
    )
    honeypot = HoneypotMemory(config)
    entries = honeypot.create_honeypot_memory("credentials", count=2)
    breached = honeypot.check_honeypot_access(entries[0], access_log=log_lines)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HoneypotEntry:
    """A single fake memory entry with an embedded canary token.

    Attributes:
        key:              The memory key under which this entry would be stored
                          (e.g. ``"db_password"``).
        value:            The fake value string, containing the canary token
                          verbatim so it can be scanned for.
        canary_token_id:  UUID string of the embedded canary token.
        created_at:       UTC timestamp when this entry was created.
        category:         The honeypot category (e.g. ``"credentials"``).
    """

    key: str
    value: str
    canary_token_id: str
    created_at: datetime
    category: str


@dataclass(frozen=True)
class HoneypotConfig:
    """Static configuration for HoneypotMemory.

    Attributes:
        categories:              List of categories to generate entries for.
                                 Valid values: ``credentials``, ``api_keys``,
                                 ``personal_data``, ``financial_data``,
                                 ``health_data``.
        entries_per_category:    Number of entries to generate per category
                                 in a single ``create_honeypot_memory`` call.
                                 Operator-set; not modified at runtime.
        rotation_interval_hours: Documentation field recording how often the
                                 operator intends to rotate honeypot entries.
                                 The library does NOT enforce or schedule
                                 rotation automatically.
    """

    categories: list[str]
    entries_per_category: int
    rotation_interval_hours: int

    def __post_init__(self) -> None:
        if self.entries_per_category < 1:
            raise ValueError(
                f"HoneypotConfig.entries_per_category must be >= 1, "
                f"got {self.entries_per_category!r}"
            )
        if self.rotation_interval_hours < 1:
            raise ValueError(
                f"HoneypotConfig.rotation_interval_hours must be >= 1, "
                f"got {self.rotation_interval_hours!r}"
            )
        unknown = set(self.categories) - _VALID_CATEGORIES
        if unknown:
            raise ValueError(
                f"Unknown honeypot categories: {sorted(unknown)}. "
                f"Valid categories: {sorted(_VALID_CATEGORIES)}"
            )

    @classmethod
    def default(cls) -> HoneypotConfig:
        """Return a default config covering all categories."""
        return cls(
            categories=sorted(_VALID_CATEGORIES),
            entries_per_category=3,
            rotation_interval_hours=24,
        )


# ---------------------------------------------------------------------------
# Entry template system
# ---------------------------------------------------------------------------

_VALID_CATEGORIES: frozenset[str] = frozenset({
    "credentials",
    "api_keys",
    "personal_data",
    "financial_data",
    "health_data",
})

# Each template is a tuple: (key_template, value_template)
# {index} is replaced by an integer counter; {token_id} is replaced by the
# canary token ID (short form) so the value is scannable.

_TEMPLATES: dict[str, list[tuple[str, str]]] = {
    "credentials": [
        ("db_password_{index}", "CNRY-DB-P@ss-{token_id}-synthetic-only"),
        ("admin_password_{index}", "CNRY-Adm!n-{token_id}-synthetic-only"),
        ("ssh_key_passphrase_{index}", "CNRY-SSH-Ph@se-{token_id}-synthetic-only"),
        ("root_password_{index}", "CNRY-R00t-{token_id}-synthetic-only"),
        ("service_account_pw_{index}", "CNRY-SvcAcc-{token_id}-synthetic-only"),
    ],
    "api_keys": [
        ("openai_api_key_{index}", "sk-cnry-{token_id}-synthetic-only"),
        ("stripe_secret_key_{index}", "sk_test_cnry_{token_id}_synthetic"),
        ("aws_secret_access_key_{index}", "cnryAWSsecret{token_id}synthetic"),
        ("github_token_{index}", "ghp_cnry_{token_id}_synthetic_only"),
        ("sendgrid_api_key_{index}", "SG.cnry.{token_id}.synthetic_only"),
    ],
    "personal_data": [
        ("customer_ssn_{index}", "000-{token_id:.4s}-0000-synthetic"),
        ("customer_email_{index}", "cnry-{token_id}@synthetic-pii.example.com"),
        ("customer_phone_{index}", "+1-555-{token_id:.3s}-synthetic"),
        ("customer_dob_{index}", "1900-{token_id:.2s}-01-synthetic"),
        ("customer_address_{index}", "1 Canary Lane, {token_id:.6s}, CA 00000"),
    ],
    "financial_data": [
        ("account_number_{index}", "CNRY-ACC-{token_id}-synthetic"),
        ("routing_number_{index}", "000000000-{token_id}-synthetic"),
        ("card_number_{index}", "4000-cnry-{token_id:.4s}-0000"),
        ("iban_{index}", "GB00CNRY{token_id}SYNTHETIC"),
        ("swift_bic_{index}", "CNRYGB2L{token_id:.4s}"),
    ],
    "health_data": [
        ("mrn_{index}", "MRN-CNRY-{token_id}-synthetic"),
        ("npi_{index}", "NPI-CNRY-{token_id}-synthetic"),
        ("insurance_member_id_{index}", "INS-CNRY-{token_id}-synthetic"),
        ("diagnosis_code_{index}", "Z00.CNRY.{token_id:.4s}.synthetic"),
        ("prescription_id_{index}", "RX-CNRY-{token_id}-synthetic"),
    ],
}


def _render_template(template: str, token_id_short: str, index: int) -> str:
    """Render a template string, substituting {token_id} and {index}.

    The {token_id:.N} format (a slice notation) is not a real Python format
    spec — we handle it manually here.

    Parameters
    ----------
    template:
        The format string with ``{token_id}``, ``{token_id:.N}``, or ``{index}``.
    token_id_short:
        The abbreviated token ID to embed.
    index:
        The sequential index for this entry within its category.

    Returns
    -------
    str:
        The rendered string.
    """
    import re

    result = template

    # Replace {token_id:.N} with first-N-chars slice
    def slice_repl(match: re.Match[str]) -> str:
        length = int(match.group(1))
        return token_id_short[:length]

    result = re.sub(r"\{token_id:\.\d+s?\}", slice_repl, result)
    # Replace plain {token_id}
    result = result.replace("{token_id}", token_id_short)
    # Replace {index}
    result = result.replace("{index}", str(index))

    return result


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------


class HoneypotMemory:
    """Creates and manages honeypot memory entries for agent breach detection.

    Parameters
    ----------
    config:
        The static HoneypotConfig controlling which categories are active
        and how many entries to produce per category.

    Example
    -------
    >>> config = HoneypotConfig(
    ...     categories=["api_keys"],
    ...     entries_per_category=2,
    ...     rotation_interval_hours=24,
    ... )
    >>> honeypot = HoneypotMemory(config)
    >>> entries = honeypot.create_honeypot_memory("api_keys", count=2)
    >>> len(entries)
    2
    """

    def __init__(self, config: HoneypotConfig) -> None:
        self._config = config

    @property
    def config(self) -> HoneypotConfig:
        """Read-only view of the static configuration."""
        return self._config

    def create_honeypot_memory(
        self,
        category: str,
        count: int | None = None,
    ) -> list[HoneypotEntry]:
        """Generate fake memory entries for *category*, each with a canary token.

        Parameters
        ----------
        category:
            The category of fake data to generate.  Must be one of the
            categories defined in ``HoneypotConfig.categories``.
        count:
            Number of entries to generate.  Defaults to
            ``config.entries_per_category``.  Must be >= 1.

        Returns
        -------
        list[HoneypotEntry]:
            A list of HoneypotEntry instances ready to be planted in agent
            memory.  Each has a unique canary token ID.

        Raises
        ------
        ValueError:
            If *category* is not in the active config categories, or if
            *count* is less than 1.
        """
        if category not in self._config.categories:
            raise ValueError(
                f"Category {category!r} is not active in this HoneypotConfig. "
                f"Active categories: {self._config.categories}"
            )

        resolved_count = count if count is not None else self._config.entries_per_category
        if resolved_count < 1:
            raise ValueError(f"count must be >= 1, got {resolved_count!r}")

        templates = _TEMPLATES.get(category, [])
        entries: list[HoneypotEntry] = []
        now = datetime.now(tz=timezone.utc)

        for index in range(resolved_count):
            token_id_full = str(uuid.uuid4())
            # Short form: first 16 chars of UUID hex (without dashes)
            token_id_short = token_id_full.replace("-", "").upper()[:16]

            template_pair = templates[index % len(templates)]
            key_template, value_template = template_pair

            key = _render_template(key_template, token_id_short, index)
            value = _render_template(value_template, token_id_short, index)

            entries.append(
                HoneypotEntry(
                    key=key,
                    value=value,
                    canary_token_id=token_id_full,
                    created_at=now,
                    category=category,
                )
            )

        return entries

    def create_all_categories(self) -> dict[str, list[HoneypotEntry]]:
        """Generate honeypot entries for every active category.

        Returns
        -------
        dict[str, list[HoneypotEntry]]:
            Mapping of category name -> list of entries, using
            ``entries_per_category`` entries per category.
        """
        return {
            category: self.create_honeypot_memory(category)
            for category in self._config.categories
        }

    def check_honeypot_access(
        self,
        entry: HoneypotEntry,
        access_log: list[Any],
    ) -> bool:
        """Check whether a honeypot entry's canary token appears in *access_log*.

        Scans each item in *access_log* by converting it to a string and
        checking for the presence of:
        1. The full ``canary_token_id`` UUID string.
        2. The entry ``value`` string (which contains the embedded short token).

        Parameters
        ----------
        entry:
            The HoneypotEntry to check for.
        access_log:
            A list of log entries, each of which is converted to ``str``
            before scanning.

        Returns
        -------
        bool:
            True when the canary token or value is found in any log entry.
            No action is taken automatically — the caller decides the response.
        """
        token_id_short = entry.canary_token_id.replace("-", "").upper()[:16]

        for log_item in access_log:
            log_str = str(log_item)
            if (
                entry.canary_token_id in log_str
                or token_id_short in log_str
                or entry.value in log_str
            ):
                return True

        return False
