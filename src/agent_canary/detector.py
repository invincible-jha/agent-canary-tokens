# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
CanaryDetector — scans text for planted canary fingerprints.

The detector holds a reference to both a CanaryStore (to look up token
metadata) and a CanaryAlerter (to dispatch notifications on discovery).

Detection is intentionally simple: plain substring search over all active
fingerprints.  This is O(n * m) where n is text length and m is the number
of active tokens, but for typical use-cases (tens to low-hundreds of tokens)
this is fast enough and has no dependencies beyond the standard library.

For very large token pools, callers can build an Aho-Corasick automaton over
the fingerprints and pass its match function in via a custom scan strategy.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from agent_canary.alerter import CanaryAlerter
from agent_canary.store import CanaryStore
from agent_canary.types import AlertSeverity, CanaryAlert

logger = logging.getLogger(__name__)


class CanaryDetector:
    """
    Scans text surfaces for canary fingerprints and fires alerts on matches.

    Parameters
    ----------
    store:
        The CanaryStore that holds the active planted tokens.
    alerter:
        The alerter (or composite alerter) to invoke when a fingerprint
        is found in scanned text.
    default_severity:
        Severity level assigned to alerts when no override is provided.
    mark_triggered:
        If True (default), the store entry for a detected token is updated
        to TRIGGERED status on first detection.
    """

    def __init__(
        self,
        store: CanaryStore,
        alerter: CanaryAlerter,
        default_severity: AlertSeverity = AlertSeverity.HIGH,
        mark_triggered: bool = True,
    ) -> None:
        self._store = store
        self._alerter = alerter
        self._default_severity = default_severity
        self._mark_triggered = mark_triggered

    def check_text(
        self,
        text: str,
        source: str = "unknown",
        severity: AlertSeverity | None = None,
    ) -> list[CanaryAlert]:
        """
        Scan *text* for all active canary fingerprints.

        Each fingerprint found triggers an alert via the configured alerter
        and (optionally) marks the token as TRIGGERED in the store.

        Parameters
        ----------
        text:
            The text to scan.  This could be an LLM response, tool output,
            retrieved memory chunk, or any string surface to monitor.
        source:
            A human-readable label for what produced or contains *text*
            (e.g., ``"llm_output"``, ``"retrieval_result"``, ``"tool_call"``).
        severity:
            Override the default severity for all alerts produced by this
            scan.  Pass None to use the detector's ``default_severity``.

        Returns
        -------
        list[CanaryAlert]
            One alert per fingerprint found.  Empty list means no leaks
            were detected.
        """
        if not text:
            return []

        effective_severity = severity if severity is not None else self._default_severity
        detected_at = datetime.now(tz=timezone.utc)
        alerts: list[CanaryAlert] = []

        active_fingerprints = self._store.active_fingerprints()

        for fingerprint in active_fingerprints:
            if fingerprint not in text:
                continue

            token = self._store.get_by_fingerprint(fingerprint)
            if token is None:
                # Race condition: token deactivated between listing and lookup
                logger.debug(
                    "CanaryDetector: fingerprint '%s' matched but token "
                    "was removed before lookup; skipping.",
                    fingerprint,
                )
                continue

            alert = CanaryAlert(
                token=token,
                detected_in=text,
                detected_at=detected_at,
                severity=effective_severity,
                source=source,
            )
            alerts.append(alert)

            if self._mark_triggered:
                self._store.mark_triggered(token.token_id)

            try:
                self._alerter.send(alert)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "CanaryDetector: alerter raised an exception for token %s — %s",
                    token.token_id,
                    exc,
                )

        if alerts:
            logger.warning(
                "CanaryDetector: %d canary token(s) detected in text from source '%s'.",
                len(alerts),
                source,
            )

        return alerts

    def check_dict(
        self,
        data: dict[str, object],
        source: str = "unknown",
        severity: AlertSeverity | None = None,
    ) -> list[CanaryAlert]:
        """
        Scan all string values in a dict (recursively) for canary fingerprints.

        Parameters
        ----------
        data:
            A dictionary whose values will be serialised to string and scanned.
        source:
            Label for where *data* came from.
        severity:
            Optional severity override.

        Returns
        -------
        list[CanaryAlert]
            All alerts fired, de-duplicated by token ID.
        """
        import json as _json

        text = _json.dumps(data, default=str)
        return self.check_text(text, source=source, severity=severity)
