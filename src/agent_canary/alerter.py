# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
Alerter implementations for canary detection events.

Three concrete alerters are provided:

- ``LogAlerter``: Writes alerts to Python's standard logging framework.
- ``WebhookAlerter``: HTTP POSTs a JSON payload to a configured endpoint.
- ``EmailAlerter``: SMTP-based email stub (connection setup only; callers
  supply a send hook for full implementation).

All alerters implement the ``CanaryAlerter`` abstract base so they can be
composed into a ``CompositeAlerter`` for multi-channel notification.
"""

from __future__ import annotations

import abc
import json
import logging
import smtplib
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.mime.text import MIMEText
from typing import Any

from agent_canary.types import CanaryAlert

logger = logging.getLogger(__name__)


class CanaryAlerter(abc.ABC):
    """Abstract base for all alerters."""

    @abc.abstractmethod
    def send(self, alert: CanaryAlert) -> None:
        """
        Dispatch the alert through the implementation's channel.

        Parameters
        ----------
        alert:
            The detection alert to dispatch.
        """


class LogAlerter(CanaryAlerter):
    """
    Writes canary alerts to Python's standard logging framework.

    Maps ``AlertSeverity`` to logging levels:

    - ``LOW``      -> ``logging.INFO``
    - ``MEDIUM``   -> ``logging.WARNING``
    - ``HIGH``     -> ``logging.ERROR``
    - ``CRITICAL`` -> ``logging.CRITICAL``

    Parameters
    ----------
    logger_name:
        Name of the logger to use.  Defaults to ``"agent_canary.alerts"``.
    """

    _SEVERITY_MAP: dict[str, int] = {
        "low": logging.INFO,
        "medium": logging.WARNING,
        "high": logging.ERROR,
        "critical": logging.CRITICAL,
    }

    def __init__(self, logger_name: str = "agent_canary.alerts") -> None:
        self._log = logging.getLogger(logger_name)

    def send(self, alert: CanaryAlert) -> None:
        level = self._SEVERITY_MAP.get(alert.severity.value, logging.ERROR)
        self._log.log(level, alert.summary(), extra={"canary_alert": True})


@dataclass
class WebhookAlerter(CanaryAlerter):
    """
    HTTP POST a JSON payload to a webhook URL on canary detection.

    The payload shape is::

        {
            "event": "canary_detected",
            "token_id": "<uuid>",
            "fingerprint": "<fingerprint>",
            "context": "<context>",
            "strategy": "<strategy_name>",
            "severity": "<severity>",
            "detected_at": "<iso8601>",
            "detected_in_snippet": "<text snippet>",
            "source": "<source>",
            "extra": {}
        }

    Parameters
    ----------
    url:
        Full URL to POST the alert payload to.
    headers:
        HTTP headers to include in the request.  At minimum you likely
        want ``{"Content-Type": "application/json"}``.
    timeout_seconds:
        Request timeout.  Defaults to 5 seconds.
    """

    url: str
    headers: dict[str, str] = field(default_factory=lambda: {"Content-Type": "application/json"})
    timeout_seconds: float = 5.0

    def _build_payload(self, alert: CanaryAlert) -> dict[str, Any]:
        return {
            "event": "canary_detected",
            "token_id": str(alert.token.token_id),
            "fingerprint": alert.token.fingerprint,
            "context": alert.token.context,
            "strategy": alert.token.strategy_name,
            "severity": alert.severity.value,
            "detected_at": alert.detected_at.isoformat(),
            "detected_in_snippet": alert.detected_in[:500],
            "source": alert.source,
            "extra": alert.extra,
        }

    def send(self, alert: CanaryAlert) -> None:
        payload = self._build_payload(alert)
        body = json.dumps(payload).encode("utf-8")

        request = urllib.request.Request(
            url=self.url,
            data=body,
            headers=self.headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                status = response.status
                if status >= 400:
                    logger.warning(
                        "WebhookAlerter: non-success HTTP status %d from %s",
                        status,
                        self.url,
                    )
        except urllib.error.URLError as exc:
            logger.error(
                "WebhookAlerter: failed to deliver alert to %s — %s",
                self.url,
                exc,
            )


@dataclass
class SmtpConfig:
    """
    SMTP connection parameters for EmailAlerter.

    Attributes
    ----------
    host:
        SMTP server hostname.
    port:
        SMTP server port (typically 465 for SSL, 587 for STARTTLS).
    username:
        SMTP authentication username.
    password:
        SMTP authentication password.
    use_tls:
        If True, wrap the connection in SSL/TLS from the start.
        If False, use STARTTLS negotiation after connecting.
    """

    host: str
    port: int
    username: str
    password: str
    use_tls: bool = True


class EmailAlerter(CanaryAlerter):
    """
    Send canary detection alerts via SMTP email.

    This implementation opens a connection and sends a plain-text email.
    It is intentionally kept minimal; callers requiring advanced features
    (HTML bodies, attachments, queueing) should sub-class or wrap this.

    Parameters
    ----------
    smtp_config:
        SMTP connection and authentication parameters.
    from_address:
        Sender email address.
    to_addresses:
        One or more recipient email addresses.
    subject_prefix:
        Prepended to the alert summary in the email subject line.
    """

    def __init__(
        self,
        smtp_config: SmtpConfig,
        from_address: str,
        to_addresses: list[str],
        subject_prefix: str = "[CANARY ALERT]",
    ) -> None:
        self._config = smtp_config
        self._from_address = from_address
        self._to_addresses = to_addresses
        self._subject_prefix = subject_prefix

    def _build_message(self, alert: CanaryAlert) -> MIMEText:
        body = (
            f"{alert.summary()}\n\n"
            f"Token ID : {alert.token.token_id}\n"
            f"Fingerprint: {alert.token.fingerprint}\n"
            f"Context  : {alert.token.context}\n"
            f"Strategy : {alert.token.strategy_name}\n"
            f"Planted  : {alert.token.planted_at.isoformat()}\n"
            f"Detected : {alert.detected_at.isoformat()}\n"
            f"Source   : {alert.source}\n\n"
            f"Detected in snippet:\n{alert.detected_in[:1000]}"
        )
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = f"{self._subject_prefix} {alert.summary()}"
        msg["From"] = self._from_address
        msg["To"] = ", ".join(self._to_addresses)
        return msg

    def send(self, alert: CanaryAlert) -> None:
        msg = self._build_message(alert)
        cfg = self._config

        try:
            if cfg.use_tls:
                server: smtplib.SMTP = smtplib.SMTP_SSL(cfg.host, cfg.port)
            else:
                server = smtplib.SMTP(cfg.host, cfg.port)
                server.starttls()

            with server:
                server.login(cfg.username, cfg.password)
                server.sendmail(
                    self._from_address,
                    self._to_addresses,
                    msg.as_string(),
                )
        except smtplib.SMTPException as exc:
            logger.error("EmailAlerter: failed to send alert email — %s", exc)


class CompositeAlerter(CanaryAlerter):
    """
    Fan out a single alert to multiple alerters in order.

    Exceptions from individual alerters are caught and logged so that
    a failure in one channel does not prevent delivery to the others.

    Parameters
    ----------
    alerters:
        Ordered list of alerters to invoke for each alert.
    """

    def __init__(self, alerters: list[CanaryAlerter]) -> None:
        self._alerters = alerters

    def send(self, alert: CanaryAlert) -> None:
        for alerter in self._alerters:
            try:
                alerter.send(alert)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "CompositeAlerter: alerter %s raised an exception — %s",
                    type(alerter).__name__,
                    exc,
                )
