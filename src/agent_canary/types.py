# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
Core data types for agent-canary-tokens.

Defines the fundamental types used across the canary token system:
CanaryToken, CanaryFact, CanaryAlert, and RedactionStrategy.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID


class CanaryStatus(str, enum.Enum):
    """Lifecycle status of a planted canary token."""

    ACTIVE = "active"
    TRIGGERED = "triggered"
    DEACTIVATED = "deactivated"


class RedactionStrategy(str, enum.Enum):
    """How the system should respond when a canary is detected in output."""

    LOG_ONLY = "log_only"
    REDACT = "redact"
    BLOCK = "block"
    ALERT_AND_CONTINUE = "alert_and_continue"


class AlertSeverity(str, enum.Enum):
    """Severity level attached to a canary detection alert."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class CanaryToken:
    """
    A unique, trackable identifier embedded inside a canary fact.

    Attributes:
        token_id: UUID uniquely identifying this canary instance.
        fingerprint: Short, human-readable string embedded in the canary value
            that can be scanned for in raw text without UUID parsing.
        strategy_name: Name of the strategy that produced this token.
        context: Arbitrary label for where the canary was planted
            (e.g., "system_prompt", "user_message", "tool_output").
        planted_at: UTC timestamp when the token was created.
        status: Current lifecycle status.
        metadata: Optional extra data stored alongside the token.
    """

    token_id: UUID
    fingerprint: str
    strategy_name: str
    context: str
    planted_at: datetime
    status: CanaryStatus = CanaryStatus.ACTIVE
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_active(self) -> bool:
        """Return True when the token is still in the active state."""
        return self.status == CanaryStatus.ACTIVE


@dataclass(frozen=True)
class CanaryFact:
    """
    A synthetic piece of information that contains an embedded canary token.

    This is what actually gets planted inside an agent's context, memory,
    or any monitored text surface.

    Attributes:
        token: The underlying canary token controlling identity and lifecycle.
        value: The synthetic text that should appear verbatim in monitored output
            if a breach occurs.
        category: Human-readable category of the synthetic fact
            (e.g., "contact", "document", "credential", "url").
        description: Optional narrative description to make the fact
            look plausible in context.
    """

    token: CanaryToken
    value: str
    category: str
    description: str = ""

    @property
    def token_id(self) -> UUID:
        """Convenience accessor for the underlying token ID."""
        return self.token.token_id

    @property
    def fingerprint(self) -> str:
        """Convenience accessor for the scannable fingerprint string."""
        return self.token.fingerprint

    def as_plain_text(self) -> str:
        """Return the value as it should appear in planted context."""
        return self.value


@dataclass
class CanaryAlert:
    """
    Raised when a canary fingerprint is found in monitored text.

    Attributes:
        token: The canary token that was detected.
        detected_in: A snippet of the text where the fingerprint appeared.
        detected_at: UTC timestamp of detection.
        severity: How serious the detection is deemed to be.
        source: Optional label for the system or component that triggered
            the check (e.g., "llm_output_filter", "memory_scan").
        extra: Arbitrary extra data provided by the alerter or detector.
    """

    token: CanaryToken
    detected_in: str
    detected_at: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )
    severity: AlertSeverity = AlertSeverity.HIGH
    source: str = "unknown"
    extra: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        """Return a one-line human-readable summary of the alert."""
        return (
            f"[{self.severity.value.upper()}] Canary '{self.token.fingerprint}' "
            f"detected at {self.detected_at.isoformat()} "
            f"(context='{self.token.context}', source='{self.source}')"
        )
