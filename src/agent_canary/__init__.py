# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
agent-canary-tokens
===================

Plant synthetic canary facts in agent systems to detect memory breaches
and data exfiltration.

Quickstart
----------
>>> from agent_canary import CanaryGenerator, CanaryDetector, LogAlerter, CanaryStore
>>> store = CanaryStore()
>>> generator = CanaryGenerator(store=store)
>>> alerter = LogAlerter()
>>> detector = CanaryDetector(store=store, alerter=alerter)
>>> fact = generator.plant(context="system_prompt")
>>> alerts = detector.check_text(fact.value, source="test")
>>> assert len(alerts) == 1
"""

from agent_canary.alerter import (
    CanaryAlerter,
    CompositeAlerter,
    EmailAlerter,
    LogAlerter,
    SmtpConfig,
    WebhookAlerter,
)
from agent_canary.detector import CanaryDetector
from agent_canary.generator import CanaryGenerator
from agent_canary.honeypot import HoneypotConfig, HoneypotEntry, HoneypotMemory
from agent_canary.pii_integration import (
    PII_FORMAT_TEMPLATES,
    PIICanaryStrategy,
    create_pii_canary,
    validate_pii_canary,
)
from agent_canary.pipeline_locator import LocatorResult, PipelineLocator, PipelineStage
from agent_canary.store import CanaryStore
from agent_canary.types import (
    AlertSeverity,
    CanaryAlert,
    CanaryFact,
    CanaryStatus,
    CanaryToken,
    RedactionStrategy,
)

__version__ = "0.1.0"

__all__ = [
    # Core
    "CanaryGenerator",
    "CanaryDetector",
    "CanaryStore",
    # Types
    "CanaryToken",
    "CanaryFact",
    "CanaryAlert",
    "CanaryStatus",
    "AlertSeverity",
    "RedactionStrategy",
    # Alerters
    "CanaryAlerter",
    "LogAlerter",
    "WebhookAlerter",
    "EmailAlerter",
    "SmtpConfig",
    "CompositeAlerter",
    # Pipeline locator
    "PipelineLocator",
    "PipelineStage",
    "LocatorResult",
    # PII integration
    "PIICanaryStrategy",
    "PII_FORMAT_TEMPLATES",
    "create_pii_canary",
    "validate_pii_canary",
    # Honeypot
    "HoneypotMemory",
    "HoneypotConfig",
    "HoneypotEntry",
]
