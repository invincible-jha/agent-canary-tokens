# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""Shared fixtures for agent-canary-tokens tests."""

from __future__ import annotations

import pytest

from agent_canary.alerter import CanaryAlerter
from agent_canary.generator import CanaryGenerator
from agent_canary.store import CanaryStore


class _InMemoryAlerter(CanaryAlerter):
    """A test alerter that collects alerts in memory."""

    def __init__(self) -> None:
        self.alerts: list[object] = []

    def send(self, alert: object) -> None:  # type: ignore[override]
        self.alerts.append(alert)


@pytest.fixture
def canary_store() -> CanaryStore:
    return CanaryStore()


@pytest.fixture
def in_memory_alerter() -> _InMemoryAlerter:
    return _InMemoryAlerter()


@pytest.fixture
def canary_generator(canary_store: CanaryStore) -> CanaryGenerator:
    return CanaryGenerator(store=canary_store, seed=42)
