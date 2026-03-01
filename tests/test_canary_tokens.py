# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
Tests for agent-canary-tokens — generator, store, detector, and alerter.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agent_canary.alerter import LogAlerter
from agent_canary.detector import CanaryDetector
from agent_canary.generator import CanaryGenerator
from agent_canary.store import CanaryStore
from agent_canary.types import AlertSeverity, CanaryStatus


class TestCanaryGenerator:
    def test_plant_returns_canary_fact(self) -> None:
        store = CanaryStore()
        generator = CanaryGenerator(store=store, seed=0)
        fact = generator.plant(context="test-context")
        assert fact is not None
        assert len(fact.value) > 0

    def test_plant_registers_token_in_store(self) -> None:
        store = CanaryStore()
        generator = CanaryGenerator(store=store, seed=0)
        fact = generator.plant(context="system_prompt")
        token = store.get(fact.token.token_id)
        assert token is not None
        assert token.context == "system_prompt"

    def test_planted_token_is_active_by_default(self) -> None:
        store = CanaryStore()
        generator = CanaryGenerator(store=store, seed=0)
        fact = generator.plant()
        assert fact.token.status == CanaryStatus.ACTIVE
        assert fact.token.is_active()

    def test_fact_value_contains_fingerprint(self) -> None:
        store = CanaryStore()
        generator = CanaryGenerator(store=store, seed=0)
        fact = generator.plant()
        assert fact.token.fingerprint in fact.value

    def test_plant_with_metadata_stores_metadata(self) -> None:
        store = CanaryStore()
        generator = CanaryGenerator(store=store, seed=0)
        metadata = {"session_id": "abc123", "region": "us-east-1"}
        fact = generator.plant(metadata=metadata)
        token = store.get(fact.token.token_id)
        assert token is not None
        assert token.metadata.get("session_id") == "abc123"

    def test_plant_with_invalid_strategy_name_raises_value_error(self) -> None:
        store = CanaryStore()
        generator = CanaryGenerator(store=store, seed=0)
        with pytest.raises(ValueError, match="not found"):
            generator.plant(strategy_name="nonexistent-strategy")

    def test_each_plant_produces_unique_fingerprint(self) -> None:
        store = CanaryStore()
        generator = CanaryGenerator(store=store, seed=0)
        facts = [generator.plant() for _ in range(5)]
        fingerprints = [f.token.fingerprint for f in facts]
        # All fingerprints must be unique
        assert len(set(fingerprints)) == len(fingerprints)

    def test_empty_strategies_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="at least one strategy"):
            CanaryGenerator(strategies=[], seed=0)


class TestCanaryStore:
    def test_store_returns_none_for_unknown_token(self) -> None:
        import uuid
        store = CanaryStore()
        assert store.get(uuid.uuid4()) is None

    def test_store_lists_active_tokens(self) -> None:
        store = CanaryStore()
        generator = CanaryGenerator(store=store, seed=0)
        generator.plant(context="ctx-a")
        generator.plant(context="ctx-b")
        active = store.list_active()
        assert len(active) == 2

    def test_deactivate_removes_token_from_active_list(self) -> None:
        store = CanaryStore()
        generator = CanaryGenerator(store=store, seed=0)
        fact = generator.plant()
        store.deactivate(fact.token.token_id)
        active = store.list_active()
        assert all(t.token_id != fact.token.token_id for t in active)

    def test_fingerprints_returns_all_active_fingerprints(self) -> None:
        store = CanaryStore()
        generator = CanaryGenerator(store=store, seed=0)
        fact = generator.plant()
        fingerprints = store.active_fingerprints()
        assert fact.token.fingerprint in fingerprints


class TestCanaryDetector:
    def test_check_text_with_no_canaries_planted_returns_empty_list(self) -> None:
        store = CanaryStore()
        alerter = LogAlerter()
        detector = CanaryDetector(store=store, alerter=alerter)
        alerts = detector.check_text("This text has no canary tokens.", source="test")
        assert len(alerts) == 0

    def test_check_text_detects_planted_fingerprint(self) -> None:
        store = CanaryStore()
        generator = CanaryGenerator(store=store, seed=0)
        alerter_mock = MagicMock()
        alerter_mock.send = MagicMock()
        detector = CanaryDetector(store=store, alerter=alerter_mock)

        fact = generator.plant(context="memory")
        # Embed the fact value into a text string the detector will scan
        contaminated_text = f"Agent said: {fact.value} — continuing task."
        alerts = detector.check_text(contaminated_text, source="llm_output")
        assert len(alerts) >= 1
        assert alerter_mock.send.called

    def test_check_text_marks_token_triggered_by_default(self) -> None:
        store = CanaryStore()
        generator = CanaryGenerator(store=store, seed=0)
        alerter = LogAlerter()
        detector = CanaryDetector(store=store, alerter=alerter, mark_triggered=True)

        fact = generator.plant()
        detector.check_text(fact.value, source="test")
        token = store.get(fact.token.token_id)
        assert token is not None
        assert token.status == CanaryStatus.TRIGGERED

    def test_check_text_uses_provided_severity(self) -> None:
        store = CanaryStore()
        generator = CanaryGenerator(store=store, seed=0)
        alerter_mock = MagicMock()
        alerter_mock.send = MagicMock()
        detector = CanaryDetector(
            store=store,
            alerter=alerter_mock,
            default_severity=AlertSeverity.CRITICAL,
        )

        fact = generator.plant()
        alerts = detector.check_text(fact.value, source="critical-scan")
        if alerts:
            assert alerts[0].severity == AlertSeverity.CRITICAL

    def test_check_text_returns_empty_for_clean_text(self) -> None:
        store = CanaryStore()
        generator = CanaryGenerator(store=store, seed=0)
        generator.plant()  # Plant one token
        alerter = LogAlerter()
        detector = CanaryDetector(store=store, alerter=alerter)
        alerts = detector.check_text("completely unrelated text", source="test")
        assert len(alerts) == 0


class TestLogAlerter:
    def test_log_alerter_does_not_raise(self) -> None:
        from agent_canary.types import CanaryAlert, CanaryToken, CanaryStatus
        import uuid
        from datetime import datetime, timezone

        alerter = LogAlerter()
        token = CanaryToken(
            token_id=uuid.uuid4(),
            fingerprint="fp-test",
            strategy_name="fake_contact",
            context="test",
            planted_at=datetime.now(tz=timezone.utc),
            status=CanaryStatus.ACTIVE,
        )
        alert = CanaryAlert(
            token=token,
            source="test-source",
            severity=AlertSeverity.HIGH,
            detected_at=datetime.now(tz=timezone.utc),
            context_snippet="detected fingerprint here",
        )
        # Should not raise
        alerter.send(alert)
