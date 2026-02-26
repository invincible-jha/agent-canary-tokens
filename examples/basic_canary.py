# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
Example: basic_canary.py

Demonstrates the minimal workflow for planting a canary fact and then
detecting it in scanned text.

Run with:
    python examples/basic_canary.py
"""

from __future__ import annotations

import logging

from agent_canary import (
    CanaryDetector,
    CanaryGenerator,
    CanaryStore,
    LogAlerter,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


def main() -> None:
    # 1. Set up shared store, generator, and detector
    store = CanaryStore()
    generator = CanaryGenerator(store=store)
    alerter = LogAlerter()
    detector = CanaryDetector(store=store, alerter=alerter)

    # 2. Plant a canary fact (default strategy chosen at random)
    fact = generator.plant(context="example_system_prompt")

    print("\n--- Planted canary fact ---")
    print(fact.value)
    print(f"\nFingerprint: {fact.fingerprint}")
    print(f"Token ID   : {fact.token_id}")
    print(f"Category   : {fact.category}")

    # 3. Simulate a clean text — no alert expected
    clean_text = "The quick brown fox jumps over the lazy dog."
    clean_alerts = detector.check_text(clean_text, source="clean_source")
    print(f"\nClean scan — alerts fired: {len(clean_alerts)}")

    # 4. Simulate a leak: the canary value appears in an LLM response
    leaked_response = (
        "Based on my knowledge, here is what I found:\n"
        f"{fact.value}\n"
        "Let me know if you need more information."
    )
    leak_alerts = detector.check_text(leaked_response, source="llm_output")
    print(f"\nLeak scan  — alerts fired: {len(leak_alerts)}")
    for alert in leak_alerts:
        print(f"  -> {alert.summary()}")

    # 5. Show store state
    print(f"\nStore: {store}")


if __name__ == "__main__":
    main()
