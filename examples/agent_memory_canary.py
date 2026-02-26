# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
Example: agent_memory_canary.py

Demonstrates planting canaries inside simulated agent context windows and
then scanning LLM responses for leaks.

The pattern here mirrors real usage with any agent framework:

1. Before injecting data into the context, plant a canary fact alongside it.
2. After each LLM turn, scan the output through the detector.
3. On detection, the alerter fires (log / webhook / email).

This example simulates the full cycle without requiring a real LLM.

Run with:
    python examples/agent_memory_canary.py
"""

from __future__ import annotations

import logging
import textwrap
from dataclasses import dataclass, field

from agent_canary import (
    AlertSeverity,
    CanaryDetector,
    CanaryFact,
    CanaryGenerator,
    CanaryStore,
    LogAlerter,
)
from agent_canary.strategies import (
    FakeContactStrategy,
    FakeCredentialStrategy,
    FakeDocumentStrategy,
    FakeURLStrategy,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


# ---------------------------------------------------------------------------
# Simulated agent context
# ---------------------------------------------------------------------------


@dataclass
class AgentContext:
    """Simplified representation of an agent's running context window."""

    system_instructions: str = ""
    memory_chunks: list[str] = field(default_factory=list)
    planted_canaries: list[CanaryFact] = field(default_factory=list)

    def inject_memory(self, chunk: str) -> None:
        self.memory_chunks.append(chunk)

    def inject_canary(self, fact: CanaryFact) -> None:
        self.planted_canaries.append(fact)
        # The canary value is injected alongside the real memory chunk
        self.memory_chunks.append(fact.value)

    def build_prompt(self) -> str:
        memory_section = "\n---\n".join(self.memory_chunks)
        return (
            f"[SYSTEM]\n{self.system_instructions}\n\n"
            f"[RETRIEVED CONTEXT]\n{memory_section}"
        )


# ---------------------------------------------------------------------------
# Simulated LLM that sometimes leaks context
# ---------------------------------------------------------------------------


def simulate_llm_response(prompt: str, leak_canary: bool = False) -> str:
    """
    Simulate an LLM response.

    When *leak_canary* is True, the response includes verbatim text from the
    prompt (simulating a model that memorised or was prompted to repeat context).
    """
    if leak_canary:
        # Simulate the model regurgitating part of its context
        snippet = prompt[prompt.index("[RETRIEVED CONTEXT]"):][:300]
        return (
            "Based on the information available to me:\n\n"
            + snippet
            + "\n\nThis is what I found in my knowledge base."
        )
    return (
        "I can help with that request. "
        "Let me search for the relevant information and get back to you."
    )


# ---------------------------------------------------------------------------
# Main example
# ---------------------------------------------------------------------------


def main() -> None:
    # Build the canary infrastructure
    strategies = [
        FakeContactStrategy(seed=42),
        FakeDocumentStrategy(seed=43),
        FakeCredentialStrategy(seed=44),
        FakeURLStrategy(seed=45),
    ]
    store = CanaryStore()
    generator = CanaryGenerator(strategies=strategies, store=store)
    alerter = LogAlerter()
    detector = CanaryDetector(
        store=store,
        alerter=alerter,
        default_severity=AlertSeverity.CRITICAL,
    )

    # Set up a simulated agent session
    context = AgentContext(
        system_instructions=(
            "You are a helpful assistant. "
            "Answer questions based only on the provided context."
        )
    )

    # Inject real memory alongside canaries
    context.inject_memory("User preference: prefers concise answers.")

    contact_canary = generator.plant(context="agent_session_memory", strategy_name="fake_contact")
    context.inject_canary(contact_canary)

    doc_canary = generator.plant(context="agent_session_memory", strategy_name="fake_document")
    context.inject_canary(doc_canary)

    context.inject_memory("Project status: on track for Q2 delivery.")

    print("=== Agent Context (excerpt) ===")
    print(textwrap.indent(context.build_prompt()[:600], "  "))
    print("  ...")
    print(f"\nActive canary tokens in store: {len(store.active_tokens())}")

    # Turn 1: Clean response — model does not leak context
    print("\n=== Turn 1: Clean response ===")
    response_1 = simulate_llm_response(context.build_prompt(), leak_canary=False)
    print(f"LLM response: {response_1}")
    alerts_1 = detector.check_text(response_1, source="llm_turn_1")
    print(f"Alerts fired: {len(alerts_1)}")

    # Turn 2: Leaking response — model repeats planted context verbatim
    print("\n=== Turn 2: Leaking response ===")
    response_2 = simulate_llm_response(context.build_prompt(), leak_canary=True)
    print(f"LLM response (first 400 chars): {response_2[:400]}")
    alerts_2 = detector.check_text(response_2, source="llm_turn_2")
    print(f"Alerts fired: {len(alerts_2)}")
    for alert in alerts_2:
        print(f"  -> {alert.summary()}")

    # Show persistence — serialise and restore store
    print("\n=== Store persistence ===")
    json_snapshot = store.to_json()
    print(f"JSON snapshot length: {len(json_snapshot)} chars")

    from agent_canary import CanaryStore as CS
    restored_store = CS.from_json(json_snapshot)
    print(f"Restored store: {restored_store}")


if __name__ == "__main__":
    main()
