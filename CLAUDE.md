# agent-canary-tokens — Claude Context

## Project Identity
Standalone Python security library for planting synthetic canary facts inside
agent systems to detect memory breaches and data exfiltration.  Zero
dependencies beyond the Python standard library.

## FIRE LINE (Non-Negotiable)
- NO imports from aumos_governance, aumos_types, or any AumOS package
- NO references to memory tiers, consent tracking, or trust levels
- NO integration with any AumOS protocol
- This library must work independently of any agent framework

## Forbidden Identifiers
These must NEVER appear in source code:
progressLevel, promoteLevel, computeTrustScore, behavioralScore,
adaptiveBudget, optimizeBudget, predictSpending, detectAnomaly,
generateCounterfactual, PersonalWorldModel, MissionAlignment, SocialTrust,
CognitiveLoop, AttentionFilter, GOVERNANCE_PIPELINE

## Code Standards
- Python 3.10+ with strict type hints on all function signatures
- Zero external runtime dependencies
- ruff for linting, mypy --strict for type checking
- SPDX header on every source file

## Architecture
```
CanaryGenerator  -->  CanaryStore
     |                    |
     v                    v
CanaryFact          CanaryDetector  -->  CanaryAlerter
```

- `generator.py`  — orchestrates strategy selection and token registration
- `store.py`      — thread-safe token registry with JSON persistence
- `detector.py`   — plain-text fingerprint scanner
- `alerter.py`    — Log / Webhook / Email / Composite alerters
- `types.py`      — frozen dataclasses shared across all modules
- `strategies/`   — pluggable canary fact generators

## Adding a New Strategy
1. Create `src/agent_canary/strategies/my_strategy.py`
2. Subclass `CanaryStrategy` from `base.py`
3. Implement `name`, `make_fingerprint`, and `generate`
4. The `generate` return value MUST contain `token.fingerprint` verbatim
5. Export from `strategies/__init__.py`

## Session Notes
- Run examples with: `python examples/basic_canary.py`
- No test suite in this repo (build-only phase per project spec)
- Linting: `ruff check src/`
- Type check: `mypy src/ --strict`
