# FIRE LINE — agent-canary-tokens

This document defines the absolute constraints that this repository must
never violate, regardless of feature requests or integrations.

## What This Repository IS

A **standalone** Python security library for planting synthetic canary
facts in text surfaces (agent context, memory, tool outputs) and detecting
when those facts leak into places they should not appear.

It is a general-purpose honeypot/tripwire tool that happens to be useful
for agent systems.  It could be used with LangChain, AutoGen, CrewAI,
custom frameworks, or any system that processes text.

## What This Repository IS NOT

- It is NOT part of the AumOS governance protocol.
- It is NOT a trust management system.
- It is NOT an anomaly detection engine.
- It is NOT a memory tier manager.
- It does NOT track consent.
- It does NOT compute trust scores.
- It does NOT have adaptive behaviour of any kind.

## Hard Constraints

### Import Boundary
```
# These imports must NEVER appear in this repository:
import aumos_governance
import aumos_types
from aumos_core import ...
from aumos_sdks import ...
```

Any code that introduces an AumOS import is an automatic code-review failure.

### Forbidden Concepts
The following concepts from AumOS proprietary IP must not be implemented,
referenced, or even alluded to in code, comments, or documentation:

| Forbidden concept | Why |
|---|---|
| Adaptive trust progression | Core AumOS IP (P0-01) |
| Behavioral scoring | Core AumOS IP (P0-02) |
| Three-tier attention filter | Core AumOS IP |
| GOVERNANCE_PIPELINE | Core AumOS IP |
| Personal World Model (PWM) | Core AumOS IP |
| Mission Alignment Engine (MAE) | Core AumOS IP |
| Social Trust Protocol (STP) | Core AumOS IP |
| Cognitive loop | Core AumOS IP |
| Adaptive budget allocation | Core AumOS IP |

### No Latency Targets
Do not embed specific latency targets (e.g., "<50ms", "<100ms") or
threshold values in source code, comments, or documentation.

### Detection Is Recording Only
The detector scans text and emits alerts.  It does NOT:
- Score or rank canary leaks
- Build profiles of agent behaviour over time
- Automatically adjust what gets planted based on history
- Feed data into any adaptive system

## Review Checklist
Before merging any PR, verify:

- [ ] Zero AumOS imports in `src/` or `examples/`
- [ ] No forbidden identifiers (`grep` the list above)
- [ ] `ruff check src/` passes with zero warnings
- [ ] `mypy src/ --strict` passes with zero errors
- [ ] All source files have the SPDX header
- [ ] `scripts/fire-line-audit.sh` exits 0
