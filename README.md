# agent-canary-tokens

Plant synthetic canary facts in agent systems to detect memory breaches
and data exfiltration.

A standalone Python security library with zero external dependencies.
Works with any agent framework: LangChain, AutoGen, CrewAI, custom stacks,
or anything that processes text.

---

## What Problem Does This Solve?

Large language model agents routinely ingest sensitive context — user data,
internal documents, API credentials — through system prompts, memory stores,
and retrieval pipelines.  If that context leaks into model outputs, tool
calls, or logs, it is often invisible without active monitoring.

**Canary tokens** solve this by planting synthetic facts that look real
but are entirely fabricated.  If a canary fact surfaces anywhere it should
not, you know exactly which context was breached, when it was planted, and
where it appeared.

---

## Quickstart

```python
from agent_canary import CanaryGenerator, CanaryDetector, CanaryStore, LogAlerter

# Set up
store = CanaryStore()
generator = CanaryGenerator(store=store)
alerter = LogAlerter()
detector = CanaryDetector(store=store, alerter=alerter)

# Plant a canary in agent context
fact = generator.plant(context="system_prompt")
print(fact.value)
# Contact: Elowyn Coldfen
# Email: cnry-a1b2c3d4e5f6@canary-test.invalid
# Phone: +1-555-4829301

# Inject fact.value into your agent's context alongside real data

# After each LLM response, scan for leaks
alerts = detector.check_text(llm_response, source="llm_output")
if alerts:
    print(f"Breach detected: {alerts[0].summary()}")
```

---

## Installation

```bash
pip install agent-canary-tokens
```

Requires Python 3.10+.  Zero runtime dependencies.

---

## Core Concepts

| Component | Role |
|---|---|
| `CanaryGenerator` | Selects a strategy, allocates a UUID, registers the token, returns a plantable `CanaryFact` |
| `CanaryStore` | Thread-safe registry of all planted tokens, with JSON persistence |
| `CanaryDetector` | Scans text for active fingerprints, fires alerts on match |
| `CanaryAlerter` | Dispatches alerts via log, webhook, email, or any combination |
| `CanaryStrategy` | Pluggable fact generator — four built-in, one custom delegate |

---

## Built-in Strategies

| Strategy | Category | What it generates |
|---|---|---|
| `FakeContactStrategy` | `contact` | Name, email, phone number |
| `FakeDocumentStrategy` | `document` | Document title, ID, revision, classification |
| `FakeCredentialStrategy` | `credential` | Synthetic API key |
| `FakeURLStrategy` | `url` | Trackable URL with UUID in path |
| `CustomStrategy` | caller-defined | Anything — supply your own functions |

---

## Alerters

```python
from agent_canary import (
    LogAlerter,
    WebhookAlerter,
    EmailAlerter,
    SmtpConfig,
    CompositeAlerter,
)

# Log to Python logging
log_alerter = LogAlerter()

# HTTP POST to a webhook
webhook_alerter = WebhookAlerter(
    url="https://hooks.example.com/canary",
    headers={"Authorization": "Bearer TOKEN"},
)

# SMTP email
email_alerter = EmailAlerter(
    smtp_config=SmtpConfig(host="smtp.example.com", port=465,
                           username="u", password="p"),
    from_address="canary@example.com",
    to_addresses=["security@example.com"],
)

# Fan out to all channels
alerter = CompositeAlerter([log_alerter, webhook_alerter, email_alerter])
```

---

## Persistence

```python
# Save store state to JSON
snapshot = store.to_json()

# Restore in a new process
from agent_canary import CanaryStore
store = CanaryStore.from_json(snapshot)
```

---

## Using Multiple Strategies

```python
from agent_canary import CanaryGenerator, CanaryStore
from agent_canary.strategies import (
    FakeContactStrategy,
    FakeDocumentStrategy,
    FakeCredentialStrategy,
    FakeURLStrategy,
)

store = CanaryStore()
generator = CanaryGenerator(
    strategies=[
        FakeContactStrategy(),
        FakeDocumentStrategy(),
        FakeCredentialStrategy(),
        FakeURLStrategy(),
    ],
    store=store,
)

# Plant with a specific strategy
contact_fact = generator.plant(context="memory", strategy_name="fake_contact")
cred_fact    = generator.plant(context="tool_output", strategy_name="fake_credential")

# Or let the generator pick randomly
random_fact  = generator.plant(context="retrieval")
```

---

## Custom Strategy

```python
from agent_canary.strategies.custom import CustomStrategy
from agent_canary.types import CanaryFact

strategy = CustomStrategy(
    strategy_name="project_code",
    fingerprint_fn=lambda uid: f"PROJ-{str(uid)[:8].upper()}",
    generator_fn=lambda token: CanaryFact(
        token=token,
        value=f"Internal code: {token.fingerprint}",
        category="project_code",
    ),
)

generator = CanaryGenerator(strategies=[strategy], store=store)
```

---

## Examples

Three runnable examples in `examples/`:

- `basic_canary.py` — minimal plant-and-detect workflow
- `webhook_alerting.py` — composite alerter with local webhook receiver
- `agent_memory_canary.py` — full agent session simulation with multiple strategies

---

## Documentation

- `docs/strategies.md` — strategy reference and authoring guide
- `docs/detection.md` — how detection works, performance, thread safety
- `docs/deployment.md` — installation, persistence, rotation, framework integration

---

## Security

See `SECURITY.md` for the vulnerability disclosure policy.

---

## License

Apache License, Version 2.0
See https://www.apache.org/licenses/LICENSE-2.0 for full text.
Copyright (c) 2026 MuVeraAI Corporation
