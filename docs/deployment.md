# Deployment Guide

## Installation

```bash
pip install agent-canary-tokens
```

Or with dev dependencies:

```bash
pip install "agent-canary-tokens[dev]"
```

## Minimal Setup

```python
from agent_canary import CanaryGenerator, CanaryDetector, CanaryStore, LogAlerter

store = CanaryStore()
generator = CanaryGenerator(store=store)
alerter = LogAlerter()
detector = CanaryDetector(store=store, alerter=alerter)
```

## Persisting Store State

The store serialises to JSON for persistence across restarts or sharing
between processes.

```python
# Save
snapshot = store.to_json()
with open("canary_store.json", "w") as file:
    file.write(snapshot)

# Restore
with open("canary_store.json") as file:
    snapshot = file.read()
restored_store = CanaryStore.from_json(snapshot)
```

Store JSON contains all token metadata including planted timestamps and
current status.  Treat this file as sensitive — it reveals which fingerprints
are active and could allow an attacker to avoid triggering them.

## Multi-Channel Alerting

```python
from agent_canary import CompositeAlerter, LogAlerter, WebhookAlerter

alerter = CompositeAlerter([
    LogAlerter(),
    WebhookAlerter(
        url="https://your-siem.example.com/canary-events",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer YOUR_TOKEN",
        },
    ),
])
```

## Email Alerting

```python
from agent_canary import EmailAlerter, SmtpConfig

smtp = SmtpConfig(
    host="smtp.example.com",
    port=465,
    username="alerts@example.com",
    password="...",
    use_tls=True,
)
alerter = EmailAlerter(
    smtp_config=smtp,
    from_address="canary-alerts@example.com",
    to_addresses=["security-team@example.com"],
)
```

## Canary Rotation

Rotate canaries periodically so that an attacker who obtains an old token
list cannot avoid future detections.

```python
# Deactivate old tokens
for token in store.active_tokens():
    if (datetime.now(tz=timezone.utc) - token.planted_at).days > 30:
        store.deactivate(token.token_id)

# Plant fresh canaries
new_fact = generator.plant(context="system_prompt")
```

## Integrating with an Agent Framework

The pattern is the same regardless of framework:

1. Before injecting data into the agent's context, call `generator.plant()`.
2. Embed `fact.value` inside the data (alongside real content).
3. After each LLM response, call `detector.check_text(response)`.
4. Optionally scan tool outputs and retrieved memory chunks as well.

```python
# LangChain-style pseudo-code
def build_system_prompt(base_prompt: str) -> str:
    canary_fact = generator.plant(context="system_prompt")
    return f"{base_prompt}\n\n{canary_fact.value}"

def on_llm_response(response_text: str) -> None:
    alerts = detector.check_text(response_text, source="llm_output")
    if alerts:
        raise SecurityError(f"Canary breach: {alerts[0].summary()}")
```

## Operational Security

- Store the `CanaryStore` JSON snapshot in a location separate from your
  agent's context and memory stores.
- Do not log the `fact.value` of planted canaries to application logs that
  are accessible to the agent.
- The `WebhookAlerter` timeout defaults to 5 seconds.  For high-volume
  deployments, run alerting asynchronously.
- Use `CompositeAlerter` with both `LogAlerter` and `WebhookAlerter` so you
  have a local audit trail even if the remote endpoint is unavailable.
