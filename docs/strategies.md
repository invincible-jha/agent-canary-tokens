# Canary Strategies

Strategies are the pluggable components that generate synthetic canary facts.
Each strategy produces a unique fingerprint for a given token UUID and then
constructs a realistic-looking synthetic value that embeds that fingerprint.

## Built-in Strategies

### FakeContactStrategy

**Category:** `contact`

Generates synthetic contact records containing a fabricated name, email
address, and phone number.  The fingerprint is embedded in the email local
part so that a plain-text scan will locate it.

**Fingerprint format:** `cnry-<first-12-hex-chars>`

Example value:
```
Contact: Brienne Ashvale
Email: cnry-a1b2c3d4e5f6@canary-test.invalid
Phone: +1-555-4829301
```

**Use case:** Plant in agent memory or retrieval context where contact data
is a plausible content type.

---

### FakeDocumentStrategy

**Category:** `document`

Generates synthetic internal document references including a title, document
ID, revision, year, and a synthetic classification label.  The fingerprint
is embedded as the document ID.

**Fingerprint format:** `DOC-XXXX-XXXX-XXXX` (uppercase hex segments)

Example value:
```
Document Title: Project Nightfall — Technical Specification
Document ID: DOC-A1B2-C3D4-E5F6
Revision: v2.0
Year: 2026
Classification: SYNTHETIC-CONFIDENTIAL
```

**Use case:** Plant in document retrieval pipelines or knowledge-base memory
to detect if the agent is leaking internal document references.

---

### FakeCredentialStrategy

**Category:** `credential`

Generates synthetic API keys that embed the fingerprint between a recognisable
prefix and random padding.  Keys are structurally marked as synthetic
(`cnry_` prefix) so they cannot be confused with real secrets.

**Fingerprint format:** First 16 uppercase hex characters of the UUID.

Example value:
```
Service: SyntheticService-A1B2C3
API Key: cnry_sk_A1B2C3D4E5F6A7B8xKj92nPqRsT4Uv5W
Note: SYNTHETIC CANARY — not a real credential
```

**Use case:** Plant in contexts where credential exfiltration is a concern,
such as tool outputs or function call responses.

---

### FakeURLStrategy

**Category:** `url`

Generates unique URLs that embed the full token UUID in the path segment.
URLs use the `.invalid` TLD (RFC 2606) so they cannot resolve to a real host.
For production, operators can configure a real callback domain and instrument
it to fire HTTP alerts when the URL is fetched.

**Fingerprint format:** Full UUID string with hyphens.

Example value:
```
Reference URL: https://canary-track.invalid/document/a1b2c3d4-e5f6-7890-abcd-ef1234567890?ref=kj4p9m
Note: SYNTHETIC CANARY — this URL does not resolve
```

**Use case:** Plant in any context where URL exfiltration is a risk.
If the URL is fetched, both the plain-text detector and your web server
logs will signal the breach.

---

### CustomStrategy

**Category:** caller-defined

Allows any caller to supply their own fingerprint builder and fact generator
without subclassing.

```python
from agent_canary.strategies.custom import CustomStrategy
from agent_canary.types import CanaryFact

strategy = CustomStrategy(
    strategy_name="internal_project_code",
    fingerprint_fn=lambda uid: f"PROJ-{str(uid)[:8].upper()}",
    generator_fn=lambda token: CanaryFact(
        token=token,
        value=f"Internal project reference: {token.fingerprint}",
        category="project_code",
    ),
)
```

The `generator_fn` **must** embed `token.fingerprint` verbatim in the
returned fact's `.value`.  `CustomStrategy` validates this at runtime.

---

## Implementing a New Strategy

1. Subclass `CanaryStrategy` from `agent_canary.strategies.base`.
2. Implement the `name` property (must be unique across registered strategies).
3. Implement `make_fingerprint(token_id: UUID) -> str`.
4. Implement `generate(token: CanaryToken) -> CanaryFact`.
5. Ensure `fact.value` contains `token.fingerprint` verbatim.
6. Export from `agent_canary/strategies/__init__.py`.

```python
from uuid import UUID
from agent_canary.strategies.base import CanaryStrategy
from agent_canary.types import CanaryFact, CanaryToken

class MyStrategy(CanaryStrategy):
    @property
    def name(self) -> str:
        return "my_strategy"

    def make_fingerprint(self, token_id: UUID) -> str:
        return f"MY-{str(token_id)[:8].upper()}"

    def generate(self, token: CanaryToken) -> CanaryFact:
        return CanaryFact(
            token=token,
            value=f"Custom canary: {token.fingerprint}",
            category="custom",
        )
```
