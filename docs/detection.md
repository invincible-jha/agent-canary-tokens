# Detection

## How Detection Works

`CanaryDetector.check_text()` performs a plain substring search over all
active canary fingerprints in the store against the supplied text.

For each fingerprint found:

1. The corresponding `CanaryToken` is retrieved from the store.
2. A `CanaryAlert` is constructed with the matching text snippet,
   timestamp, severity, and source label.
3. The alert is dispatched to the configured `CanaryAlerter`.
4. If `mark_triggered=True` (default), the token's status is updated to
   `TRIGGERED` in the store so repeat detections in subsequent scans
   are still possible (tokens remain indexed until explicitly deactivated).

## What to Scan

Any text surface that an agent system can produce or consume is a valid
scan target:

| Surface | Source label suggestion |
|---|---|
| LLM response text | `"llm_output"` |
| Tool / function call output | `"tool_output"` |
| Retrieval result chunks | `"retrieval_result"` |
| Agent-to-agent messages | `"agent_message"` |
| Log lines / traces | `"log_scan"` |
| API response bodies | `"api_response"` |

## Scanning Structured Data

Use `check_dict()` to scan a Python dictionary (e.g., a parsed JSON API
response).  It serialises the dict to JSON and runs the same substring
search.

```python
response_json = {"content": "...", "metadata": {...}}
alerts = detector.check_dict(response_json, source="api_response")
```

## Severity

Pass a `severity` override to `check_text()` or `check_dict()` when the
scanning context implies a specific risk level.  If not specified, the
detector's `default_severity` is used (defaults to `AlertSeverity.HIGH`).

```python
from agent_canary import AlertSeverity

# Treat leaks in external API responses as critical
alerts = detector.check_text(
    external_text,
    source="external_api",
    severity=AlertSeverity.CRITICAL,
)
```

## Performance

Detection is O(n * m) where n is the character length of the scanned text
and m is the number of active tokens.  For typical deployments (tens to
low-hundreds of tokens, response text up to a few thousand characters) this
completes in microseconds.

If you need to scan very large corpora against hundreds of active tokens,
consider building an Aho-Corasick automaton over the fingerprints (using
the `pyahocorasick` library or a custom implementation) and integrating it
via a `CustomStrategy` with a matching custom scan function.

## Thread Safety

`CanaryStore` is thread-safe.  `CanaryDetector` holds no mutable state of
its own; all state is in the store.  Multiple threads may call `check_text()`
concurrently without risk of data corruption.
