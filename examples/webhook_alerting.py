# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
Example: webhook_alerting.py

Shows how to configure WebhookAlerter to POST canary detection events
to an external endpoint, and how to combine it with LogAlerter using
CompositeAlerter so alerts go to both channels simultaneously.

For a real deployment, replace WEBHOOK_URL with your actual endpoint
(e.g., a Slack incoming webhook, PagerDuty event API, or custom SIEM).

Run with:
    python examples/webhook_alerting.py
"""

from __future__ import annotations

import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from agent_canary import (
    CanaryDetector,
    CanaryGenerator,
    CanaryStore,
    CompositeAlerter,
    LogAlerter,
    WebhookAlerter,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

# ---------------------------------------------------------------------------
# Minimal in-process HTTP server to receive the webhook POST
# ---------------------------------------------------------------------------

received_payloads: list[bytes] = []


class _WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        received_payloads.append(body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass  # Suppress default request logging to keep example output clean


def _start_local_server(port: int = 18742) -> HTTPServer:
    server = HTTPServer(("127.0.0.1", port), _WebhookHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# ---------------------------------------------------------------------------
# Main example
# ---------------------------------------------------------------------------


def main() -> None:
    server = _start_local_server(port=18742)
    webhook_url = "http://127.0.0.1:18742/canary-alert"

    print(f"Local webhook server listening at {webhook_url}")

    # Build a composite alerter: log + webhook
    alerter = CompositeAlerter([
        LogAlerter(),
        WebhookAlerter(
            url=webhook_url,
            headers={"Content-Type": "application/json", "X-Canary-Source": "example"},
        ),
    ])

    store = CanaryStore()
    generator = CanaryGenerator(store=store)
    detector = CanaryDetector(store=store, alerter=alerter)

    # Plant two canaries using different strategies
    contact_fact = generator.plant(context="agent_memory", strategy_name="fake_contact")
    url_fact = generator.plant(context="tool_output", strategy_name="fake_url")

    print(f"\nPlanted contact canary: fingerprint={contact_fact.fingerprint}")
    print(f"Planted URL canary    : fingerprint={url_fact.fingerprint}")

    # Simulate a leak containing the URL canary
    leaked_text = (
        "Here is the resource I retrieved:\n"
        f"{url_fact.value}\n"
        "Please use the above reference."
    )

    alerts = detector.check_text(leaked_text, source="retrieval_output")

    print(f"\nAlerts fired: {len(alerts)}")
    for alert in alerts:
        print(f"  -> {alert.summary()}")

    print(f"\nWebhook payloads received: {len(received_payloads)}")
    for payload in received_payloads:
        print(f"  -> {payload.decode()[:200]}")

    server.shutdown()


if __name__ == "__main__":
    main()
