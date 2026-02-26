# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `agent-canary-tokens`, please
report it privately to: security@muveraai.com

Do not open a public GitHub issue for security vulnerabilities.

We will acknowledge receipt within 3 business days and aim to provide a
resolution or mitigation plan within 14 days.

## Scope

This library generates synthetic data and performs plain-text scanning.
It does not make outbound network connections by default (WebhookAlerter
does so only when explicitly configured by the operator).

The `EmailAlerter` and `WebhookAlerter` classes accept operator-supplied
URLs and SMTP credentials.  Callers are responsible for ensuring these
values are stored and transmitted securely.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
