# Changelog

All notable changes to `agent-canary-tokens` will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

## [0.1.0] — 2026-02-26

### Added
- `CanaryToken` and `CanaryFact` frozen dataclasses for type-safe token
  identity and planted fact representation.
- `CanaryAlert` dataclass with `AlertSeverity` and one-line `summary()`.
- `RedactionStrategy` enum for downstream response policy decisions.
- `CanaryStore`: thread-safe in-memory registry with JSON serialisation
  (`to_json` / `from_json`) and dual-index lookup by UUID and fingerprint.
- `CanaryGenerator`: orchestrates strategy selection, UUID allocation,
  fingerprint construction, and store registration via `plant()`.
- `CanaryDetector`: plain-text fingerprint scanner that fires alerts and
  optionally marks tokens as TRIGGERED.  Includes `check_dict` helper.
- `LogAlerter`: maps severity to Python logging levels.
- `WebhookAlerter`: HTTP POST with configurable URL and headers.
- `EmailAlerter`: SMTP-based email delivery with `SmtpConfig` dataclass.
- `CompositeAlerter`: fan-out to multiple alerters with per-alerter
  exception isolation.
- `FakeContactStrategy`: synthetic name/email/phone canary facts.
- `FakeDocumentStrategy`: synthetic document title/ID canary facts.
- `FakeCredentialStrategy`: synthetic API key canary facts.
- `FakeURLStrategy`: unique trackable URL canary facts using `.invalid` TLD.
- `CustomStrategy`: delegate generation to caller-supplied functions.
- Three runnable examples: `basic_canary.py`, `webhook_alerting.py`,
  `agent_memory_canary.py`.
- `scripts/fire-line-audit.sh` for automated FIRE LINE compliance checking.
- `pyproject.toml` with hatchling build, ruff, and mypy configuration.
- `py.typed` marker for PEP 561 type checking support.
