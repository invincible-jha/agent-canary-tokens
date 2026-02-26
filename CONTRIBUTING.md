# Contributing to agent-canary-tokens

Thank you for your interest in contributing.  This project is in early
development.  Contribution guidelines will be expanded as the project matures.

## Quick Start

1. Fork the repository and clone your fork.
2. Create a feature branch: `git checkout -b feature/my-improvement`
3. Install dev dependencies: `pip install -e ".[dev]"`
4. Make changes, ensuring all type hints are present and linter passes.
5. Run `scripts/fire-line-audit.sh` and confirm it exits 0.
6. Open a pull request against `main`.

## Code Standards

- Python 3.10+ with strict type hints on all public function signatures.
- Zero external runtime dependencies — standard library only.
- `ruff check src/` must pass with zero warnings.
- `mypy src/ --strict` must pass with zero errors.
- Every source file must begin with the SPDX header.

## FIRE LINE

Before submitting, read `FIRE_LINE.md`.  PRs that introduce AumOS imports
or forbidden identifiers will be closed without review.

## Issues

Bug reports and feature requests are welcome via GitHub Issues.
Please include a minimal reproducible example for bugs.
