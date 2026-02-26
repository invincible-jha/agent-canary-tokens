# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
Canary generation strategies package.

Re-exports all built-in strategies and the abstract base so that callers
only need to import from ``agent_canary.strategies``.
"""

from agent_canary.strategies.base import CanaryStrategy
from agent_canary.strategies.custom import CustomStrategy, FactGeneratorFn, FingerprintFn
from agent_canary.strategies.fake_contact import FakeContactStrategy
from agent_canary.strategies.fake_credential import FakeCredentialStrategy
from agent_canary.strategies.fake_document import FakeDocumentStrategy
from agent_canary.strategies.fake_url import FakeURLStrategy

__all__ = [
    "CanaryStrategy",
    "CustomStrategy",
    "FactGeneratorFn",
    "FingerprintFn",
    "FakeContactStrategy",
    "FakeCredentialStrategy",
    "FakeDocumentStrategy",
    "FakeURLStrategy",
]
