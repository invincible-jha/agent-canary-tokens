# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
CanaryStore — in-memory registry of planted canary tokens.

Supports JSON serialisation so that state can be persisted across
process restarts or shared between services.

Thread safety: all mutating operations are protected by a threading.Lock
so the store is safe to use from concurrent threads.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from agent_canary.types import CanaryStatus, CanaryToken


def _token_to_dict(token: CanaryToken) -> dict[str, Any]:
    """Serialise a CanaryToken to a plain JSON-compatible dictionary."""
    return {
        "token_id": str(token.token_id),
        "fingerprint": token.fingerprint,
        "strategy_name": token.strategy_name,
        "context": token.context,
        "planted_at": token.planted_at.isoformat(),
        "status": token.status.value,
        "metadata": token.metadata,
    }


def _dict_to_token(data: dict[str, Any]) -> CanaryToken:
    """Deserialise a CanaryToken from a plain dictionary."""
    return CanaryToken(
        token_id=UUID(data["token_id"]),
        fingerprint=data["fingerprint"],
        strategy_name=data["strategy_name"],
        context=data["context"],
        planted_at=datetime.fromisoformat(data["planted_at"]),
        status=CanaryStatus(data["status"]),
        metadata=data.get("metadata", {}),
    )


class CanaryStore:
    """
    In-memory store for CanaryToken objects.

    Tokens are indexed by their UUID for O(1) lookup, and also by their
    fingerprint string so the detector can quickly find which token
    corresponds to a discovered fingerprint without iterating all tokens.

    Parameters
    ----------
    tokens:
        Optional initial list of tokens to pre-populate the store.
    """

    def __init__(self, tokens: list[CanaryToken] | None = None) -> None:
        self._lock = threading.Lock()
        self._by_id: dict[UUID, CanaryToken] = {}
        self._by_fingerprint: dict[str, UUID] = {}

        if tokens:
            for token in tokens:
                self._index(token)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _index(self, token: CanaryToken) -> None:
        """Add token to both indices without acquiring the lock."""
        self._by_id[token.token_id] = token
        self._by_fingerprint[token.fingerprint] = token.token_id

    def _replace(self, token: CanaryToken) -> None:
        """Replace an existing entry in both indices without locking."""
        old = self._by_id.get(token.token_id)
        if old is not None and old.fingerprint != token.fingerprint:
            self._by_fingerprint.pop(old.fingerprint, None)
        self._index(token)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register(self, token: CanaryToken) -> None:
        """
        Add a new token to the store.

        Parameters
        ----------
        token:
            The token to register.

        Raises
        ------
        ValueError
            If a token with the same ID is already registered.
        """
        with self._lock:
            if token.token_id in self._by_id:
                raise ValueError(
                    f"Token {token.token_id} is already registered. "
                    "Use a new UUID for each planted canary."
                )
            self._index(token)

    def get(self, token_id: UUID) -> CanaryToken | None:
        """Return the token with *token_id*, or None if not found."""
        with self._lock:
            return self._by_id.get(token_id)

    def get_by_fingerprint(self, fingerprint: str) -> CanaryToken | None:
        """Return the token whose fingerprint matches, or None."""
        with self._lock:
            token_id = self._by_fingerprint.get(fingerprint)
            if token_id is None:
                return None
            return self._by_id.get(token_id)

    def active_tokens(self) -> list[CanaryToken]:
        """Return all tokens currently in the ACTIVE state."""
        with self._lock:
            return [t for t in self._by_id.values() if t.is_active()]

    def all_tokens(self) -> list[CanaryToken]:
        """Return all tokens regardless of status."""
        with self._lock:
            return list(self._by_id.values())

    def deactivate(self, token_id: UUID) -> bool:
        """
        Mark a token as DEACTIVATED so it is no longer scanned.

        Parameters
        ----------
        token_id:
            ID of the token to deactivate.

        Returns
        -------
        bool
            True if the token was found and deactivated; False if not found.
        """
        with self._lock:
            token = self._by_id.get(token_id)
            if token is None:
                return False
            updated = CanaryToken(
                token_id=token.token_id,
                fingerprint=token.fingerprint,
                strategy_name=token.strategy_name,
                context=token.context,
                planted_at=token.planted_at,
                status=CanaryStatus.DEACTIVATED,
                metadata=token.metadata,
            )
            self._replace(updated)
            return True

    def mark_triggered(self, token_id: UUID) -> bool:
        """
        Mark a token as TRIGGERED (a canary has been detected).

        Parameters
        ----------
        token_id:
            ID of the token that fired.

        Returns
        -------
        bool
            True if the token was found and updated; False if not found.
        """
        with self._lock:
            token = self._by_id.get(token_id)
            if token is None:
                return False
            updated = CanaryToken(
                token_id=token.token_id,
                fingerprint=token.fingerprint,
                strategy_name=token.strategy_name,
                context=token.context,
                planted_at=token.planted_at,
                status=CanaryStatus.TRIGGERED,
                metadata=token.metadata,
            )
            self._replace(updated)
            return True

    def active_fingerprints(self) -> list[str]:
        """Return fingerprints for all currently active tokens."""
        with self._lock:
            return [
                t.fingerprint
                for t in self._by_id.values()
                if t.is_active()
            ]

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_json(self) -> str:
        """
        Serialise the entire store to a JSON string.

        The returned string can be passed to ``from_json`` to restore the store.
        """
        with self._lock:
            payload = {
                "tokens": [_token_to_dict(t) for t in self._by_id.values()],
                "serialised_at": datetime.now(tz=timezone.utc).isoformat(),
            }
        return json.dumps(payload, indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "CanaryStore":
        """
        Restore a CanaryStore from a JSON string produced by ``to_json``.

        Parameters
        ----------
        json_str:
            A JSON string previously returned by ``CanaryStore.to_json()``.

        Returns
        -------
        CanaryStore
            A new store pre-populated with the deserialised tokens.
        """
        payload = json.loads(json_str)
        tokens = [_dict_to_token(d) for d in payload.get("tokens", [])]
        return cls(tokens=tokens)

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_id)

    def __repr__(self) -> str:
        with self._lock:
            total = len(self._by_id)
            active = sum(1 for t in self._by_id.values() if t.is_active())
        return f"CanaryStore(total={total}, active={active})"
