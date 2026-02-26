# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
Strategy: FakeURLStrategy

Generates unique, trackable URLs that embed the canary token ID directly
in the path.  If any of these URLs appear in agent output, tool calls,
or retrieved content, a canary has leaked.

The URLs use the `.invalid` TLD (RFC 2606) so they cannot resolve to
a real host, avoiding accidental outbound requests.

For production deployments, operators can configure a real callback
domain that is instrumented to fire HTTP alerts when these URLs are fetched.
"""

from __future__ import annotations

import random
import string
from uuid import UUID

from agent_canary.strategies.base import CanaryStrategy
from agent_canary.types import CanaryFact, CanaryToken

_PATH_COMPONENTS: tuple[str, ...] = (
    "report", "document", "asset", "resource", "record",
    "file", "artifact", "dataset", "snapshot", "profile",
)

_QUERY_KEYS: tuple[str, ...] = (
    "ref", "src", "trace", "origin", "session",
)

_PADDING_CHARS: str = string.ascii_lowercase + string.digits


def _random_slug(rng: random.Random, length: int = 6) -> str:
    return "".join(rng.choices(_PADDING_CHARS, k=length))


class FakeURLStrategy(CanaryStrategy):
    """
    Produces synthetic URLs that embed the canary token ID in the path
    segment so that a plain-text scan of any monitored text surface can
    detect a leak by finding the fingerprint substring.

    URL structure::

        https://<domain>/<path-component>/<fingerprint>?<query-key>=<slug>

    Parameters
    ----------
    base_domain:
        Domain to use in generated URLs.  Defaults to
        ``canary-track.invalid`` (non-resolvable, RFC 2606).
    scheme:
        URL scheme.  Defaults to ``https``.
    seed:
        Optional random seed for reproducible generation in tests.
    """

    def __init__(
        self,
        base_domain: str = "canary-track.invalid",
        scheme: str = "https",
        seed: int | None = None,
    ) -> None:
        self._rng = random.Random(seed)
        self._base_domain = base_domain
        self._scheme = scheme

    @property
    def name(self) -> str:
        return "fake_url"

    def make_fingerprint(self, token_id: UUID) -> str:
        """
        Use the full UUID string (with hyphens) as the fingerprint.

        The UUID appears verbatim in the URL path, making it both globally
        unique and trivially scannable.

        Example: ``a1b2c3d4-e5f6-7890-abcd-ef1234567890``
        """
        return str(token_id)

    def generate(self, token: CanaryToken) -> CanaryFact:
        """
        Return a CanaryFact whose `.value` contains a synthetic URL that
        embeds the full token UUID in the path.
        """
        path_component = self._rng.choice(_PATH_COMPONENTS)
        query_key = self._rng.choice(_QUERY_KEYS)
        slug = _random_slug(self._rng)

        url = (
            f"{self._scheme}://{self._base_domain}"
            f"/{path_component}/{token.fingerprint}"
            f"?{query_key}={slug}"
        )

        value = (
            f"Reference URL: {url}\n"
            f"Note: SYNTHETIC CANARY — this URL does not resolve"
        )

        return CanaryFact(
            token=token,
            value=value,
            category="url",
            description=(
                f"Synthetic trackable URL with embedded token "
                f"'{token.fingerprint}'. If this URL is fetched or referenced "
                "outside its planted location, a canary breach is confirmed."
            ),
        )
