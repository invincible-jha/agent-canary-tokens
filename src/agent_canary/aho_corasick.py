# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 MuVeraAI Corporation
"""
Aho-Corasick multi-pattern canary scanning.

Provides efficient simultaneous scanning for many canary fingerprints in a
single pass over the target text. Asymptotic cost is O(n + m + z) where:
  n = text length
  m = total length of all patterns
  z = number of matches found

This is substantially faster than the naive O(n * k) approach (k = pattern
count) when monitoring large text bodies against many active canaries.

The automaton is built from scratch when patterns change. For workloads where
the canary set changes frequently, callers should batch updates and rebuild
rather than rebuilding after every insertion.

Example
-------
>>> automaton = AhoCorasickAutomaton()
>>> automaton.build({"fingerprint_1": "CNRY-abc123", "fingerprint_2": "CNRY-xyz789"})
>>> matches = automaton.scan("User retrieved CNRY-abc123 from context.")
>>> matches[0].pattern_id
'fingerprint_1'
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Match result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CanaryMatch:
    """A single canary pattern found by the Aho-Corasick automaton.

    Attributes:
        pattern_id: The identifier of the matched canary pattern.
        pattern:    The exact string that was found in the text.
        start:      Zero-based start index of the match in the text.
        end:        Zero-based exclusive end index of the match.
    """

    pattern_id: str
    pattern: str
    start: int
    end: int

    @property
    def span(self) -> tuple[int, int]:
        """Return the (start, end) span tuple."""
        return (self.start, self.end)


# ---------------------------------------------------------------------------
# Trie node
# ---------------------------------------------------------------------------


class _TrieNode:
    """Internal node for the Aho-Corasick trie."""

    __slots__ = ("children", "fail", "output")

    def __init__(self) -> None:
        self.children: dict[str, _TrieNode] = {}
        self.fail: _TrieNode | None = None
        # Output: list of (pattern_id, pattern) for patterns ending here
        self.output: list[tuple[str, str]] = []


# ---------------------------------------------------------------------------
# Automaton
# ---------------------------------------------------------------------------


class AhoCorasickAutomaton:
    """Multi-pattern string search automaton using the Aho-Corasick algorithm.

    Scans arbitrary text for all registered patterns in a single linear pass.
    All patterns are plain strings (case-sensitive by default). For
    case-insensitive matching, normalize both patterns and text to lowercase
    before use.

    Lifecycle:
    1. Call ``build(patterns)`` to compile the automaton.
    2. Call ``scan(text)`` one or more times.
    3. Call ``build(...)`` again whenever the pattern set changes.

    Parameters
    ----------
    case_sensitive:
        If False, both patterns and scanned text are lowercased before
        processing. Defaults to True.

    Example
    -------
    >>> automaton = AhoCorasickAutomaton()
    >>> automaton.build({"tok1": "CNRY-aaa", "tok2": "CNRY-bbb"})
    >>> automaton.scan("got CNRY-aaa and CNRY-bbb here")
    [CanaryMatch(pattern_id='tok1', ...), CanaryMatch(pattern_id='tok2', ...)]
    """

    def __init__(self, case_sensitive: bool = True) -> None:
        self._case_sensitive = case_sensitive
        self._root: _TrieNode = _TrieNode()
        self._is_built: bool = False
        self._pattern_count: int = 0

    @property
    def is_built(self) -> bool:
        """True if the automaton has been compiled and is ready to scan."""
        return self._is_built

    @property
    def pattern_count(self) -> int:
        """Number of patterns currently compiled into the automaton."""
        return self._pattern_count

    def build(self, patterns: dict[str, str]) -> None:
        """Compile the automaton from a mapping of pattern_id -> pattern_text.

        This replaces any previously compiled patterns. Patterns that are
        empty strings are silently skipped.

        Parameters
        ----------
        patterns:
            Mapping from a pattern identifier (e.g., the canary fingerprint
            string or token UUID) to the pattern text to search for.
        """
        # Reset
        self._root = _TrieNode()
        self._is_built = False
        self._pattern_count = 0

        # Phase 1: Insert all patterns into the trie
        for pattern_id, pattern_text in patterns.items():
            if not pattern_text:
                continue
            text = pattern_text if self._case_sensitive else pattern_text.lower()
            self._insert(pattern_id, pattern_text, text)
            self._pattern_count += 1

        # Phase 2: Build failure links via BFS
        self._build_failure_links()
        self._is_built = True
        logger.debug(
            "AhoCorasickAutomaton: built with %d pattern(s).", self._pattern_count
        )

    def scan(self, text: str) -> list[CanaryMatch]:
        """Search *text* for all registered patterns in a single linear pass.

        Parameters
        ----------
        text:
            The text to search.

        Returns
        -------
        list[CanaryMatch]:
            All matches found, sorted by start position. When multiple
            patterns match at overlapping positions, all are returned.

        Raises
        ------
        RuntimeError:
            If called before ``build()`` has been invoked.
        """
        if not self._is_built:
            raise RuntimeError(
                "AhoCorasickAutomaton.scan() called before build(). "
                "Call build(patterns) first."
            )

        if not text or self._pattern_count == 0:
            return []

        scan_text = text if self._case_sensitive else text.lower()
        matches: list[CanaryMatch] = []
        current: _TrieNode = self._root

        for index, char in enumerate(scan_text):
            # Follow failure links until we find a transition or reach root
            while current is not self._root and char not in current.children:
                current = current.fail  # type: ignore[assignment]

            if char in current.children:
                current = current.children[char]

            # Collect all patterns that end at this position
            for pattern_id, original_pattern in current.output:
                start = index - len(original_pattern) + 1
                matches.append(
                    CanaryMatch(
                        pattern_id=pattern_id,
                        pattern=original_pattern,
                        start=start,
                        end=index + 1,
                    )
                )

        return sorted(matches, key=lambda m: m.start)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _insert(
        self,
        pattern_id: str,
        original_pattern: str,
        normalized_pattern: str,
    ) -> None:
        """Insert one pattern into the trie."""
        node = self._root
        for char in normalized_pattern:
            if char not in node.children:
                node.children[char] = _TrieNode()
            node = node.children[char]
        node.output.append((pattern_id, original_pattern))

    def _build_failure_links(self) -> None:
        """BFS over the trie to set failure (suffix) links on every node."""
        queue: deque[_TrieNode] = deque()

        # Root's direct children fail back to root
        for child in self._root.children.values():
            child.fail = self._root
            queue.append(child)

        while queue:
            current = queue.popleft()

            for char, child in current.children.items():
                # Walk failure links to find the longest proper suffix
                fail_node = current.fail
                while fail_node is not None and char not in fail_node.children:
                    fail_node = fail_node.fail

                child.fail = (
                    fail_node.children[char]
                    if fail_node is not None and char in fail_node.children
                    else self._root
                )

                # Merge output from failure link (suffix pattern inheritance)
                child.output.extend(child.fail.output)

                queue.append(child)


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------


def build_automaton_from_store(
    fingerprints: dict[str, str],
    case_sensitive: bool = True,
) -> AhoCorasickAutomaton:
    """Build and return a compiled ``AhoCorasickAutomaton`` from a fingerprint map.

    Parameters
    ----------
    fingerprints:
        Mapping from fingerprint string (pattern_id) to the fingerprint text.
    case_sensitive:
        Whether matching should be case-sensitive. Defaults to True.

    Returns
    -------
    AhoCorasickAutomaton:
        A ready-to-use compiled automaton.
    """
    automaton = AhoCorasickAutomaton(case_sensitive=case_sensitive)
    automaton.build(fingerprints)
    return automaton
