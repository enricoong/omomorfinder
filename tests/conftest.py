"""
Shared pytest fixtures. Every test is offline: no DNS, HTTP or WHOIS traffic.
"""

from __future__ import annotations

import pytest

from omomorfinder import similarity
from omomorfinder.resources import _FALLBACK_CONFUSABLES, _FALLBACK_PSL, POPULAR_TLDS, PublicSuffixList


class StubResources:
    """
    Minimal stand-in for ResourceManager backed by the built-in fallbacks.

    Provides the same read-only methods the generator and engine use, without
    downloading anything.
    """

    def confusables(self) -> dict[str, set[str]]:
        """
        Built-in confusables table.

        Returns:
            dict[str, set[str]]: ASCII char -> lookalike characters.
        """
        return {k: set(v) for k, v in _FALLBACK_CONFUSABLES.items()}

    def tlds(self) -> set[str]:
        """
        Built-in TLD list.

        Returns:
            set[str]: Single-label popular TLDs.
        """
        return {t for t in POPULAR_TLDS if "." not in t}

    def psl(self) -> PublicSuffixList:
        """
        Built-in Public Suffix List.

        Returns:
            PublicSuffixList: Matcher over the fallback rules.
        """
        return PublicSuffixList(list(_FALLBACK_PSL))


@pytest.fixture(scope="session")
def resources() -> StubResources:
    """
    Offline resources with confusables registered for skeleton computation.

    Returns:
        StubResources: Stub resource manager.
    """
    res = StubResources()
    similarity.load_confusables(res.confusables())
    return res
