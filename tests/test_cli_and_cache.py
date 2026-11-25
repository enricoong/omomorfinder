"""
Tests for argument parsing, settings, the public suffix list and the cache.
"""

import pytest

from omomorfinder import __version__
from omomorfinder.cache import Cache
from omomorfinder.cli import build_parser, settings_from_args
from omomorfinder.resources import PublicSuffixList


def test_parser_profiles_and_defaults() -> None:
    """
    Profiles map to settings and nothing is exported without -o.

    Returns:
        None
    """
    args = build_parser().parse_args(["example.com", "--deep", "--tlds", "com,net"])
    s = settings_from_args(args)
    assert s.profile == "deep" and s.deep and s.tld_mode == "com,net"
    assert args.output is None


def test_unknown_fuzzer_rejected() -> None:
    """
    An unknown fuzzer name aborts with a clear message.

    Returns:
        None
    """
    args = build_parser().parse_args(["example.com", "--fuzzers", "omission,nope"])
    with pytest.raises(SystemExit):
        settings_from_args(args)


def test_version_flag(capsys) -> None:
    """
    --version prints the single-source version.

    Args:
        capsys: pytest output capture.
    Returns:
        None
    """
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--version"])
    assert __version__ in capsys.readouterr().out


def test_public_suffix_list_rules() -> None:
    """
    Normal, multi-level, wildcard and exception rules.

    Returns:
        None
    """
    psl = PublicSuffixList(["com", "uk", "co.uk", "*.ck", "!www.ck"])
    assert psl.split("login.example.co.uk") == ("login", "example", "co.uk")
    assert psl.registrable("a.b.example.com") == "example.com"
    assert psl.suffix("foo.bar.ck") == "bar.ck"
    assert psl.suffix("www.ck") == "ck"


def test_cache_roundtrip_and_disabled(tmp_path) -> None:
    """
    Values survive a reopen; a disabled cache always misses.

    Args:
        tmp_path: pytest temporary directory.
    Returns:
        None
    """
    db = tmp_path / "c.db"
    cache = Cache(db)
    key = Cache.make_key("GET", "https://example.com")
    cache.set("http", key, {"status": 200}, b"body", ttl=60)
    cache.close()
    reopened = Cache(db)
    assert reopened.get("http", key) == ({"status": 200}, b"body")
    reopened.close()
    assert Cache(db, enabled=False).get("http", key) is None
