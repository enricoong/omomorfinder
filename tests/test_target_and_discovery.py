"""
Tests for domain-only input validation and brand-in-subdomain detection.
"""

import pytest

from omomorfinder.pipeline.context import InputError
from omomorfinder.pipeline.discovery import brand_in_labels, credential_label
from omomorfinder.pipeline.target import parse_target, validate_domain


@pytest.mark.parametrize("bad", [
    "https://example.com", "example.com/login", "user@example.com", "example.com:8080",
    "192.168.1.10", "localhost", "exa mple.com", "*.example.com", "", "-bad-.com",
])
def test_validate_domain_rejects_non_domains(bad: str) -> None:
    """
    URLs, paths, ports, IPs, wildcards and malformed names are rejected.

    Args:
        bad (str): Invalid input.
    Returns:
        None
    """
    with pytest.raises(InputError):
        validate_domain(bad)


def test_validate_domain_accepts_domains() -> None:
    """
    Plain, upper-case, trailing-dot and IDN domains are accepted.

    Returns:
        None
    """
    assert validate_domain("Example.COM.") == "example.com"
    assert validate_domain("exämple.de") == "exämple.de"
    assert validate_domain("login.example.co.uk") == "login.example.co.uk"


def test_parse_target_reduces_host_to_registrable(resources) -> None:
    """
    A host name becomes its registrable domain, with an explanatory note.

    Args:
        resources: Stub resource manager fixture.
    Returns:
        None
    """
    udom, adom, name, suffix, note = parse_target("login.example.co.uk", resources.psl(), set())
    assert (adom, name, suffix) == ("example.co.uk", "example", "co.uk")
    assert note and "example.co.uk" in note
    assert parse_target("www.example.com", resources.psl(), set())[4] is None


def test_parse_target_unknown_tld(resources) -> None:
    """
    A TLD missing from the IANA list is rejected.

    Args:
        resources: Stub resource manager fixture.
    Returns:
        None
    """
    with pytest.raises(InputError):
        parse_target("example.notatld", resources.psl(), {"com", "it"})


def test_brand_in_labels(resources) -> None:
    """
    Brand impersonation in subdomain labels (exact, word, homograph).

    Args:
        resources: Stub resource manager fixture.
    Returns:
        None
    """
    assert brand_in_labels(["poste", "it"], "poste")
    assert brand_in_labels(["poste-login"], "poste")
    assert brand_in_labels(["p0ste"], "poste")
    assert not brand_in_labels(["mail", "www"], "poste")
    assert credential_label(["secure-login"]) and not credential_label(["www"])
