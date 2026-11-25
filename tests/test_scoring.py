"""
Tests for the relevance index and classification rules.
"""

from omomorfinder.models import Candidate, DnsInfo, PageInfo, RegistrationInfo, TargetProfile
from omomorfinder.scoring import Scorer, risk_level


def make_target() -> TargetProfile:
    """
    Target profile used by every scoring test.

    Returns:
        TargetProfile: "example.it" with private name servers.
    """
    t = TargetProfile(input="example.it", domain="example.it", ascii="example.it", name="example", suffix="it")
    t.dns = DnsInfo(status="registered", ns=["dns1.example.it"])
    t.registration = RegistrationInfo(source="whois", registered=True, registrant_org="Example S.p.A.")
    return t


def make_candidate(**kw) -> Candidate:
    """
    Registered lookalike candidate with sensible defaults.

    Args:
        **kw: Attributes to override.
    Returns:
        Candidate: Candidate "examp1e.it".
    """
    c = Candidate(domain="examp1e.it", ascii="examp1e.it", name="examp1e", suffix="it",
                  fuzzers={"homoglyph"}, lexical=1.0, homograph=True)
    c.dns = DnsInfo(status="registered", a=["203.0.113.7"], ns=["ns1.cheaphost.example"])
    for key, value in kw.items():
        setattr(c, key, value)
    return c


def test_risk_levels() -> None:
    """
    Score thresholds map to the documented risk levels.

    Returns:
        None
    """
    assert [risk_level(s) for s in (90, 65, 45, 25, 5)] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def test_available_candidate() -> None:
    """
    An unregistered domain is AVAILABLE and only scores on similarity.

    Returns:
        None
    """
    c = make_candidate()
    c.dns = DnsInfo(status="unregistered")
    Scorer(make_target()).score(c)
    assert c.category == "AVAILABLE"
    assert all(item.group == "lexical" for item in c.breakdown)


def test_feed_listing_is_malicious() -> None:
    """
    A domain listed in a phishing feed is MALICIOUS.

    Returns:
        None
    """
    c = make_candidate(feeds={"OpenPhish"})
    Scorer(make_target()).score(c)
    assert c.category == "MALICIOUS" and c.score >= 60


def test_login_with_brand_is_malicious() -> None:
    """
    A login form plus brand mentions is classified as phishing.

    Returns:
        None
    """
    page = PageInfo(reachable=True, has_password=True, has_login_form=True, brand_mentions=3)
    c = make_candidate(page=page)
    Scorer(make_target()).score(c)
    assert c.category == "MALICIOUS"


def test_redirect_to_target_is_defensive() -> None:
    """
    A lookalike redirecting to the real site is a defensive registration.

    Returns:
        None
    """
    page = PageInfo(reachable=True, redirects_to_target=True)
    c = make_candidate(page=page)
    Scorer(make_target()).score(c)
    assert c.category == "DEFENSIVE"
    assert any("defensive" in item.label for item in c.breakdown)


def test_brand_subdomain_scores_and_explains() -> None:
    """
    A brand-impersonating subdomain adds points, a reason and, with a feed
    listing of its subdomains, makes the domain MALICIOUS.

    Returns:
        None
    """
    c = make_candidate(lexical=0.6, homograph=False, feed_subdomains={"OpenPhish"})
    c.add_subdomain("example.it.secure-verify.example", "feed", brand=True, credential=True)
    Scorer(make_target()).score(c)
    labels = [item.label for item in c.breakdown]
    assert any(label.startswith("brand used in subdomain") for label in labels)
    assert any(label.startswith("credential-themed subdomain") for label in labels)
    assert c.category == "MALICIOUS"


def test_top_reasons_order() -> None:
    """
    The "why" helper returns the strongest positive reasons first.

    Returns:
        None
    """
    from omomorfinder.scoring import top_reasons

    c = make_candidate(feeds={"OpenPhish"})
    Scorer(make_target()).score(c)
    reasons = top_reasons(c, 3)
    assert reasons[0].label.startswith("listed in")
    assert [r.points for r in reasons] == sorted((r.points for r in reasons), reverse=True)


def test_same_registrant_is_defensive() -> None:
    """
    Same registrant organisation (ignoring corporate suffixes) is defensive.

    Returns:
        None
    """
    c = make_candidate(registration=RegistrationInfo(source="rdap", registered=True, registrant_org="EXAMPLE SPA"))
    Scorer(make_target()).score(c)
    assert c.category == "DEFENSIVE"
