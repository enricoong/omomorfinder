"""
Safe web content retrieval and HTML analysis.

Pages are fetched *without executing JavaScript*, with strict size and time
limits and no file downloads, so visiting a malicious lookalike is low risk.
The analysis extracts the signals that distinguish phishing kits, parked
domains, competitors and defensive registrations:

  * login / password forms and forms posting to third-party hosts,
  * JavaScript / meta-refresh redirects and obfuscated scripts,
  * brand mentions, phishing lexicon, parking-page fingerprints,
  * logo / favicon / og:image URLs for the visual comparison stage.
"""

from __future__ import annotations

import asyncio
import logging
import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from .config import TTL, Settings
from .models import PageInfo
from .net import HttpClient, HttpResult
from .nlp import phishing_keywords

log = logging.getLogger(__name__)

try:  # lxml is ~5x faster than the stdlib parser
    import lxml  # noqa: F401

    _PARSER = "lxml"
except ImportError:  # pragma: no cover
    _PARSER = "html.parser"

PARKING_NS_MARKERS: tuple[str, ...] = (
    "sedoparking", "parkingcrew", "bodis", "above.com", "dan.com", "afternic",
    "parklogic", "parkingpage", "dns-parking", "hugedomains", "smartname",
    "cashparking", "fabulous.com", "rookdns", "uniregistrymarket", "domainnamesales",
    "voodoo.com", "ztomy", "parked", "namefind", "undeveloped", "efty",
)
PARKING_TEXT_MARKERS: tuple[str, ...] = (
    "domain is for sale", "this domain may be for sale", "buy this domain",
    "domain for sale", "make an offer", "parked free", "parked domain",
    "domain parking", "this domain is parked", "related searches", "sedo.com",
    "hugedomains", "dan.com", "afternic", "inquire about this domain",
    "get this domain", "the domain owner", "questo dominio è in vendita",
    "dominio in vendita", "acquista questo dominio", "future home of something quite cool",
    "domain has been registered", "is parked", "parkingcrew", "bodis.com",
)
DEFAULT_PAGE_MARKERS: tuple[str, ...] = (
    "welcome to nginx", "apache2 default page", "apache2 ubuntu default page",
    "it works!", "index of /", "iis windows server", "default web site page",
    "plesk", "cpanel", "this site is under construction", "sito in costruzione",
    "coming soon", "account suspended", "web hosting",
)
OBFUSCATION_PATTERNS: dict[str, re.Pattern[str]] = {
    "eval-packer": re.compile(r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e", re.I),
    "eval-decode": re.compile(r"eval\s*\(\s*(atob|unescape|decodeURIComponent)\s*\(", re.I),
    "document.write-unescape": re.compile(r"document\.write\s*\(\s*(unescape|atob)\s*\(", re.I),
    "hex-blob": re.compile(r"(\\x[0-9a-f]{2}){40,}", re.I),
    "charcode-blob": re.compile(r"fromCharCode\s*\(\s*(\d+\s*,\s*){30,}", re.I),
    "base64-html": re.compile(r"data:text/html;base64,", re.I),
}
FILTER_PAGE_MARKERS: tuple[str, ...] = (
    "web filter violation", "web page blocked", "this site is blocked", "access to this site is blocked",
    "fortiguard", "blocked by your organization", "zscaler", "websense", "forcepoint",
    "url filtering", "access denied by policy", "sito bloccato", "pagina bloccata",
    "accesso a questo sito è stato bloccato", "blocked by the administrator", "sophos web appliance",
    "palo alto networks url filtering", "cisco umbrella", "this domain is blocked",
)
SOCIAL_IMAGE = re.compile(
    r"facebook|twitter|instagram|linkedin|youtube|whatsapp|tiktok|pinterest|telegram|"
    r"app-?store|google-?play|play-?store|badge|flag|spinner|loader|placeholder|pixel|spacer|payment|visa|mastercard",
    re.I,
)
JS_REDIRECT = re.compile(
    r"(window|document|top|self|parent)\.location(\.href)?\s*=|location\.(replace|assign)\s*\(", re.I
)
LOGIN_FIELD = re.compile(r"user|email|e-mail|login|account|username|codice|cliente|phone|telefono", re.I)


def host_of(url: str | None) -> str:
    """
    Lower-case hostname of a URL.

    Args:
        url (str | None): Absolute URL.
    Returns:
        str: Hostname without "www." prefix, or "" when missing.
    """
    if not url:
        return ""
    host = (urlsplit(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def count_word(text: str, word: str) -> int:
    """
    Count whole-word, case-insensitive occurrences of a word.

    "poste" matches "Poste Italiane" but not "posteo" or "riposteria".

    Args:
        text (str): Lower-case haystack.
        word (str): Word to count.
    Returns:
        int: Number of occurrences.
    """
    if not word:
        return 0
    return len(re.findall(rf"(?<![^\W_]){re.escape(word.lower())}(?![^\W_])", text))


def same_site(host: str, domain: str) -> bool:
    """
    Whether a host is a domain or one of its subdomains.

    Args:
        host (str): Hostname.
        domain (str): Registrable domain (ASCII).
    Returns:
        bool: True for "domain" or "*.domain".
    """
    return host == domain or host.endswith("." + domain)


def analyze_html(html: str, base_url: str, brand_terms: list[str], info: PageInfo) -> None:
    """
    Extract content signals from an HTML document into `info`.

    Args:
        html (str): HTML source.
        base_url (str): URL the HTML was served from (for relative links).
        brand_terms (list[str]): Brand words to count.
        info (PageInfo): Object updated in place.
    Returns:
        None
    """
    soup = BeautifulSoup(html, _PARSER)
    page_host = host_of(base_url)
    info.title = " ".join((soup.title.get_text(" ", strip=True) if soup.title else "").split())[:200]

    # --- forms ---------------------------------------------------------------
    info.has_password = soup.find("input", attrs={"type": re.compile("^password$", re.I)}) is not None
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        if action and not action.lower().startswith(("javascript:", "#")):
            target = host_of(urljoin(base_url, action))
            if target and target != page_host and target not in info.external_form_actions:
                info.external_form_actions.append(target)
        inputs = form.find_all("input")
        has_user = any(LOGIN_FIELD.search(" ".join(str(i.get(a, "")) for a in ("name", "id", "type", "placeholder")))
                       for i in inputs)
        has_pwd = any(str(i.get("type", "")).lower() == "password" for i in inputs)
        if has_pwd or (has_user and len(inputs) <= 6 and phishing_keywords(form.get_text(" ")[:500])):
            info.has_login_form = True

    # --- redirects & obfuscation --------------------------------------------
    info.iframes = len(soup.find_all("iframe"))
    info.meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile("^refresh$", re.I)}) is not None
    scripts = " ".join(s.get_text() for s in soup.find_all("script"))[:400_000]
    info.js_redirect = bool(JS_REDIRECT.search(scripts))
    info.obfuscation = [name for name, rx in OBFUSCATION_PATTERNS.items() if rx.search(scripts) or
                        (name == "base64-html" and rx.search(html[:200_000]))]

    # --- images for the visual stage ----------------------------------------
    icons: list[str] = []
    for link in soup.find_all("link", href=True):
        rel = " ".join(link.get("rel") or []).lower()
        if "icon" in rel and "mask" not in rel:
            icons.append(urljoin(base_url, link["href"]))
    icons.append(urljoin(base_url, "/favicon.ico"))
    images: list[str] = []
    for meta in soup.find_all("meta", content=True):
        prop = str(meta.get("property") or meta.get("name") or "").lower()
        if prop in ("og:image", "twitter:image", "og:logo"):
            images.append(urljoin(base_url, meta["content"]))
    for img in soup.find_all("img"):
        src = img.get("src") or img.get("data-src") or ""
        attrs = " ".join([src, str(img.get("alt", "")), " ".join(img.get("class") or []), str(img.get("id", ""))]).lower()
        parent_link = img.find_parent("a")
        home_link = parent_link is not None and str(parent_link.get("href", "")).strip() in ("/", base_url, "./", "#")
        if src and ("logo" in attrs or home_link or img.find_parent("header") is not None):
            images.append(urljoin(base_url, src))
    info.icon_urls = list(dict.fromkeys(u for u in icons if not u.lower().endswith(".svg")))[:4]
    info.image_urls = list(dict.fromkeys(
        u for u in images
        if not u.lower().split("?")[0].endswith(".svg") and not SOCIAL_IMAGE.search(u.rsplit("/", 1)[-1])
    ))[:6]

    # --- visible text ------------------------------------------------------
    for tag in soup(["script", "style", "noscript", "template", "svg"]):
        tag.decompose()
    text = " ".join(soup.get_text(" ", strip=True).split())
    info.text = text[:20_000]
    haystack = f"{info.title} {info.text}".lower()
    if any(m in haystack[:4000] for m in FILTER_PAGE_MARKERS):
        # a local proxy replaced the page: nothing in it describes the site
        info.filtered = True
        info.text, info.image_urls, info.icon_urls = "", [], []
        info.has_password = info.has_login_form = info.js_redirect = info.meta_refresh = False
        info.external_form_actions, info.obfuscation = [], []
        info.error = "intercepted by a local web filter / secure proxy"
        return
    # the page's own hostname (e.g. "postelogin.com" in a footer) is not a brand mention
    own = page_host.split(".")[0] if page_host else ""
    brand_hay = haystack.replace(page_host, " ").replace(own, " ") if own else haystack
    info.brand_mentions = count_word(brand_hay, brand_terms[0]) if brand_terms else 0
    info.brand_mentions += sum(1 for term in brand_terms[1:] if count_word(brand_hay, term))
    info.phishing_keywords = phishing_keywords(haystack)

    parking = [m for m in PARKING_TEXT_MARKERS if m in haystack]
    defaults = [m for m in DEFAULT_PAGE_MARKERS if m in haystack[:3000]]
    if parking:
        info.parked = True
        info.parking_reasons.extend(f"text: {m}" for m in parking[:3])
    if defaults and len(info.text) < 1500:
        info.parked = True
        info.parking_reasons.extend(f"default page: {m}" for m in defaults[:2])
    if len(info.text) < 40 and not info.has_password and info.iframes == 0 and not info.js_redirect:
        info.parking_reasons.append("almost empty page")


def parking_nameservers(nameservers: list[str]) -> list[str]:
    """
    Detect name servers that belong to domain-parking services.

    Args:
        nameservers (list[str]): NS hostnames.
    Returns:
        list[str]: Matching markers (empty if none).
    """
    joined = " ".join(nameservers).lower()
    return [m for m in PARKING_NS_MARKERS if m in joined]


class ContentFetcher:
    """
    Fetches homepages (HTTPS first, then HTTP) and analyses them.

    Args (constructor):
        http (HttpClient): Shared HTTP client.
        settings (Settings): Size/time limits.
    """

    def __init__(self, http: HttpClient, settings: Settings) -> None:
        """
        Store dependencies.

        Args:
            http (HttpClient): Shared HTTP client.
            settings (Settings): Scan configuration.
        Returns:
            None
        """
        self.http = http
        self.settings = settings

    async def _get(self, url: str, verify: bool) -> HttpResult:
        """
        Single page request with page-specific cache policy.

        Args:
            url (str): URL to fetch.
            verify (bool): Verify TLS certificates.
        Returns:
            HttpResult: Response (errors are cached for one hour).
        """
        return await self.http.get(
            url, verify=verify, cache_ns="page", ttl=TTL["page"], error_ttl=3600,
            max_bytes=self.settings.max_page_bytes, retries=1, retry_on_connect=False,
            headers={"Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5"},
        )

    async def fetch(self, domain: str, target_domain: str, brand_terms: list[str]) -> PageInfo:
        """
        Fetch and analyse the homepage of a domain.

        Order: HTTPS with verification -> HTTPS without verification (flags
        an invalid certificate) -> plain HTTP.

        Args:
            domain (str): ASCII domain to visit.
            target_domain (str): Target registrable domain (redirect check).
            brand_terms (list[str]): Brand words to count.
        Returns:
            PageInfo: Analysis result (reachable=False when nothing answered).
        """
        info = PageInfo(url=f"https://{domain}/")
        res = await self._get(info.url, verify=True)
        info.tls_valid = True
        if res.error and res.is_tls_error:
            res = await self._get(info.url, verify=False)
            info.tls_valid = False
        timed_out = bool(res.error and "timeout" in res.error.lower())
        if res.error and not timed_out:  # a filtered host would just time out again on :80
            http_res = await self._get(f"http://{domain}/", verify=False)
            if not http_res.error:
                res = http_res
                info.tls_valid = None
        if res.error:
            info.error = res.error.split("\n")[0][:160]
            return info

        info.reachable = True
        info.status = res.status
        info.final_url = res.final_url
        info.redirect_chain = res.history
        info.server = res.headers.get("server")
        final_host = host_of(res.final_url)
        info.redirects_to_target = same_site(final_host, target_domain)
        if final_host and not same_site(final_host, domain) and not info.redirects_to_target:
            info.parking_reasons.append(f"redirects to {final_host}")
        ctype = res.headers.get("content-type", "").lower()
        body = res.text
        if "html" in ctype or body.lstrip()[:1] == "<":
            try:  # CPU-bound parsing runs in a worker thread to keep the event loop responsive
                await asyncio.to_thread(analyze_html, body, res.final_url or info.url, brand_terms, info)
            except Exception as exc:  # malformed HTML must never break the scan
                log.debug("html analysis failed for %s: %s", domain, exc)
        return info
