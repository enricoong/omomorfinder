"""
Data models shared by every analysis stage.

All models are slotted dataclasses (low memory, fast attribute access) and
are serialisable through `to_jsonable`, which the report exporters use.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def utcnow() -> datetime:
    """
    Current time as a timezone-aware UTC datetime.

    Returns:
        datetime: Now, in UTC.
    """
    return datetime.now(UTC)


def to_jsonable(obj: Any) -> Any:
    """
    Recursively convert dataclasses, sets and datetimes to JSON types.

    Args:
        obj (Any): Any model or container.
    Returns:
        Any: Structure made only of dict/list/str/int/float/bool/None.
    """
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_jsonable(getattr(obj, f.name)) for f in dataclasses.fields(obj)
                if not f.name.startswith("_")}
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, (set, frozenset)):
        return sorted(to_jsonable(v) for v in obj)
    if isinstance(obj, bytes):
        return None
    return obj


@dataclass(slots=True)
class DnsInfo:
    """
    DNS footprint of a domain.

    Attributes:
        status (str): "registered", "unregistered" or "unknown".
        a (list[str]): IPv4 addresses.
        aaaa (list[str]): IPv6 addresses.
        mx (list[str]): Mail exchangers (lower-case hostnames).
        ns (list[str]): Authoritative name servers.
        spf (str | None): SPF TXT record, if any.
        dmarc (str | None): DMARC TXT record, if any.
        wildcard_tld (bool): The TLD answers for any name (status is then
            uncertain and must be confirmed through RDAP/WHOIS).
    """

    status: str = "unknown"
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    spf: str | None = None
    dmarc: str | None = None
    wildcard_tld: bool = False

    @property
    def ips(self) -> list[str]:
        """
        All resolved IP addresses.

        Returns:
            list[str]: IPv4 followed by IPv6 addresses.
        """
        return [*self.a, *self.aaaa]


@dataclass(slots=True)
class RegistrationInfo:
    """
    Registration data from RDAP or WHOIS.

    Attributes:
        source (str): "rdap", "whois" or "none".
        registered (bool | None): None when unknown.
        registrar (str | None): Registrar name.
        registrant_org (str | None): Registrant organisation (if not redacted).
        registrant_name (str | None): Registrant name (if not redacted).
        registrant_country (str | None): ISO country code.
        created (datetime | None): Creation date.
        updated (datetime | None): Last update.
        expires (datetime | None): Expiry date.
        nameservers (list[str]): Delegated name servers.
        statuses (list[str]): EPP status codes.
        privacy (bool): Registrant data redacted / privacy-protected.
        server (str | None): RDAP URL or WHOIS server used.
        error (str | None): Lookup error.
    """

    source: str = "none"
    registered: bool | None = None
    registrar: str | None = None
    registrant_org: str | None = None
    registrant_name: str | None = None
    registrant_country: str | None = None
    created: datetime | None = None
    updated: datetime | None = None
    expires: datetime | None = None
    nameservers: list[str] = field(default_factory=list)
    statuses: list[str] = field(default_factory=list)
    privacy: bool = False
    server: str | None = None
    error: str | None = None

    @property
    def age_days(self) -> int | None:
        """
        Domain age in days.

        Returns:
            int | None: Days since creation, None if unknown.
        """
        if self.created is None:
            return None
        return max(0, (utcnow() - self.created).days)


@dataclass(slots=True)
class VtInfo:
    """
    VirusTotal domain report summary.

    Attributes:
        malicious (int): Engines flagging the domain as malicious.
        suspicious (int): Engines flagging it as suspicious.
        harmless (int): Engines considering it harmless.
        undetected (int): Engines with no verdict.
        reputation (int): VirusTotal community reputation.
        categories (list[str]): Categories assigned by vendors.
        last_analysis (datetime | None): Last analysis time.
        error (str | None): Lookup error / "not found".
    """

    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int = 0
    categories: list[str] = field(default_factory=list)
    last_analysis: datetime | None = None
    error: str | None = None


@dataclass(slots=True)
class AbuseInfo:
    """
    AbuseIPDB report for one IP address.

    Attributes:
        ip (str): IP address.
        score (int): Abuse confidence score (0-100).
        reports (int): Total reports.
        isp (str | None): ISP name.
        country (str | None): ISO country code.
        usage_type (str | None): e.g. "Data Center/Web Hosting/Transit".
        error (str | None): Lookup error.
    """

    ip: str
    score: int = 0
    reports: int = 0
    isp: str | None = None
    country: str | None = None
    usage_type: str | None = None
    error: str | None = None


@dataclass(slots=True)
class CtInfo:
    """
    Certificate Transparency summary for a domain.

    Attributes:
        count (int): Distinct certificates seen.
        first_seen (datetime | None): Oldest certificate notBefore.
        last_seen (datetime | None): Newest certificate notBefore.
        issuers (list[str]): Issuer organisations.
        names (list[str]): Hostnames covered by the certificates.
    """

    count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    issuers: list[str] = field(default_factory=list)
    names: list[str] = field(default_factory=list)


@dataclass(slots=True)
class UrlscanInfo:
    """
    urlscan.io search summary.

    Attributes:
        total (int): Number of public scans.
        last_scan (datetime | None): Most recent scan time.
        result_url (str | None): Link to the most recent scan.
        screenshot_url (str | None): Screenshot of the most recent scan.
        malicious (bool): urlscan verdict on any scan.
    """

    total: int = 0
    last_scan: datetime | None = None
    result_url: str | None = None
    screenshot_url: str | None = None
    malicious: bool = False


@dataclass(slots=True)
class ImageFingerprint:
    """
    Perceptual fingerprint of an image (logo, favicon, screenshot).

    Attributes:
        url (str): Image source.
        kind (str): "favicon", "logo", "og" or "screenshot".
        phash (int): 64-bit DCT perceptual hash.
        dhash (int): 64-bit difference hash.
        width (int): Original width.
        height (int): Original height.
        mmh3 (int | None): Shodan-style favicon hash (favicons only).
        sha256 (str): Hash of the raw bytes (exact-copy detection).
    """

    url: str
    kind: str
    phash: int
    dhash: int
    width: int
    height: int
    mmh3: int | None = None
    sha256: str = ""


@dataclass(slots=True)
class PageInfo:
    """
    Result of fetching and analysing a web page.

    Attributes:
        url (str): First URL tried.
        final_url (str | None): URL after redirects.
        status (int): HTTP status.
        reachable (bool): Whether any HTTP(S) response was received.
        tls_valid (bool | None): Certificate validity for HTTPS.
        title (str): Page title.
        text (str): Visible text (trimmed).
        redirect_chain (list[str]): Redirect hops.
        redirects_to_target (bool): Final URL lies on the target domain.
        server (str | None): Server header.
        has_password (bool): Contains an `<input type=password>`.
        has_login_form (bool): Contains a form that looks like a login.
        external_form_actions (list[str]): Hosts receiving form data that
            differ from the page host.
        iframes (int): Number of iframes.
        meta_refresh (bool): Uses `<meta http-equiv=refresh>`.
        js_redirect (bool): Uses JavaScript location redirects.
        obfuscation (list[str]): Obfuscation indicators found.
        brand_mentions (int): Occurrences of the brand in title/text.
        parked (bool): Looks like a parking / for-sale page.
        parking_reasons (list[str]): Why it was considered parked.
        phishing_keywords (list[str]): Phishing-related keywords found.
        image_urls (list[str]): Logo-like images to fingerprint.
        icon_urls (list[str]): Favicon URLs.
        filtered (bool): The response was a block page injected by a local
            web filter / secure proxy (real content unknown, but the
            security vendor already categorised the site as unsafe).
        error (str | None): Fetch error.
    """

    url: str = ""
    final_url: str | None = None
    status: int = 0
    reachable: bool = False
    tls_valid: bool | None = None
    title: str = ""
    text: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    redirects_to_target: bool = False
    server: str | None = None
    has_password: bool = False
    has_login_form: bool = False
    external_form_actions: list[str] = field(default_factory=list)
    iframes: int = 0
    meta_refresh: bool = False
    js_redirect: bool = False
    obfuscation: list[str] = field(default_factory=list)
    brand_mentions: int = 0
    parked: bool = False
    parking_reasons: list[str] = field(default_factory=list)
    phishing_keywords: list[str] = field(default_factory=list)
    image_urls: list[str] = field(default_factory=list)
    icon_urls: list[str] = field(default_factory=list)
    filtered: bool = False
    error: str | None = None


@dataclass(slots=True)
class VisualMatch:
    """
    Visual similarity between a candidate site and the target brand.

    Attributes:
        logo_similarity (float): Best perceptual-hash similarity (0-1).
        matched_url (str | None): Candidate image that matched best.
        favicon_match (bool): Exact favicon match (mmh3 or sha256).
        favicon_mmh3 (int | None): Candidate favicon Shodan hash.
        orb_similarity (float): ORB keypoint similarity (deep mode).
        screenshot_similarity (float): Screenshot similarity (deep mode).
        screenshot_path (str | None): Saved screenshot (deep mode).
    """

    logo_similarity: float = 0.0
    matched_url: str | None = None
    favicon_match: bool = False
    favicon_mmh3: int | None = None
    orb_similarity: float = 0.0
    screenshot_similarity: float = 0.0
    screenshot_path: str | None = None


@dataclass(slots=True)
class ScoreItem:
    """
    One explainable contribution to the relevance index.

    Attributes:
        group (str): "lexical", "registration", "infra", "reputation" or
            "content".
        label (str): Human readable reason.
        points (float): Points added (negative values reduce the score).
    """

    group: str
    label: str
    points: float


@dataclass(slots=True)
class SubdomainInfo:
    """
    A subdomain observed under a lookalike domain.

    Attributes:
        name (str): Full hostname, e.g. "login.examp1e.com".
        sources (set[str]): Where it was seen: "ct", "dns", "feed".
        ips (list[str]): Resolved addresses (empty if not resolved).
        brand (bool): A label impersonates the target brand
            (e.g. "example.it.secure-login.com").
        credential (bool): A label is credential/payment themed
            ("login", "secure", "account", "pay", ...).
    """

    name: str
    sources: set[str] = field(default_factory=set)
    ips: list[str] = field(default_factory=list)
    brand: bool = False
    credential: bool = False


@dataclass(slots=True)
class Candidate:
    """
    A lookalike domain and everything learnt about it.

    Attributes:
        domain (str): Display (Unicode) form.
        ascii (str): ASCII / punycode form used for lookups.
        name (str): Label without suffix.
        suffix (str): Public suffix.
        fuzzers (set[str]): Generation techniques / discovery sources.
        lexical (float): Lexical similarity to the target (0-1).
        homograph (bool): Visually indistinguishable from the target.
        dns (DnsInfo): DNS footprint.
        registration (RegistrationInfo | None): RDAP/WHOIS data.
        vt (VtInfo | None): VirusTotal data.
        abuse (list[AbuseInfo]): AbuseIPDB data per IP.
        ct (CtInfo | None): Certificate Transparency data.
        urlscan (UrlscanInfo | None): urlscan.io data.
        feeds (set[str]): Threat feeds listing the domain itself.
        feed_subdomains (set[str]): Feeds listing only subdomains of it.
        subdomains (list[SubdomainInfo]): Subdomains found (CT, DNS, feeds).
        wildcard_dns (bool): Every subdomain resolves ("*.domain" record).
        page (PageInfo | None): Web content analysis.
        visual (VisualMatch | None): Logo / screenshot similarity.
        text_similarity (float): TF-IDF similarity with the target site.
        semantic_similarity (float | None): Embedding similarity (deep).
        score (int): Relevance index 0-100.
        risk (str): CRITICAL / HIGH / MEDIUM / LOW / INFO.
        category (str): MALICIOUS / SUSPICIOUS / PARKED / COMPETITOR /
            DEFENSIVE / REGISTERED / AVAILABLE.
        breakdown (list[ScoreItem]): Explainable score contributions.
        notes (list[str]): Free-form analyst notes.
    """

    domain: str
    ascii: str
    name: str
    suffix: str
    fuzzers: set[str] = field(default_factory=set)
    lexical: float = 0.0
    homograph: bool = False
    dns: DnsInfo = field(default_factory=DnsInfo)
    registration: RegistrationInfo | None = None
    vt: VtInfo | None = None
    abuse: list[AbuseInfo] = field(default_factory=list)
    ct: CtInfo | None = None
    urlscan: UrlscanInfo | None = None
    feeds: set[str] = field(default_factory=set)
    feed_subdomains: set[str] = field(default_factory=set)
    subdomains: list[SubdomainInfo] = field(default_factory=list)
    wildcard_dns: bool = False
    page: PageInfo | None = None
    visual: VisualMatch | None = None
    text_similarity: float = 0.0
    semantic_similarity: float | None = None
    score: int = 0
    risk: str = "INFO"
    category: str = "AVAILABLE"
    breakdown: list[ScoreItem] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def registered(self) -> bool:
        """
        Whether the domain is known to be registered.

        Returns:
            bool: True if DNS or RDAP/WHOIS says it is registered.
        """
        if self.registration is not None and self.registration.registered is not None:
            return self.registration.registered
        return self.dns.status == "registered"

    @property
    def max_abuse(self) -> int:
        """
        Highest AbuseIPDB score among the domain's IPs.

        Returns:
            int: Score 0-100 (0 when unknown).
        """
        return max((a.score for a in self.abuse), default=0)

    def add_subdomain(self, name: str, source: str, *, brand: bool = False,
                      credential: bool = False, ips: list[str] | None = None) -> SubdomainInfo:
        """
        Record a subdomain, merging with an existing entry of the same name.

        Args:
            name (str): Full hostname.
            source (str): "ct", "dns" or "feed".
            brand (bool): Impersonates the brand.
            credential (bool): Credential/payment themed.
            ips (list[str] | None): Resolved addresses.
        Returns:
            SubdomainInfo: The (new or merged) entry.
        """
        for sub in self.subdomains:
            if sub.name == name:
                break
        else:
            sub = SubdomainInfo(name=name)
            self.subdomains.append(sub)
        sub.sources.add(source)
        sub.brand = sub.brand or brand
        sub.credential = sub.credential or credential
        if ips:
            sub.ips = sorted(set(sub.ips) | set(ips))
        return sub


@dataclass(slots=True)
class TargetProfile:
    """
    Everything learnt about the legitimate target domain.

    Attributes:
        input (str): Raw user input.
        domain (str): Registrable domain (Unicode).
        ascii (str): Registrable domain (ASCII).
        name (str): Label without suffix (brand keyword).
        suffix (str): Public suffix.
        dns (DnsInfo): DNS footprint.
        registration (RegistrationInfo | None): RDAP/WHOIS data.
        page (PageInfo | None): Homepage analysis.
        logos (list[ImageFingerprint]): Brand images fingerprints.
        favicon_mmh3 (int | None): Shodan favicon hash.
        brand_terms (list[str]): Brand words (name + title tokens).
        screenshot_path (str | None): Homepage screenshot (deep mode).
    """

    input: str
    domain: str
    ascii: str
    name: str
    suffix: str
    dns: DnsInfo = field(default_factory=DnsInfo)
    registration: RegistrationInfo | None = None
    page: PageInfo | None = None
    logos: list[ImageFingerprint] = field(default_factory=list)
    favicon_mmh3: int | None = None
    brand_terms: list[str] = field(default_factory=list)
    screenshot_path: str | None = None
