"""
Explainable relevance index (0-100) and classification.

Each signal adds (or removes) a fixed number of points and is recorded as a
`ScoreItem` (groups: lexical, registration, infra, reputation, content,
subdomain), so every score can be justified line by line in the output.
Classification is rule based and ordered: availability first, then
defensive registrations (to avoid flagging the brand's own domains), then
malicious evidence, parking, competitors and generic suspicion.
"""

from __future__ import annotations

import re
from datetime import timedelta

from .content import host_of, parking_nameservers, same_site
from .models import Candidate, ScoreItem, TargetProfile, utcnow

RISK_LEVELS: tuple[tuple[int, str], ...] = ((80, "CRITICAL"), (60, "HIGH"), (40, "MEDIUM"), (20, "LOW"), (0, "INFO"))

CATEGORIES: tuple[str, ...] = (
    "MALICIOUS", "SUSPICIOUS", "PARKED", "COMPETITOR", "REGISTERED", "DEFENSIVE", "UNVERIFIED", "AVAILABLE",
)

# Registrars specialised in corporate brand protection: a lookalike held by
# one of them, like the target, is almost always a defensive registration.
BRAND_PROTECTION_REGISTRARS: tuple[str, ...] = (
    "markmonitor", "csc corporate", "corporation service company", "com laude",
    "safenames", "nameshield", "ebrand", "brandsight", "comlaude", "gandi corporate",
    "fairwinds", "authentic web", "lexsynergy", "101domain grs", "akamai",
)
# Shared DNS providers: equal NS sets on these prove nothing.
SHARED_DNS: tuple[str, ...] = (
    "cloudflare", "awsdns", "domaincontrol", "azure-dns", "googledomains", "registrar-servers",
    "nsone", "ultradns", "dnsmadeeasy", "akam", "hostinger", "aruba", "register.it",
    "ovh", "gandi", "name.com", "namecheap", "wixdns", "squarespace", "dynect",
)
_CORP_SUFFIX = re.compile(r"\b(s\.?p\.?a|s\.?r\.?l|inc|llc|ltd|gmbh|corp(oration)?|co|company|limited|plc|ag|sa|bv|nv)\b\.?", re.I)


def risk_level(score: int) -> str:
    """
    Map a score to a risk level.

    Args:
        score (int): Relevance index 0-100.
    Returns:
        str: CRITICAL, HIGH, MEDIUM, LOW or INFO.
    """
    for threshold, name in RISK_LEVELS:
        if score >= threshold:
            return name
    return "INFO"


def top_reasons(c: Candidate, limit: int = 3) -> list[ScoreItem]:
    """
    The strongest reasons behind a score, for the "why" column.

    Positive contributions come first (largest first); a defensive
    reduction, when present, is always included because it explains a low
    score on an otherwise suspicious-looking domain.

    Args:
        c (Candidate): Scored candidate.
        limit (int): Maximum number of reasons.
    Returns:
        list[ScoreItem]: Selected contributions.
    """
    positive = sorted((i for i in c.breakdown if i.points > 0), key=lambda i: -i.points)
    negative = [i for i in c.breakdown if i.points < 0]
    picked = positive[: limit - (1 if negative else 0)] + negative[:1]
    return picked[:limit]


def normalise_org(org: str | None) -> str:
    """
    Normalise an organisation name for comparison.

    Args:
        org (str | None): Raw organisation name.
    Returns:
        str: Lower-case name without corporate suffixes and punctuation.
    """
    if not org:
        return ""
    cleaned = _CORP_SUFFIX.sub(" ", org.lower())
    return " ".join(re.sub(r"[^\w\s]", " ", cleaned).split())


class Scorer:
    """
    Computes the relevance index and category of candidates.

    Args (constructor):
        target (TargetProfile): Analysed target (used for defensive checks).
    """

    def __init__(self, target: TargetProfile) -> None:
        """
        Pre-compute target attributes used in comparisons.

        Args:
            target (TargetProfile): Analysed target.
        Returns:
            None
        """
        self.target = target
        reg = target.registration
        self.target_org = normalise_org(reg.registrant_org if reg else None)
        self.target_registrar = (reg.registrar or "").lower() if reg else ""
        self.target_ns = set(target.dns.ns) | set(reg.nameservers if reg else [])

    def defensive_reasons(self, c: Candidate) -> list[str]:
        """
        Evidence that a candidate belongs to the target company itself.

        Args:
            c (Candidate): Enriched candidate.
        Returns:
            list[str]: Human readable reasons (empty when none).
        """
        reasons: list[str] = []
        t = self.target
        if c.page and c.page.redirects_to_target:
            reasons.append(f"redirects to {t.domain}")
        reg = c.registration
        if reg and self.target_org and normalise_org(reg.registrant_org) == self.target_org:
            reasons.append(f"same registrant ({reg.registrant_org})")
        ns = set(c.dns.ns) | set(reg.nameservers if reg else [])
        if ns and any(n.endswith("." + t.ascii) for n in ns):
            reasons.append("name servers hosted on the target domain")
        elif ns and ns == self.target_ns and not any(s in " ".join(ns) for s in SHARED_DNS):
            reasons.append("identical private name servers")
        if c.dns.mx and all(m.endswith("." + t.ascii) or m == t.ascii for m in c.dns.mx):
            reasons.append("mail handled by the target domain")
        registrar = (reg.registrar or "").lower() if reg else ""
        if registrar and registrar == self.target_registrar and \
                any(b in registrar for b in BRAND_PROTECTION_REGISTRARS):
            reasons.append(f"same brand-protection registrar ({reg.registrar})")
        return reasons

    def score(self, c: Candidate) -> None:
        """
        Compute score, risk and category of a candidate (in place).

        Args:
            c (Candidate): Candidate with all available enrichment.
        Returns:
            None
        """
        items: list[ScoreItem] = []

        def add(group: str, label: str, points: float) -> None:
            """
            Record one contribution.

            Args:
                group (str): Signal group.
                label (str): Reason shown to the analyst.
                points (float): Points (may be negative).
            Returns:
                None
            """
            items.append(ScoreItem(group, label, points))

        # ---- lexical ------------------------------------------------------
        lex_pts = 25 * max(0.0, (c.lexical - 0.5) / 0.5)
        if lex_pts:
            add("lexical", f"name similarity {c.lexical:.0%}", round(lex_pts, 1))
        if c.homograph:
            add("lexical", "visually indistinguishable from the target", 8)

        registered = c.registered
        page, reg, vis = c.page, c.registration, c.visual
        if registered:
            add("registration", "domain is registered", 10)
            age = reg.age_days if reg else None
            if age is not None:
                if age < 30:
                    add("registration", f"registered {age} days ago", 15)
                elif age < 180:
                    add("registration", f"registered {age} days ago", 10)
                elif age < 365:
                    add("registration", f"registered {age} days ago", 5)
            if reg and reg.privacy:
                add("registration", "registrant hidden (privacy/redaction)", 3)
            if c.ct and c.ct.count:
                recent = c.ct.last_seen and c.ct.last_seen > utcnow() - timedelta(days=30)
                add("registration", "TLS certificate issued in the last 30 days" if recent
                    else f"{c.ct.count} TLS certificate(s) in CT logs", 6 if recent else 3)

            # ---- infrastructure ------------------------------------------
            if c.dns.mx:
                add("infra", "mail server configured (spoofing / BEC capable)", 10)
                if page is not None and not page.reachable:
                    add("infra", "mail-only domain (no website)", 4)
            if c.max_abuse >= 75:
                add("infra", f"hosting IP abuse score {c.max_abuse}", 12)
            elif c.max_abuse >= 25:
                add("infra", f"hosting IP abuse score {c.max_abuse}", 6)
            elif c.max_abuse > 0:
                add("infra", f"hosting IP abuse score {c.max_abuse}", 2)

            # ---- reputation ----------------------------------------------
            if c.feeds:
                add("reputation", "listed in " + ", ".join(sorted(c.feeds)), 35)
            elif c.feed_subdomains:
                add("reputation", "subdomains listed in " + ", ".join(sorted(c.feed_subdomains))
                    + " (possibly an abused shared platform)", 12)
            if c.vt and not c.vt.error:
                if c.vt.malicious >= 3:
                    add("reputation", f"VirusTotal: {c.vt.malicious} engines malicious", 30)
                elif c.vt.malicious >= 1:
                    add("reputation", f"VirusTotal: {c.vt.malicious} engine(s) malicious", 18)
                if c.vt.suspicious:
                    add("reputation", f"VirusTotal: {c.vt.suspicious} suspicious", 6)
            if c.urlscan and c.urlscan.malicious:
                add("reputation", "urlscan.io verdict: malicious", 20)

            # ---- content ---------------------------------------------------
            if page and page.filtered:
                add("reputation", "blocked by the local web filter (vendor flags it as unsafe)", 6)
            elif page and page.reachable:
                add("content", "website online", 3)
                if page.brand_mentions:
                    add("content", f"brand mentioned {page.brand_mentions}x", 8)
                if page.has_password:
                    add("content", "password field on page", 12)
                elif page.has_login_form:
                    add("content", "login form on page", 7)
                if page.external_form_actions:
                    add("content", "form posts to " + ", ".join(page.external_form_actions[:2]), 6)
                if len(page.phishing_keywords) >= 2:
                    add("content", "phishing lexicon: " + ", ".join(page.phishing_keywords[:4]), 5)
                if page.obfuscation:
                    add("content", "obfuscated JS: " + ", ".join(page.obfuscation[:3]), 5)
                if page.tls_valid is False:
                    add("content", "invalid TLS certificate", 2)
                if page.parked:
                    add("content", "parked / for sale / default page", -10)
            if parking_nameservers(c.dns.ns):
                add("infra", "parking name servers", -8)
            if vis:
                hotlinked = bool(vis.matched_url) and same_site(host_of(vis.matched_url), self.target.ascii)
                origin = " (loaded from target infrastructure: group site or hotlinking kit)" if hotlinked else ""
                if vis.favicon_match:
                    add("content", "exact copy of the target brand image" + origin, 18)
                elif vis.logo_similarity >= 0.92:
                    add("content", f"logo match {vis.logo_similarity:.0%}" + origin, 18)
                elif vis.logo_similarity >= 0.85:
                    add("content", f"logo similar {vis.logo_similarity:.0%}" + origin, 10)
                elif vis.orb_similarity >= 0.35:
                    add("content", f"logo keypoints match {vis.orb_similarity:.0%}", 8)
                if vis.screenshot_similarity >= 0.85:
                    add("content", f"page looks like the target ({vis.screenshot_similarity:.0%})", 12)
            text_sim = max(c.text_similarity, c.semantic_similarity or 0.0)
            if text_sim >= 0.6:
                add("content", f"content similarity {text_sim:.0%}", 12)
            elif text_sim >= 0.35:
                add("content", f"content similarity {text_sim:.0%}", 6)

            # ---- subdomains ----------------------------------------------
            brand_subs = [sd.name for sd in c.subdomains if sd.brand]
            cred_subs = [sd.name for sd in c.subdomains if sd.credential and (sd.ips or sd.sources - {"dns"})]
            if brand_subs:
                more = f" (+{len(brand_subs) - 1} more)" if len(brand_subs) > 1 else ""
                add("subdomain", f"brand used in subdomain {brand_subs[0]}{more}", 20)
            if cred_subs:
                more = f" (+{len(cred_subs) - 1} more)" if len(cred_subs) > 1 else ""
                add("subdomain", f"credential-themed subdomain {cred_subs[0]}{more}", 6)
            if c.wildcard_dns:
                add("subdomain", "wildcard DNS: any subdomain resolves (used by phishing kits)", 3)

        defensive = self.defensive_reasons(c) if registered else []
        total = sum(i.points for i in items)
        if defensive:
            penalty = -round(total * 0.75, 1)
            add("registration", "likely defensive: " + "; ".join(defensive), penalty)
            total += penalty
        c.breakdown = items
        c.score = int(max(0, min(100, round(total))))
        c.risk = risk_level(c.score)
        c.category = self.classify(c, defensive)

    @staticmethod
    def classify(c: Candidate, defensive: list[str]) -> str:
        """
        Assign the category of a scored candidate.

        Args:
            c (Candidate): Scored candidate.
            defensive (list[str]): Defensive-registration evidence.
        Returns:
            str: One of `CATEGORIES`.
        """
        if not c.registered:
            if c.dns.status == "unknown" and (c.registration is None or c.registration.registered is None):
                return "UNVERIFIED"
            return "AVAILABLE"
        if defensive:
            return "DEFENSIVE"
        page, vis = c.page, c.visual
        login = bool(page and (page.has_password or page.has_login_form))
        brand = bool(page and page.brand_mentions)
        logo = bool(vis and (vis.favicon_match or vis.logo_similarity >= 0.9))
        text_sim = max(c.text_similarity, c.semantic_similarity or 0.0)
        brand_sub = any(sd.brand for sd in c.subdomains)
        if c.feeds or (c.vt and c.vt.malicious >= 2) or (c.urlscan and c.urlscan.malicious) \
                or (login and (brand or logo or text_sim >= 0.6 or brand_sub)) \
                or (brand_sub and c.feed_subdomains):
            return "MALICIOUS"
        if not login and ((page and page.parked) or parking_nameservers(c.dns.ns)):
            return "PARKED"
        if page and page.reachable and not brand and not login and not logo and \
                (c.text_similarity >= 0.25 or (c.semantic_similarity or 0) >= 0.55):
            return "COMPETITOR"
        if c.score >= 45:
            return "SUSPICIOUS"
        return "REGISTERED"
