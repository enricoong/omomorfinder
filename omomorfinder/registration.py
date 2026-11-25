"""
Domain registration lookups: RDAP first, WHOIS (port 43) as fallback.

RDAP (RFC 9082/9083) is mandatory for every ICANN gTLD and returns
structured JSON; the right server is found through the IANA bootstrap
file. Many ccTLDs still only offer WHOIS: queries go through the polite
`whois.WhoisClient` (adaptive pacing, budget, reachability probe); this
module adds thin-registry referral and section-aware parsing (e.g. ".it").
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from typing import Any

from .cache import Cache
from .config import TTL
from .models import RegistrationInfo
from .net import HttpClient
from .resources import ResourceManager
from .whois import WhoisClient

log = logging.getLogger(__name__)

REDACTION_MARKERS = (
    "redacted", "privacy", "data protected", "not disclosed", "withheld",
    "gdpr", "statutory masking", "whoisguard", "domains by proxy", "proxy",
    "non-public", "not available", "hidden", "private",
)

WHOIS_NOT_FOUND = re.compile(
    r"no match|not found|no entries found|no data found|status:\s*(available|free)"
    r"|is available for|domain not registered|object does not exist|no object found"
    r"|nothing found|not registered|is free|no such domain|does not exist",
    re.I,
)
WHOIS_RATE_LIMITED = re.compile(r"limit exceeded|rate limit|quota exceeded|too many|try again later", re.I)

_DATE_FORMATS = (
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%d.%m.%Y", "%Y.%m.%d",
    "%d/%m/%Y", "%Y/%m/%d", "%d-%m-%Y", "%Y%m%d", "%b %d %Y", "%d %b %Y",
    "%a %b %d %H:%M:%S %Z %Y", "%Y-%m-%dT%H:%M:%S", "%d-%b-%Y %H:%M:%S",
    "%Y/%m/%d %H:%M:%S", "%d.%m.%Y %H:%M:%S",
)

# WHOIS line keys (lower-case, normalised) mapped to RegistrationInfo fields.
_WHOIS_KEYS: dict[str, str] = {
    "creation date": "created", "created": "created", "created on": "created",
    "registered": "created", "registered on": "created", "registration date": "created",
    "registration time": "created", "domain registration date": "created",
    "commencement date": "created", "domain record activated": "created",
    "registry expiry date": "expires", "registrar registration expiration date": "expires",
    "expiration date": "expires", "expiry date": "expires", "expire date": "expires",
    "expires": "expires", "expires on": "expires", "paid-till": "expires",
    "renewal date": "expires", "updated date": "updated", "last updated": "updated",
    "last update": "updated", "last modified": "updated", "changed": "updated",
    "registrar": "registrar", "registrar name": "registrar", "sponsoring registrar": "registrar",
    "registrant organization": "registrant_org", "registrant organisation": "registrant_org",
    "registrant org": "registrant_org", "org": "registrant_org",
    "registrant name": "registrant_name", "registrant": "registrant_name",
    "registrant country": "registrant_country", "registrant country code": "registrant_country",
    "name server": "ns", "nameserver": "ns", "nserver": "ns", "name servers": "ns",
    "domain status": "status", "status": "status",
}


def parse_date(value: Any) -> datetime | None:
    """
    Parse the many date formats found in RDAP/WHOIS output.

    Args:
        value (Any): Date string (or None).
    Returns:
        datetime | None: Timezone-aware UTC datetime, None if unparsable.
    """
    if not value or not isinstance(value, str):
        return None
    s = value.strip().replace(" UTC", "").replace("(UTC)", "").strip()
    candidates = [s, s.replace("Z", "+00:00"), s.split(" (")[0], s.split()[0] if s.split() else s]
    for cand in candidates:
        try:
            dt = datetime.fromisoformat(cand)
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            pass
        for fmt in _DATE_FORMATS:
            try:
                return datetime.strptime(cand, fmt).replace(tzinfo=UTC)
            except ValueError:
                continue
    return None


def clean_contact(value: str | None) -> tuple[str | None, bool]:
    """
    Normalise a contact field and detect privacy redaction.

    Args:
        value (str | None): Raw value.
    Returns:
        tuple[str | None, bool]: (clean value or None, True if redacted).
    """
    if not value:
        return None, False
    v = " ".join(value.split())
    if any(m in v.lower() for m in REDACTION_MARKERS):
        return None, True
    return v, False


def _vcard(entity: dict[str, Any]) -> dict[str, Any]:
    """
    Extract fn/org/country from an RDAP entity jCard.

    Args:
        entity (dict[str, Any]): RDAP entity object.
    Returns:
        dict[str, Any]: Keys "fn", "org", "cc" when present.
    """
    out: dict[str, Any] = {}
    card = entity.get("vcardArray")
    if not (isinstance(card, list) and len(card) == 2 and isinstance(card[1], list)):
        return out
    for prop in card[1]:
        if not isinstance(prop, list) or len(prop) < 4:
            continue
        name, params, _, val = prop[0], prop[1] or {}, prop[2], prop[3]
        if name == "fn" and isinstance(val, str):
            out["fn"] = val
        elif name == "org":
            out["org"] = val if isinstance(val, str) else " ".join(map(str, val))
        elif name == "adr":
            cc = params.get("cc") if isinstance(params, dict) else None
            if not cc and isinstance(val, list) and val and isinstance(val[-1], str):
                cc = val[-1]
            if cc:
                out["cc"] = cc
    return out


def _walk_entities(entities: list[Any]) -> list[dict[str, Any]]:
    """
    Flatten nested RDAP entities.

    Args:
        entities (list[Any]): Top-level "entities" array.
    Returns:
        list[dict[str, Any]]: Every entity, depth first.
    """
    out: list[dict[str, Any]] = []
    stack = list(entities or [])
    while stack:
        ent = stack.pop()
        if isinstance(ent, dict):
            out.append(ent)
            stack.extend(ent.get("entities") or [])
    return out


def parse_rdap(data: dict[str, Any], server: str) -> RegistrationInfo:
    """
    Convert an RDAP domain object into a RegistrationInfo.

    Args:
        data (dict[str, Any]): Decoded RDAP JSON.
        server (str): URL queried (for provenance).
    Returns:
        RegistrationInfo: Parsed record with registered=True.
    """
    info = RegistrationInfo(source="rdap", registered=True, server=server)
    for ev in data.get("events") or []:
        action = str(ev.get("eventAction", "")).lower()
        date = parse_date(ev.get("eventDate"))
        if action == "registration":
            info.created = date
        elif action == "expiration":
            info.expires = date
        elif action in ("last changed", "last update of rdap database") and info.updated is None:
            info.updated = date if action == "last changed" else None
    info.statuses = [str(s) for s in data.get("status") or []]
    info.nameservers = sorted({
        str(ns.get("ldhName", "")).lower().rstrip(".")
        for ns in data.get("nameservers") or [] if ns.get("ldhName")
    })
    for ent in _walk_entities(data.get("entities") or []):
        roles = {str(r).lower() for r in ent.get("roles") or []}
        card = _vcard(ent)
        if "registrar" in roles and not info.registrar:
            info.registrar = card.get("fn") or card.get("org")
        if "registrant" in roles:
            org, red1 = clean_contact(card.get("org"))
            name, red2 = clean_contact(card.get("fn"))
            info.registrant_org = info.registrant_org or org
            info.registrant_name = info.registrant_name or name
            info.registrant_country = info.registrant_country or card.get("cc")
            info.privacy = info.privacy or red1 or red2
    for remark in data.get("remarks") or []:
        title = str(remark.get("title", "")).lower()
        if "redact" in title or "privacy" in title:
            info.privacy = True
    return info


def parse_whois(text: str, domain: str) -> RegistrationInfo:
    """
    Parse a raw WHOIS answer (generic key/value and sectioned formats).

    Args:
        text (str): Raw WHOIS response.
        domain (str): Queried domain (sanity check).
    Returns:
        RegistrationInfo: Parsed record; registered=False when the server
        reports the domain as free, None when rate-limited/unclear.
    """
    info = RegistrationInfo(source="whois")
    if WHOIS_RATE_LIMITED.search(text) and len(text) < 600:
        info.error = "rate limited by WHOIS server"
        return info
    body = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith(("%", "#", ">>>")))
    section = ""
    nameservers: set[str] = set()
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith(("%", "#")):
            continue
        indented = raw[:1] in (" ", "\t")
        line = raw.strip()
        if ":" not in line or line.endswith(":") and not indented:
            if not indented:
                section = line.rstrip(":").strip().lower()
                continue
            if section.startswith(("nameserver", "name server", "dns")):
                nameservers.add(line.split()[0].lower().rstrip("."))
            continue
        key, _, value = line.partition(":")
        key = " ".join(key.lower().split())
        value = value.strip()
        if not value:
            if not indented:
                section = key
            continue
        if indented and section:
            if section.startswith("registrant") and key in ("organization", "organisation", "name", "country"):
                key = {"organization": "registrant organization", "organisation": "registrant organization",
                       "name": "registrant name", "country": "registrant country"}[key]
            elif section.startswith("registrar") and key in ("organization", "name"):
                key = "registrar" if key == "organization" or not info.registrar else "_skip"
            elif section.startswith(("nameserver", "name server", "dns")):
                nameservers.add(value.split()[0].lower().rstrip("."))
                continue
            elif section.startswith(("admin", "tech", "billing")):
                continue
        target = _WHOIS_KEYS.get(key)
        if target is None:
            continue
        if target in ("created", "expires", "updated"):
            if getattr(info, target) is None:
                setattr(info, target, parse_date(value))
        elif target == "ns":
            nameservers.add(value.split()[0].lower().rstrip("."))
        elif target == "status":
            info.statuses.append(value.split()[0])
        elif target == "registrar":
            info.registrar = info.registrar or value
        elif target in ("registrant_org", "registrant_name"):
            clean, redacted = clean_contact(value)
            info.privacy = info.privacy or redacted
            if clean and getattr(info, target) is None:
                setattr(info, target, clean)
        elif target == "registrant_country":
            info.registrant_country = info.registrant_country or value[:40]
    info.nameservers = sorted(n for n in nameservers if "." in n)
    free_status = any(st.lower() in ("available", "free", "no-object") for st in info.statuses)
    has_data = bool(info.created or info.registrar or info.nameservers) or bool(info.statuses and not free_status)
    if free_status or (not has_data and WHOIS_NOT_FOUND.search(body)):
        info.registered = False
    else:
        info.registered = True if has_data else None
    return info


class RegistrationLookup:
    """
    Registration data for a domain: RDAP first, polite WHOIS as fallback.

    Args (constructor):
        http (HttpClient): Shared HTTP client (RDAP and IANA pages).
        cache (Cache): Shared cache.
        resources (ResourceManager): Provides the RDAP bootstrap map.
        whois_budget (int): Max uncached WHOIS queries per server per scan.
    """

    def __init__(self, http: HttpClient, cache: Cache, resources: ResourceManager,
                 whois_budget: int = 40) -> None:
        """
        Store dependencies and build the WHOIS client.

        Args:
            http (HttpClient): Shared HTTP client.
            cache (Cache): Shared cache.
            resources (ResourceManager): Dataset manager.
            whois_budget (int): WHOIS query budget per server.
        Returns:
            None
        """
        self.http = http
        self.resources = resources
        self.whois_client = WhoisClient(http, cache, whois_budget)

    async def lookup(self, domain: str, suffix: str) -> RegistrationInfo:
        """
        Look up a domain via RDAP, falling back to WHOIS.

        Args:
            domain (str): ASCII domain.
            suffix (str): Its public suffix.
        Returns:
            RegistrationInfo: Best available record (never raises).
        """
        tld = suffix.rsplit(".", 1)[-1]
        base = self.resources.rdap_servers().get(tld)
        rdap_info: RegistrationInfo | None = None
        if base:
            rdap_info = await self.rdap(domain, base)
            if rdap_info.registered is not None:
                return rdap_info
        whois_info = await self.whois(domain, tld)
        if whois_info.registered is not None or rdap_info is None:
            return whois_info
        return rdap_info

    async def rdap(self, domain: str, base: str) -> RegistrationInfo:
        """
        Query the registry RDAP server (and the registrar's, if linked).

        Args:
            domain (str): ASCII domain.
            base (str): RDAP base URL ending with "/".
        Returns:
            RegistrationInfo: Parsed record; registered=False on HTTP 404.
        """
        url = f"{base}domain/{domain}"
        res = await self.http.get(
            url, headers={"Accept": "application/rdap+json"}, cache_ns="rdap",
            ttl=TTL["rdap"], max_bytes=2_000_000, retries=2,
        )
        if res.status == 404:
            return RegistrationInfo(source="rdap", registered=False, server=url)
        data = res.json() if res.ok else None
        if not isinstance(data, dict):
            return RegistrationInfo(source="rdap", server=url, error=res.error or f"HTTP {res.status}")
        info = parse_rdap(data, url)
        if not info.registrant_org:
            related = next(
                (lk.get("href") for lk in data.get("links") or []
                 if lk.get("rel") == "related" and "rdap" in str(lk.get("type", "rdap")) and lk.get("href")),
                None,
            )
            if related and related.startswith("https://") and related != url:
                res2 = await self.http.get(
                    related, headers={"Accept": "application/rdap+json"}, cache_ns="rdap",
                    ttl=TTL["rdap"], max_bytes=2_000_000, retries=1,
                )
                data2 = res2.json() if res2.ok else None
                if isinstance(data2, dict):
                    extra = parse_rdap(data2, related)
                    info.registrant_org = extra.registrant_org
                    info.registrant_name = info.registrant_name or extra.registrant_name
                    info.registrant_country = info.registrant_country or extra.registrant_country
                    info.privacy = info.privacy or extra.privacy
                    info.created = info.created or extra.created
        return info

    async def whois(self, domain: str, tld: str) -> RegistrationInfo:
        """
        WHOIS lookup with thin-registry referral support.

        Args:
            domain (str): ASCII domain.
            tld (str): Top-level domain.
        Returns:
            RegistrationInfo: Parsed record (error set when unavailable).
        """
        server = await self.whois_client.server_for(tld)
        if not server:
            return RegistrationInfo(source="whois", error="no WHOIS service for this TLD")
        query = f"-T dn,ace {domain}" if server == "whois.denic.de" else domain
        text = await self.whois_client.query(server, query)
        if text is None:
            return RegistrationInfo(source="whois", server=server, error="WHOIS not available")
        info = parse_whois(text, domain)
        info.server = server
        m = re.search(r"Registrar WHOIS Server:\s*(\S+)", text, re.I)
        if info.registered and m and not info.registrant_org:
            referral = m.group(1).strip().lower().removeprefix("whois://").rstrip("/")
            if referral and referral != server and "." in referral:
                text2 = await self.whois_client.query(referral, domain)
                if text2:
                    extra = parse_whois(text2, domain)
                    info.registrant_org = extra.registrant_org
                    info.registrant_name = info.registrant_name or extra.registrant_name
                    info.registrant_country = info.registrant_country or extra.registrant_country
                    info.privacy = info.privacy or extra.privacy
        return info

    def status(self) -> str:
        """
        Service status line (delegates to the WHOIS client).

        Returns:
            str: Status text for the UI.
        """
        return self.whois_client.status()
