"""
Threat-intelligence enrichment: VirusTotal, AbuseIPDB, Certificate
Transparency (crt.sh) and urlscan.io.

Every client degrades gracefully: without an API key it is simply disabled,
and when a quota is exhausted it switches itself off for the rest of the scan
instead of hammering the service. All answers are cached.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from .config import TTL, Settings
from .models import AbuseInfo, CtInfo, UrlscanInfo, VtInfo
from .net import HttpClient
from .registration import parse_date

log = logging.getLogger(__name__)


class VirusTotalClient:
    """
    VirusTotal API v3 client (domain reports).

    Args (constructor):
        http (HttpClient): Shared HTTP client.
        settings (Settings): Provides the API key and quota.
    """

    BASE = "https://www.virustotal.com/api/v3"

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
        self.key = settings.vt_api_key
        self.disabled_reason: str | None = None if self.key else "no API key (VT_API_KEY)"
        self.used = 0

    @property
    def enabled(self) -> bool:
        """
        Whether the client can still be used.

        Returns:
            bool: False without key or after quota exhaustion.
        """
        return self.disabled_reason is None

    async def domain(self, domain: str) -> VtInfo | None:
        """
        Fetch the VirusTotal report of a domain.

        Args:
            domain (str): ASCII domain.
        Returns:
            VtInfo | None: Report summary, None when the client is disabled.
        """
        if not self.enabled:
            return None
        res = await self.http.get(
            f"{self.BASE}/domains/{domain}", headers={"x-apikey": self.key or ""},
            cache_ns="vt", ttl=TTL["vt"], retries=1, max_bytes=3_000_000,
        )
        if not res.from_cache:
            self.used += 1
        if res.status == 404:
            return VtInfo(error="not found")
        if res.status == 401:
            self.disabled_reason = "invalid API key"
            return None
        if res.status == 429:
            body = res.text.lower()
            self.disabled_reason = "daily quota exhausted" if "quota" in body else "rate limited"
            return None
        data = res.json() if res.ok else None
        if not isinstance(data, dict):
            return VtInfo(error=res.error or f"HTTP {res.status}")
        attrs: dict[str, Any] = (data.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        ts = attrs.get("last_analysis_date")
        return VtInfo(
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            harmless=int(stats.get("harmless", 0)),
            undetected=int(stats.get("undetected", 0)),
            reputation=int(attrs.get("reputation", 0) or 0),
            categories=sorted({str(v) for v in (attrs.get("categories") or {}).values()})[:6],
            last_analysis=datetime.fromtimestamp(ts, timezone.utc) if isinstance(ts, (int, float)) else None,
        )


class AbuseIpdbClient:
    """
    AbuseIPDB API v2 client (IP reputation).

    Args (constructor):
        http (HttpClient): Shared HTTP client.
        settings (Settings): Provides the API key.
    """

    URL = "https://api.abuseipdb.com/api/v2/check"

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
        self.key = settings.abuseipdb_api_key
        self.disabled_reason: str | None = None if self.key else "no API key (ABUSEIPDB_API_KEY)"
        self.used = 0

    @property
    def enabled(self) -> bool:
        """
        Whether the client can still be used.

        Returns:
            bool: False without key or after quota exhaustion.
        """
        return self.disabled_reason is None

    async def check(self, ip: str) -> AbuseInfo | None:
        """
        Fetch the abuse report of an IP address (last 90 days).

        Args:
            ip (str): IPv4/IPv6 address.
        Returns:
            AbuseInfo | None: Report, None when the client is disabled.
        """
        if not self.enabled:
            return None
        res = await self.http.get(
            self.URL, params={"ipAddress": ip, "maxAgeInDays": "90"},
            headers={"Key": self.key or "", "Accept": "application/json"},
            cache_ns="abuseipdb", ttl=TTL["abuseipdb"], retries=1,
        )
        if not res.from_cache:
            self.used += 1
        if res.status in (401, 403):
            self.disabled_reason = "invalid API key"
            return None
        if res.status == 429:
            self.disabled_reason = "daily quota exhausted"
            return None
        data = (res.json() or {}).get("data") if res.ok else None
        if not isinstance(data, dict):
            return AbuseInfo(ip=ip, error=res.error or f"HTTP {res.status}")
        return AbuseInfo(
            ip=ip,
            score=int(data.get("abuseConfidenceScore") or 0),
            reports=int(data.get("totalReports") or 0),
            isp=data.get("isp"),
            country=data.get("countryCode"),
            usage_type=data.get("usageType"),
        )


class CertTransparency:
    """
    Certificate Transparency search through crt.sh.

    A single keyword query ("%brand%") discovers lookalikes that no
    permutation algorithm would guess, and reveals freshly issued
    certificates (a strong "phishing kit about to go live" signal).

    Args (constructor):
        http (HttpClient): Shared HTTP client.
    """

    URL = "https://crt.sh/"

    def __init__(self, http: HttpClient) -> None:
        """
        Store dependencies.

        Args:
            http (HttpClient): Shared HTTP client.
        Returns:
            None
        """
        self.http = http
        self.error: str | None = None
        self.failures = 0

    @property
    def available(self) -> bool:
        """
        Circuit breaker: crt.sh is a free, frequently overloaded service;
        after two consecutive failures it is left alone for the scan.

        Returns:
            bool: False once the breaker has tripped.
        """
        return self.failures < 2

    async def _query(self, q: str, timeout: float = 90.0, retries: int = 2) -> list[dict[str, Any]]:
        """
        Run a crt.sh JSON query.

        Args:
            q (str): crt.sh identity query (supports % wildcards).
            timeout (float): Read timeout (big keyword queries are slow).
            retries (int): Retries on 5xx / timeouts.
        Returns:
            list[dict[str, Any]]: Raw certificate entries (empty on error).
        """
        if not self.available:
            return []
        res = await self.http.get(
            self.URL, params={"q": q, "output": "json", "exclude": "expired"},
            cache_ns="crtsh", ttl=TTL["crtsh"], retries=retries, max_bytes=60_000_000, timeout=timeout,
        )
        data = res.json() if res.ok else None
        if not isinstance(data, list):
            self.error = (res.error or f"HTTP {res.status}").split("\n")[0]
            self.failures += 1
            return []
        self.failures = 0
        return [d for d in data if isinstance(d, dict)]

    @staticmethod
    def aggregate(entries: list[dict[str, Any]], registrable: Any) -> dict[str, CtInfo]:
        """
        Group certificate entries by registrable domain.

        Args:
            entries (list[dict[str, Any]]): crt.sh entries.
            registrable (Callable[[str], str | None]): Host -> eTLD+1 function.
        Returns:
            dict[str, CtInfo]: Registrable domain -> aggregated CT info.
        """
        out: dict[str, CtInfo] = {}
        seen: dict[str, set[int]] = {}
        for e in entries:
            names = {n.strip().lower().lstrip("*.") for n in str(e.get("name_value", "")).split("\n")}
            names.add(str(e.get("common_name", "")).strip().lower().lstrip("*."))
            nb = parse_date(e.get("not_before"))
            issuer = str(e.get("issuer_name", ""))
            org = next((p.split("=", 1)[1] for p in issuer.split(", ") if p.startswith("O=")), issuer[:40])
            cert_id = int(e.get("id") or 0)
            for host in names:
                if not host or " " in host or "@" in host:
                    continue
                reg = registrable(host)
                if not reg:
                    continue
                info = out.setdefault(reg, CtInfo())
                ids = seen.setdefault(reg, set())
                if cert_id not in ids:
                    ids.add(cert_id)
                    info.count += 1
                if nb and (info.first_seen is None or nb < info.first_seen):
                    info.first_seen = nb
                if nb and (info.last_seen is None or nb > info.last_seen):
                    info.last_seen = nb
                if org and org not in info.issuers and len(info.issuers) < 5:
                    info.issuers.append(org)
                if host not in info.names and len(info.names) < 15:
                    info.names.append(host)
        return out

    async def search_keyword(self, keyword: str, registrable: Any) -> dict[str, CtInfo]:
        """
        Find every certificate whose names contain a keyword.

        Args:
            keyword (str): Brand keyword (>= 4 characters recommended).
            registrable (Callable[[str], str | None]): Host -> eTLD+1.
        Returns:
            dict[str, CtInfo]: Registrable domain -> CT info.
        """
        return self.aggregate(await self._query(f"%{keyword}%"), registrable)

    async def search_domain(self, domain: str, registrable: Any) -> CtInfo | None:
        """
        Certificates of one domain and its subdomains.

        Args:
            domain (str): ASCII registrable domain.
            registrable (Callable[[str], str | None]): Host -> eTLD+1.
        Returns:
            CtInfo | None: Aggregated info, None if no certificate.
        """
        entries = await self._query(f"%.{domain}", timeout=30.0, retries=0)
        info = self.aggregate(entries, registrable).get(domain)
        if info is None and self.available:
            info = self.aggregate(await self._query(domain, timeout=30.0, retries=0), registrable).get(domain)
        return info


class UrlscanClient:
    """
    urlscan.io search client (passive: only reads existing public scans).

    Args (constructor):
        http (HttpClient): Shared HTTP client.
        settings (Settings): Provides the optional API key.
    """

    URL = "https://urlscan.io/api/v1/search/"

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
        self.key = settings.urlscan_api_key
        self.disabled_reason: str | None = None

    @property
    def enabled(self) -> bool:
        """
        Whether the client can still be used.

        Returns:
            bool: False after quota exhaustion.
        """
        return self.disabled_reason is None

    async def search(self, domain: str) -> UrlscanInfo | None:
        """
        Look for public scans of a domain.

        Args:
            domain (str): ASCII domain.
        Returns:
            UrlscanInfo | None: Summary, None when disabled or on error.
        """
        if not self.enabled:
            return None
        headers = {"API-Key": self.key} if self.key else None
        res = await self.http.get(
            self.URL, params={"q": f"page.domain:{domain}", "size": "10"}, headers=headers,
            cache_ns="urlscan", ttl=TTL["urlscan"], retries=1,
        )
        if res.status == 429:
            self.disabled_reason = "rate limited"
            return None
        data = res.json() if res.ok else None
        if not isinstance(data, dict):
            return None
        results = data.get("results") or []
        info = UrlscanInfo(total=int(data.get("total") or len(results)))
        if results:
            first = results[0]
            info.last_scan = parse_date((first.get("task") or {}).get("time"))
            info.result_url = first.get("result", "").replace("/api/v1/result/", "/result/") or None
            info.screenshot_url = first.get("screenshot")
            info.malicious = any((r.get("verdicts") or {}).get("malicious") for r in results)
        return info
