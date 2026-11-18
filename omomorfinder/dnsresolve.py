"""
High-throughput asynchronous DNS probing.

DNS is the cheap first filter of the pipeline: an NS query against the
parent zone tells whether a lookalike is registered (NXDOMAIN = free) at a
tiny fraction of the cost of RDAP/WHOIS. Results are cached, concurrency is
bounded, and wildcard TLDs (that answer for every name) are detected so
their results are flagged as uncertain instead of producing false positives.
"""

from __future__ import annotations

import asyncio
import logging
import random
import string

import dns.asyncresolver
import dns.exception
import dns.resolver

from .cache import Cache
from .config import TTL, Settings
from .models import DnsInfo

log = logging.getLogger(__name__)


class DnsResolver:
    """
    Cached asynchronous resolver with bounded concurrency.

    Args (constructor):
        settings (Settings): Provides resolvers and concurrency.
        cache (Cache): Shared cache (namespace "dns").
    """

    def __init__(self, settings: Settings, cache: Cache) -> None:
        """
        Configure the underlying dnspython async resolver.

        Args:
            settings (Settings): Scan configuration.
            cache (Cache): Shared cache.
        Returns:
            None
        """
        if settings.resolvers:
            self.resolver = dns.asyncresolver.Resolver(configure=False)
            self.resolver.nameservers = list(settings.resolvers)
        else:
            try:
                self.resolver = dns.asyncresolver.Resolver()
            except dns.resolver.NoResolverConfiguration:
                self.resolver = dns.asyncresolver.Resolver(configure=False)
                self.resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
        self.resolver.timeout = 2.5
        self.resolver.lifetime = 6.0
        self.cache = cache
        self._sem = asyncio.Semaphore(max(1, settings.dns_concurrency))
        self._wildcards: dict[str, asyncio.Task[bool]] = {}
        self.queries = 0

    @staticmethod
    def _parse(rdtype: str, answer: dns.resolver.Answer) -> list[str]:
        """
        Convert a dnspython answer into plain strings.

        Args:
            rdtype (str): Record type ("A", "AAAA", "MX", "NS", "TXT").
            answer (dns.resolver.Answer): dnspython answer.
        Returns:
            list[str]: Sorted unique values (hostnames without trailing dot).
        """
        values: set[str] = set()
        for rr in answer:
            if rdtype in ("A", "AAAA"):
                values.add(rr.address)
            elif rdtype == "MX":
                values.add(str(rr.exchange).rstrip(".").lower())
            elif rdtype == "NS":
                values.add(str(rr.target).rstrip(".").lower())
            elif rdtype == "TXT":
                values.add(b"".join(rr.strings).decode("utf-8", errors="replace"))
            else:
                values.add(rr.to_text())
        return sorted(v for v in values if v)

    async def query(self, name: str, rdtype: str) -> tuple[str, list[str]]:
        """
        Resolve one record type, with caching.

        Args:
            name (str): ASCII domain name.
            rdtype (str): Record type.
        Returns:
            tuple[str, list[str]]: (status, values) where status is "ok",
            "noanswer", "nxdomain", "servfail", "timeout" or "error".
        """
        key = Cache.make_key(name, rdtype)
        cached = self.cache.get_json("dns", key)
        if cached is not None:
            return cached[0], cached[1]
        async with self._sem:
            self.queries += 1
            try:
                ans = await self.resolver.resolve(name, rdtype, raise_on_no_answer=False)
                if ans.rrset is None:
                    status, values = "noanswer", []
                else:
                    status, values = "ok", self._parse(rdtype, ans)
            except dns.resolver.NXDOMAIN:
                status, values = "nxdomain", []
            except dns.resolver.NoNameservers:
                status, values = "servfail", []
            except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
                status, values = "timeout", []
            except dns.exception.DNSException as exc:
                log.debug("dns error %s %s: %s", name, rdtype, exc)
                status, values = "error", []
        if status in ("ok", "noanswer", "nxdomain", "servfail"):
            self.cache.set_json("dns", key, [status, values], TTL["dns"])
        return status, values

    async def is_wildcard_tld(self, suffix: str) -> bool:
        """
        Detect TLDs that answer for any (even random) name.

        The check runs once per suffix and is shared by concurrent callers.

        Args:
            suffix (str): Public suffix (ASCII).
        Returns:
            bool: True if a random 24-character label resolves.
        """
        task = self._wildcards.get(suffix)
        if task is None:
            async def check() -> bool:
                """
                Resolve a random label under the suffix.

                Returns:
                    bool: True if it resolves (wildcard TLD).
                """
                label = "".join(random.choices(string.ascii_lowercase + string.digits, k=24))
                status, _ = await self.query(f"{label}.{suffix}", "A")
                return status == "ok"

            task = asyncio.ensure_future(check())
            self._wildcards[suffix] = task
        return await task

    async def probe(self, domain: str, suffix: str, full: bool = True) -> DnsInfo:
        """
        Determine registration status and DNS footprint of a domain.

        Strategy: query NS first (answered by the parent zone). NXDOMAIN means
        unregistered and stops there; otherwise A/AAAA/MX are fetched
        concurrently.

        Args:
            domain (str): ASCII domain.
            suffix (str): Its public suffix (for wildcard detection).
            full (bool): Fetch A/AAAA/MX for registered domains.
        Returns:
            DnsInfo: Footprint with status "registered", "unregistered" or
            "unknown".
        """
        info = DnsInfo()
        ns_status, ns = await self.query(domain, "NS")
        if ns_status == "nxdomain":
            info.status = "unregistered"
            return info
        if ns_status in ("timeout", "error"):
            a_status, a = await self.query(domain, "A")
            if a_status == "nxdomain":
                info.status = "unregistered"
                return info
            if a_status not in ("ok", "noanswer"):
                return info
            info.a = a
        info.ns = ns
        if full:
            (_, a), (_, aaaa), (_, mx) = await asyncio.gather(
                self.query(domain, "A"), self.query(domain, "AAAA"), self.query(domain, "MX")
            )
            info.a, info.aaaa, info.mx = a, aaaa, [m for m in mx if m and m != "."]
        if not ns and await self.is_wildcard_tld(suffix):
            info.wildcard_tld = True
            info.status = "unknown"
        else:
            info.status = "registered"
        return info

    async def mail_security(self, domain: str) -> tuple[str | None, str | None]:
        """
        Fetch SPF and DMARC policies of a domain.

        Args:
            domain (str): ASCII domain.
        Returns:
            tuple[str | None, str | None]: (SPF record, DMARC record).
        """
        (_, txt), (_, dmarc) = await asyncio.gather(
            self.query(domain, "TXT"), self.query(f"_dmarc.{domain}", "TXT")
        )
        spf = next((t for t in txt if t.lower().startswith("v=spf1")), None)
        dm = next((t for t in dmarc if t.lower().startswith("v=dmarc1")), None)
        return spf, dm
