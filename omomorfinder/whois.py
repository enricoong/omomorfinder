"""
Polite port-43 WHOIS client, designed never to trip registry rate limits.

Why this module exists: ccTLDs such as ".it" or ".de" have no RDAP, so
WHOIS is the only source of registration data, and their servers throttle
or temporarily ban clients that query too fast. Strategy:

  * **No needless queries.** The WHOIS server of each TLD comes from a
    built-in table or from IANA's HTTPS root database (never from
    whois.iana.org on port 43). Answers are cached for 24 h.
  * **Reachability probe.** One TCP connect per server tells whether port 43
    is reachable at all; networks that block it are detected immediately
    and the client stays silent instead of hammering a dead route.
  * **Adaptive pacing (AIMD).** Each server starts with a conservative
    interval. Any sign of throttling (rate-limit text, timeouts, empty
    answers) doubles the interval and imposes a cool-down; every success
    slowly shortens it again. The query is retried after the cool-down,
    so a throttling server slows the scan down instead of being banned.
  * **Budget.** At most N uncached queries per server per scan; callers
    submit the most relevant domains first.
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
import time
from dataclasses import dataclass, field

from . import activity
from .cache import Cache
from .config import TTL
from .net import HttpClient

log = logging.getLogger(__name__)

# Authoritative WHOIS servers of common TLDs without RDAP (saves a lookup).
KNOWN_WHOIS_SERVERS: dict[str, str] = {
    "it": "whois.nic.it", "de": "whois.denic.de", "eu": "whois.eu", "nl": "whois.domain-registry.nl",
    "be": "whois.dns.be", "ch": "whois.nic.ch", "li": "whois.nic.ch", "at": "whois.nic.at",
    "pl": "whois.dns.pl", "cz": "whois.nic.cz", "se": "whois.iis.se", "ru": "whois.tcinet.ru",
    "io": "whois.nic.io", "me": "whois.nic.me", "ca": "whois.cira.ca", "es": "whois.nic.es",
    "pt": "whois.dns.pt", "sk": "whois.sk-nic.sk", "ie": "whois.weare.ie", "lu": "whois.dns.lu",
}

RATE_LIMITED = re.compile(
    r"limit exceeded|rate limit|quota exceeded|too many|try again later|temporarily denied", re.I
)
_IANA_PAGE = "https://www.iana.org/domains/root/db/{tld}.html"
_IANA_WHOIS = re.compile(r"WHOIS Server</div>\s*<div[^>]*>\s*([a-z0-9][a-z0-9.-]+\.[a-z]{2,})", re.I)


@dataclass(slots=True)
class WhoisPacer:
    """
    Adaptive (AIMD) pacing state of one WHOIS server.

    Attributes:
        base (float): Starting / minimum interval between queries (s).
        maximum (float): Upper bound of the interval (s).
        interval (float): Current interval (s).
        next_slot (float): Monotonic time of the next allowed query.
        throttles (int): Consecutive throttling signals.
        lock (asyncio.Lock): Serialises slot reservations.
        sem (asyncio.Semaphore): One query in flight per server.
    """

    base: float = 2.0
    maximum: float = 30.0
    interval: float = 2.0
    next_slot: float = 0.0
    throttles: int = 0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    sem: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(1))

    async def wait_turn(self) -> None:
        """
        Sleep until this server may be queried again (with jitter).

        Returns:
            None
        """
        async with self.lock:
            now = time.monotonic()
            wait = max(0.0, self.next_slot - now)
            self.next_slot = max(now, self.next_slot) + self.interval * random.uniform(1.0, 1.35)
        if wait:
            await asyncio.sleep(wait)

    def success(self) -> None:
        """
        Additive decrease of the interval after a good answer.

        Returns:
            None
        """
        self.throttles = 0
        self.interval = max(self.base, self.interval * 0.85)

    def throttled(self) -> float:
        """
        Multiplicative increase of the interval plus a cool-down.

        Returns:
            float: Cool-down in seconds before the next attempt.
        """
        self.throttles += 1
        self.interval = min(self.maximum, self.interval * 2)
        cooldown = min(60.0, 10.0 * self.throttles)
        self.next_slot = max(self.next_slot, time.monotonic() + cooldown)
        return cooldown


class WhoisClient:
    """
    Cached, budgeted, adaptively paced port-43 WHOIS client.

    Args (constructor):
        http (HttpClient): Used for IANA's HTTPS root database.
        cache (Cache): Shared cache (namespaces "whois", "whois_refer").
        budget (int): Max uncached queries per server per scan.
    """

    MAX_ATTEMPTS = 3

    def __init__(self, http: HttpClient, cache: Cache, budget: int = 40) -> None:
        """
        Initialise per-server state.

        Args:
            http (HttpClient): Shared HTTP client.
            cache (Cache): Shared cache.
            budget (int): Query budget per server.
        Returns:
            None
        """
        self.http = http
        self.cache = cache
        self.budget = budget
        self._pacers: dict[str, WhoisPacer] = {}
        self._probes: dict[str, asyncio.Task[bool]] = {}
        self._server_locks: dict[str, asyncio.Lock] = {}
        self._queries: dict[str, int] = {}
        self.unreachable: set[str] = set()
        self.slowed: set[str] = set()
        self.skipped = 0

    def pacer(self, server: str) -> WhoisPacer:
        """
        Pacing state of a server (created on first use).

        Args:
            server (str): WHOIS hostname.
        Returns:
            WhoisPacer: Its pacer.
        """
        pacer = self._pacers.get(server)
        if pacer is None:
            pacer = self._pacers[server] = WhoisPacer()
        return pacer

    async def server_for(self, tld: str) -> str | None:
        """
        Authoritative WHOIS server of a TLD (table, cache, then IANA HTTPS).

        Args:
            tld (str): Top-level domain (ASCII, lower case).
        Returns:
            str | None: Hostname, None when the TLD has no WHOIS service.
        """
        if tld in KNOWN_WHOIS_SERVERS:
            return KNOWN_WHOIS_SERVERS[tld]
        key = Cache.make_key("iana-page", tld)
        cached = self.cache.get_json("whois_refer", key)
        if cached is not None:
            return cached or None
        lock = self._server_locks.setdefault(tld, asyncio.Lock())
        async with lock:
            cached = self.cache.get_json("whois_refer", key)
            if cached is not None:
                return cached or None
            res = await self.http.get(_IANA_PAGE.format(tld=tld), max_bytes=400_000, retries=1)
            if not res.ok:
                return None  # transient: not cached, retried by a later lookup
            match = _IANA_WHOIS.search(res.text)
            server = match.group(1).lower() if match else ""
            self.cache.set_json("whois_refer", key, server, TTL["whois_refer"])
            return server or None

    async def reachable(self, server: str) -> bool:
        """
        One-time TCP probe of port 43 (shared by concurrent callers).

        Args:
            server (str): WHOIS hostname.
        Returns:
            bool: False when the network blocks port 43 or the host is down.
        """
        task = self._probes.get(server)
        if task is None:
            async def probe() -> bool:
                """
                Open and immediately close a TCP connection.

                Returns:
                    bool: True if the connection succeeded.
                """
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(server, 43, happy_eyeballs_delay=0.25), 8)
                except (OSError, TimeoutError) as exc:
                    log.debug("whois probe %s failed: %s", server, exc)
                    self.unreachable.add(server)
                    return False
                writer.close()
                return True

            task = self._probes[server] = asyncio.ensure_future(probe())
        return await task

    async def query(self, server: str, query: str, timeout: float = 12.0) -> str | None:
        """
        Run one WHOIS query politely (cache, probe, budget, AIMD, retries).

        Args:
            server (str): WHOIS hostname.
            query (str): Query line.
            timeout (float): Connect and read timeout (s).
        Returns:
            str | None: Response text, None when unavailable/skipped.
        """
        key = Cache.make_key(server, query)
        cached = self.cache.get_json("whois", key)
        if cached is not None:
            return cached
        if not await self.reachable(server):
            return None
        if self._queries.get(server, 0) >= self.budget:
            self.skipped += 1
            return None
        self._queries[server] = self._queries.get(server, 0) + 1
        pacer = self.pacer(server)
        for _attempt in range(self.MAX_ATTEMPTS):
            async with pacer.sem:
                await pacer.wait_turn()
                activity.emit("whois", activity.whois_command(server, query))
                text = await self._exchange(server, query, timeout)
            if text and not (RATE_LIMITED.search(text[:800]) and len(text) < 800):
                pacer.success()
                self.cache.set_json("whois", key, text, TTL["whois"])
                return text
            cooldown = pacer.throttled()
            self.slowed.add(server)
            log.debug("whois %s throttled, cooling down %.0fs", server, cooldown)
        return None

    @staticmethod
    async def _exchange(server: str, query: str, timeout: float) -> str | None:
        """
        Perform the raw TCP/43 exchange (connect, send, read until EOF).

        Args:
            server (str): WHOIS hostname.
            query (str): Query line.
            timeout (float): Timeout for connect and for the whole read.
        Returns:
            str | None: Decoded response, None when nothing was received.
        """
        chunks: list[bytes] = []
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(server, 43, happy_eyeballs_delay=0.25), timeout)
        except (OSError, TimeoutError) as exc:
            log.debug("whois connect %s failed: %s", server, exc)
            return None

        async def read_all() -> None:
            """
            Read until EOF or until 256 KiB were received.

            Returns:
                None
            """
            total = 0
            while total < 262_144:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)

        try:
            writer.write(f"{query}\r\n".encode("ascii", "ignore"))
            await writer.drain()
            await asyncio.wait_for(read_all(), timeout)
        except (OSError, TimeoutError) as exc:
            log.debug("whois read %s failed: %s", server, exc)
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 3)
            except (OSError, TimeoutError):
                pass
        raw = b"".join(chunks)
        if not raw:
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1", errors="replace")

    def status(self) -> str:
        """
        One-line service status for the UI.

        Returns:
            str: "on", "on: ..." or "off: ..." text.
        """
        if self.unreachable and not self._queries:
            return "off: port 43 blocked by this network (RDAP still used)"
        notes = []
        if self.slowed:
            notes.append(f"auto-slowed for {', '.join(sorted(self.slowed))}")
        if self.skipped:
            notes.append(f"{self.skipped} low-priority lookups skipped (--whois-limit)")
        if self.unreachable:
            notes.append(f"unreachable: {', '.join(sorted(self.unreachable))}")
        return "on" + (f": {'; '.join(notes)}" if notes else "")
