"""
Shared plumbing of the analysis pipeline.

  * `Reporter`: the progress protocol the stages talk to (implemented by
    the terminal UI, or by a silent stub for --json / --quiet runs);
  * `ScanContext`: one object holding the settings and every client
    (cache, HTTP, DNS, RDAP/WHOIS, intel APIs, ...), passed to each stage so
    stages stay independent, small and testable;
  * `ScanResult`: what a scan returns;
  * small helpers (bounded gather, file-safe names).
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ..cache import Cache
from ..config import CACHE_DIR, DATA_DIR, Settings
from ..content import ContentFetcher
from ..dnsresolve import DnsResolver
from ..intel import AbuseIpdbClient, CertTransparency, UrlscanClient, VirusTotalClient
from ..models import Candidate, TargetProfile
from ..net import HttpClient
from ..nlp import EmbeddingModel
from ..registration import RegistrationLookup
from ..resources import ResourceManager
from ..visual import Screenshotter, VisualAnalyzer


class Reporter(Protocol):
    """
    Progress sink implemented by the terminal UI (or a silent stub).
    """

    def stage(self, key: str, title: str, total: int | None = None) -> None:
        """
        Open a progress stage.

        Args:
            key (str): Stage identifier.
            title (str): Human readable title.
            total (int | None): Number of steps (None = indeterminate).
        Returns:
            None
        """

    def advance(self, key: str, n: int = 1, info: str = "") -> None:
        """
        Advance a stage.

        Args:
            key (str): Stage identifier.
            n (int): Steps completed.
            info (str): Short live detail.
        Returns:
            None
        """

    def done(self, key: str, summary: str = "") -> None:
        """
        Close a stage.

        Args:
            key (str): Stage identifier.
            summary (str): Final one-line summary.
        Returns:
            None
        """

    def note(self, message: str, level: str = "info") -> None:
        """
        Print a message above the progress display.

        Args:
            message (str): Text (rich markup allowed).
            level (str): "info", "warn" or "error".
        Returns:
            None
        """


class InputError(ValueError):
    """
    Raised when the user-supplied target is not a valid domain.
    """


@dataclass(slots=True)
class ScanResult:
    """
    Complete output of a scan.

    Attributes:
        target (TargetProfile): Target analysis.
        candidates (list[Candidate]): Every candidate, best score first.
        generated (int): Candidates produced by permutation.
        discovered (int): Extra candidates from CT logs / feeds.
        services (dict[str, str]): Service name -> status text.
        stats (dict[str, Any]): Counters and timings.
        started (Any): Start datetime (UTC).
        duration (float): Seconds elapsed.
        settings (dict[str, Any]): Relevant settings snapshot.
    """

    target: TargetProfile
    candidates: list[Candidate] = field(default_factory=list)
    generated: int = 0
    discovered: int = 0
    services: dict[str, str] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)
    started: Any = None
    duration: float = 0.0
    settings: dict[str, Any] = field(default_factory=dict)

    @property
    def registered(self) -> list[Candidate]:
        """
        Registered candidates only.

        Returns:
            list[Candidate]: Candidates whose domain is registered.
        """
        return [c for c in self.candidates if c.registered]


@dataclass(slots=True)
class ScanContext:
    """
    Settings, progress sink and every client used by the stages.

    Attributes:
        settings (Settings): Scan configuration.
        reporter (Reporter): Progress sink.
        out_dir (Path): Directory for screenshots.
        cache (Cache): Two-level cache.
        http (HttpClient): Polite HTTP client.
        resources (ResourceManager): External datasets.
        dns (DnsResolver): Async DNS resolver.
        registry (RegistrationLookup): RDAP + WHOIS.
        fetcher (ContentFetcher): Web page fetcher/analyser.
        visual (VisualAnalyzer): Logo / favicon comparison.
        vt (VirusTotalClient): VirusTotal API.
        abuse (AbuseIpdbClient): AbuseIPDB API.
        ct (CertTransparency): crt.sh client.
        urlscan (UrlscanClient): urlscan.io client.
        screens (Screenshotter | None): Headless browser (deep mode).
        embedder (EmbeddingModel | None): NLP model (deep mode).
    """

    settings: Settings
    reporter: Reporter
    out_dir: Path
    cache: Cache
    http: HttpClient
    resources: ResourceManager
    dns: DnsResolver
    registry: RegistrationLookup
    fetcher: ContentFetcher
    visual: VisualAnalyzer
    vt: VirusTotalClient
    abuse: AbuseIpdbClient
    ct: CertTransparency
    urlscan: UrlscanClient
    screens: Screenshotter | None = None
    embedder: EmbeddingModel | None = None

    @classmethod
    def build(cls, settings: Settings, reporter: Reporter, out_dir: Path) -> ScanContext:
        """
        Create every client (no network activity happens here).

        Args:
            settings (Settings): Scan configuration.
            reporter (Reporter): Progress sink.
            out_dir (Path): Directory for screenshots.
        Returns:
            ScanContext: Ready context.
        """
        cache = Cache(CACHE_DIR / "cache.db", enabled=settings.use_cache)
        http = HttpClient(settings, cache)
        resources = ResourceManager(http, DATA_DIR)
        return cls(
            settings=settings, reporter=reporter, out_dir=out_dir, cache=cache, http=http,
            resources=resources, dns=DnsResolver(settings, cache),
            registry=RegistrationLookup(http, cache, resources, settings.whois_limit),
            fetcher=ContentFetcher(http, settings), visual=VisualAnalyzer(http, settings),
            vt=VirusTotalClient(http, settings), abuse=AbuseIpdbClient(http, settings),
            ct=CertTransparency(http), urlscan=UrlscanClient(http, settings),
        )

    async def close(self) -> None:
        """
        Release the browser, network clients and the cache.

        Returns:
            None
        """
        if self.screens is not None:
            await self.screens.close()
        await self.http.close()
        self.cache.close()


async def gather_limited(coros: list[Any], limit: int) -> list[Any]:
    """
    Await coroutines with bounded concurrency, preserving order.

    Args:
        coros (list[Any]): Coroutines to run.
        limit (int): Maximum simultaneous coroutines.
    Returns:
        list[Any]: Results (exceptions are returned, not raised).
    """
    sem = asyncio.Semaphore(max(1, limit))

    async def run(coro: Any) -> Any:
        """
        Run one coroutine under the semaphore.

        Args:
            coro (Any): Coroutine.
        Returns:
            Any: Its result.
        """
        async with sem:
            return await coro

    return await asyncio.gather(*(run(c) for c in coros), return_exceptions=True)


def safe_name(domain: str) -> str:
    """
    File-system-safe version of a domain (for screenshot names).

    Args:
        domain (str): ASCII domain.
    Returns:
        str: Name with only [a-z0-9._-].
    """
    return re.sub(r"[^a-z0-9._-]", "_", domain.lower())[:120]
