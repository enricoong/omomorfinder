"""
Scan orchestrator: chains the stages of the funnel.

    datasets -> target profile -> generation + discovery (feeds, CT)
      -> DNS sweep -> enrichment (RDAP/WHOIS, web, logos)
      -> subdomains -> AbuseIPDB -> NLP -> screenshots (deep)
      -> pre-score -> VirusTotal (top-N) -> final score

Each stage lives in its own module of this package and receives the shared
`ScanContext`; this module only decides the order and what flows between
stages. Expensive stages only see what survived the cheap ones.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

from ..config import Settings
from ..models import utcnow
from ..scoring import Scorer
from .analysis import screenshot_diff, text_similarity
from .context import Reporter, ScanContext, ScanResult
from .discovery import discover_ct, generate_candidates
from .dns_sweep import dns_sweep
from .enrichment import enrich
from .reputation import check_abuse, check_virustotal
from .subdomains import analyse_subdomains
from .target import profile_target, sync_datasets


class Scanner:
    """
    Runs the whole analysis pipeline for one target domain.

    Args (constructor):
        settings (Settings): Scan configuration.
        reporter (Reporter): Progress sink.
        out_dir (Path): Where screenshots are written (deep mode).
    """

    def __init__(self, settings: Settings, reporter: Reporter, out_dir: Path) -> None:
        """
        Build the shared context (no network activity yet).

        Args:
            settings (Settings): Scan configuration.
            reporter (Reporter): Progress sink.
            out_dir (Path): Output directory.
        Returns:
            None
        """
        self.ctx = ScanContext.build(settings, reporter, out_dir)

    async def run(self, domain: str) -> ScanResult:
        """
        Execute the whole pipeline.

        Args:
            domain (str): Target domain supplied by the user.
        Returns:
            ScanResult: Ranked candidates and scan metadata.
        Raises:
            InputError: When the target is not a valid registrable domain.
        """
        ctx, s = self.ctx, self.ctx.settings
        t0, started = time.monotonic(), utcnow()
        try:
            await sync_datasets(ctx)
            target = await profile_target(ctx, domain)
            result = ScanResult(target=target, started=started)

            cands, result.generated = generate_candidates(ctx, target)
            first_wave = list(cands.values())
            # CT discovery (slow, remote) runs while DNS resolves the
            # generated candidates; its discoveries are resolved afterwards.
            ct_task = asyncio.create_task(discover_ct(ctx, target, cands))
            await dns_sweep(ctx, first_wave)
            if await ct_task:
                seen = {id(c) for c in first_wave}
                await dns_sweep(ctx, [c for c in cands.values() if id(c) not in seen],
                                "DNS sweep (CT discoveries)")
            result.discovered = len(cands) - result.generated

            scorer = Scorer(target)
            everything = list(cands.values())
            if not s.fast:
                live = [c for c in everything if c.dns.status in ("registered", "unknown")]
                await enrich(ctx, target, live)
                registered = [c for c in live if c.registered]
                await analyse_subdomains(ctx, target, registered)
                await check_abuse(ctx, registered)
                await text_similarity(ctx, target, registered)
                self._rank(scorer, registered)
                if s.deep:
                    await screenshot_diff(ctx, target, registered)
                    self._rank(scorer, registered)
                await check_virustotal(ctx, [c for c in registered if c.category != "DEFENSIVE"])

            for c in everything:
                scorer.score(c)
            everything.sort(key=lambda c: (-c.score, -c.lexical, c.domain))
            result.candidates = everything
            result.services = self.service_status()
            result.duration = time.monotonic() - t0
            result.stats = self._stats()
            result.settings = {
                "profile": s.profile, "tld_mode": s.tld_mode, "keyboard": s.keyboard,
                "vt_limit": s.vt_limit, "abuse_limit": s.abuse_limit, "whois_limit": s.whois_limit,
            }
            return result
        finally:
            await ctx.close()

    @staticmethod
    def _rank(scorer: Scorer, cands: list) -> None:
        """
        Score candidates and sort them in place (best first).

        Args:
            scorer (Scorer): Scorer bound to the target.
            cands (list): Candidates.
        Returns:
            None
        """
        for c in cands:
            scorer.score(c)
        cands.sort(key=lambda c: (-c.score, -c.lexical))

    def _stats(self) -> dict[str, int]:
        """
        Network and cache counters of the run.

        Returns:
            dict[str, int]: Counter name -> value.
        """
        ctx = self.ctx
        return {
            "dns_queries": ctx.dns.queries,
            "http_requests": ctx.http.requests_sent,
            "bytes_downloaded": ctx.http.bytes_received,
            "cache_hits": ctx.cache.hits,
            "cache_misses": ctx.cache.misses,
            "vt_calls": ctx.vt.used,
            "abuseipdb_calls": ctx.abuse.used,
        }

    def service_status(self) -> dict[str, str]:
        """
        Human readable status of every external service.

        Returns:
            dict[str, str]: Service -> "on", "on: note", "off: reason" or
            "error: reason".
        """
        ctx, s = self.ctx, self.ctx.settings
        status = {
            "VirusTotal": "on" if ctx.vt.enabled else f"off: {ctx.vt.disabled_reason}",
            "AbuseIPDB": "on" if ctx.abuse.enabled else f"off: {ctx.abuse.disabled_reason}",
            "crt.sh": ("off: fast profile" if s.fast else
                       f"error: {ctx.ct.error[:50]}" if ctx.ct.error else "on"),
            "urlscan.io": ("on" if (s.urlscan_api_key or s.deep) and ctx.urlscan.enabled
                           else "off: needs URLSCAN_API_KEY or --deep"),
            "Threat feeds": f"on: {len(ctx.resources.feed_hosts()):,} hosts",
            "RDAP": "off: fast profile" if s.fast else "on",
            "WHOIS": "off: fast profile" if s.fast else ctx.registry.status(),
        }
        if s.deep:
            status["Screenshots"] = "on" if ctx.screens and not ctx.screens.error else \
                f"off: {ctx.screens.error if ctx.screens else 'no online candidates'}"
            status["Embeddings"] = "on" if ctx.embedder and not ctx.embedder.error else \
                f"off: {ctx.embedder.error if ctx.embedder else 'not needed'}"
        return status
