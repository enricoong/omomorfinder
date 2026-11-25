"""
Stage 4: enrichment of registered / unverified candidates.

Three independent pools run at the same time, so the stage lasts as long
as the slowest one rather than their sum:

  * registration (RDAP / polite WHOIS), most similar domains first;
  * web analysis (homepage + logo/favicon comparison);
  * extra lookups (per-domain CT and urlscan.io) for the top candidates.

Each step has a hard time budget: one hostile host can never stall a scan.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from ..content import parking_nameservers
from ..models import Candidate, TargetProfile, VisualMatch
from .context import ScanContext, gather_limited

log = logging.getLogger(__name__)


async def enrich_web(ctx: ScanContext, c: Candidate, target: TargetProfile) -> None:
    """
    Fetch and analyse a candidate website, then compare its brand images.

    Args:
        ctx (ScanContext): Scan context.
        c (Candidate): Candidate (needs A/AAAA records or unknown status).
        target (TargetProfile): Target profile.
    Returns:
        None
    """
    page = await ctx.fetcher.fetch(c.ascii, target.ascii, target.brand_terms)
    c.page = page
    if parking_nameservers(c.dns.ns) and not page.parked and len(page.text) < 3000:
        page.parked = True
        page.parking_reasons.append("parking name servers")
    if page.reachable and target.logos:
        fps = await ctx.visual.fingerprint_page(page.icon_urls, page.image_urls)
        c.visual = ctx.visual.compare(target.logos, fps) if fps else VisualMatch()


async def enrich_extra(ctx: ScanContext, c: Candidate) -> None:
    """
    Per-domain CT search (deep mode) and urlscan.io lookup.

    Args:
        ctx (ScanContext): Scan context.
        c (Candidate): Candidate.
    Returns:
        None
    """
    if ctx.settings.deep and c.ct is None and ctx.ct.available:
        c.ct = await ctx.ct.search_domain(c.ascii, ctx.resources.psl().registrable)
    if ctx.urlscan.enabled and (ctx.settings.urlscan_api_key or ctx.settings.deep):
        c.urlscan = await ctx.urlscan.search(c.ascii)


async def enrich(ctx: ScanContext, target: TargetProfile, cands: list[Candidate]) -> None:
    """
    Enrich every registered / unverified candidate.

    Args:
        ctx (ScanContext): Scan context.
        target (TargetProfile): Target profile.
        cands (list[Candidate]): Candidates to enrich.
    Returns:
        None
    """
    r, s = ctx.reporter, ctx.settings
    cands = sorted(cands, key=lambda c: -c.lexical)  # most relevant first (WHOIS budget)
    web = [c for c in cands if c.dns.ips or c.dns.status == "unknown"]
    extra = cands[:15] if (s.deep or (ctx.urlscan.enabled and s.urlscan_api_key)) else []
    r.stage("enrich", "RDAP/WHOIS, web content, logos", len(cands) + len(web) + len(extra))

    async def guarded(c: Candidate, coro: Any, budget: float) -> None:
        """
        Run one enrichment step with a hard time budget, never raising.

        Args:
            c (Candidate): Candidate being enriched.
            coro (Any): Coroutine to await.
            budget (float): Maximum seconds for this step.
        Returns:
            None
        """
        try:
            await asyncio.wait_for(coro, budget)
        except TimeoutError:
            log.debug("enrich %s exceeded %.0fs", c.ascii, budget)
            c.notes.append(f"enrichment step timed out after {budget:.0f}s")
        except Exception as exc:  # one broken site must not stop the scan
            log.debug("enrich %s failed: %s", c.ascii, exc, exc_info=True)
            c.notes.append(f"enrichment error: {type(exc).__name__}")
        r.advance("enrich", info=c.domain[:40])

    async def registration(c: Candidate) -> None:
        """
        RDAP/WHOIS lookup of one candidate.

        Args:
            c (Candidate): Candidate.
        Returns:
            None
        """
        c.registration = await ctx.registry.lookup(c.ascii, c.suffix)

    await asyncio.gather(
        # WHOIS queues on adaptive per-server pacers: generous budget
        gather_limited([guarded(c, registration(c), 600) for c in cands], 24),
        gather_limited([guarded(c, enrich_web(ctx, c, target), 100) for c in web], s.http_concurrency),
        gather_limited([guarded(c, enrich_extra(ctx, c), 200) for c in extra], 4),
    )
    online = sum(1 for c in cands if c.page and c.page.reachable)
    r.done("enrich", f"{len(cands)} enriched, {online} websites online")
