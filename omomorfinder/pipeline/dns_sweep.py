"""
Stage 3: DNS sweep, the cheap filter of the funnel.

Every candidate is resolved NS-first: NXDOMAIN means "free" and ends the
work on that domain; registered domains also get A/AAAA/MX. Timeouts are
retried once at lower concurrency.
"""

from __future__ import annotations

import asyncio

from ..models import Candidate
from .context import ScanContext


async def dns_sweep(ctx: ScanContext, items: list[Candidate], title: str = "DNS sweep") -> None:
    """
    Resolve every candidate (updated in place).

    Args:
        ctx (ScanContext): Scan context.
        items (list[Candidate]): Candidates.
        title (str): Stage title for the UI.
    Returns:
        None
    """
    if not items:
        return
    r = ctx.reporter
    r.stage("dns", title, len(items))
    found = 0

    async def probe(c: Candidate, count: bool = True) -> None:
        """
        Probe one candidate and update the live counter.

        Args:
            c (Candidate): Candidate.
            count (bool): Advance the progress bar.
        Returns:
            None
        """
        nonlocal found
        c.dns = await ctx.dns.probe(c.ascii, c.suffix)
        if c.dns.status == "registered":
            found += 1
        if count:
            r.advance("dns", info=f"{found} registered")

    await asyncio.gather(*(probe(c) for c in items))

    retry = [c for c in items if c.dns.status == "unknown" and not c.dns.wildcard_tld]
    if retry:  # timeouts under load: retry gently (definitive answers are cached)
        r.advance("dns", 0, info=f"retrying {len(retry)} timeouts")
        sem = asyncio.Semaphore(40)

        async def again(c: Candidate) -> None:
            """
            Re-probe one candidate with low concurrency.

            Args:
                c (Candidate): Candidate.
            Returns:
                None
            """
            async with sem:
                await probe(c, count=False)

        await asyncio.gather(*(again(c) for c in retry))
    unknown = sum(1 for c in items if c.dns.status == "unknown")
    r.done("dns", f"{found} registered, {unknown} unverified, {ctx.dns.queries:,} queries")
