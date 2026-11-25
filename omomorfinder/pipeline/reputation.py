"""
Stage 6: third-party reputation (AbuseIPDB and VirusTotal).

Both APIs have small free quotas, so only the most relevant data is sent:
deduplicated hosting IPs of the most similar domains (AbuseIPDB) and the
highest-scoring non-defensive domains (VirusTotal, paced on its quota).
"""

from __future__ import annotations

from typing import Any

from ..models import Candidate
from .context import ScanContext, gather_limited


async def check_abuse(ctx: ScanContext, cands: list[Candidate]) -> None:
    """
    Query AbuseIPDB for hosting IPs (deduplicated, most similar first).

    Args:
        ctx (ScanContext): Scan context.
        cands (list[Candidate]): Registered candidates.
    Returns:
        None
    """
    if not ctx.abuse.enabled:
        return
    ips: list[str] = []
    for c in sorted(cands, key=lambda x: -x.lexical):
        for ip in c.dns.a[:2]:
            if ip not in ips:
                ips.append(ip)
    ips = ips[: ctx.settings.abuse_limit]
    if not ips:
        return
    r = ctx.reporter
    r.stage("abuse", "AbuseIPDB reputation", len(ips))
    reports: dict[str, Any] = {}

    async def one(ip: str) -> None:
        """
        Check one IP.

        Args:
            ip (str): IP address.
        Returns:
            None
        """
        reports[ip] = await ctx.abuse.check(ip)
        r.advance("abuse", info=ip)

    await gather_limited([one(ip) for ip in ips], 4)
    for c in cands:
        c.abuse = [reports[ip] for ip in c.dns.a[:2] if reports.get(ip)]
    bad = sum(1 for rep in reports.values() if rep and rep.score >= 25)
    r.done("abuse", f"{len(ips)} IPs checked, {bad} with abuse reports")


async def check_virustotal(ctx: ScanContext, cands: list[Candidate]) -> None:
    """
    Query VirusTotal for the highest-scoring registered candidates.

    Args:
        ctx (ScanContext): Scan context.
        cands (list[Candidate]): Registered candidates sorted by score.
    Returns:
        None
    """
    s = ctx.settings
    if not ctx.vt.enabled or s.vt_limit <= 0:
        return
    todo = cands[: s.vt_limit]
    if not todo:
        return
    r = ctx.reporter
    eta = len(todo) * 60 / max(s.vt_rate_per_min, 0.1)
    r.stage("vt", f"VirusTotal (quota-paced, ~{eta / 60:.0f} min)", len(todo))

    async def one(c: Candidate) -> None:
        """
        Fetch one VirusTotal report.

        Args:
            c (Candidate): Candidate.
        Returns:
            None
        """
        if ctx.vt.enabled:
            c.vt = await ctx.vt.domain(c.ascii)
        r.advance("vt", info=c.domain[:40])

    await gather_limited([one(c) for c in todo], 2)
    flagged = sum(1 for c in todo if c.vt and c.vt.malicious)
    msg = f"{len(todo)} domains checked, {flagged} flagged"
    if ctx.vt.disabled_reason:
        msg += f" (stopped: {ctx.vt.disabled_reason})"
    r.done("vt", msg)
