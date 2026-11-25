"""
Stage 7: content similarity (NLP) and, in deep mode, visual page diff.

  * TF-IDF similarity between each lookalike site and the real one
    (multilingual sentence embeddings are added in --deep);
  * headless screenshots of the target and of the top online candidates,
    compared with perceptual hashes.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys

from ..models import Candidate, TargetProfile, VisualMatch
from ..nlp import EmbeddingModel, TfidfIndex
from ..visual import Screenshotter, dhash, load_image, phash
from .context import ScanContext, gather_limited, safe_name


async def text_similarity(ctx: ScanContext, target: TargetProfile, cands: list[Candidate]) -> None:
    """
    TF-IDF (and, in deep mode, embedding) similarity with the target site.

    Args:
        ctx (ScanContext): Scan context.
        target (TargetProfile): Target profile.
        cands (list[Candidate]): Registered candidates.
    Returns:
        None
    """
    if not (target.page and target.page.text):
        return
    docs = {"__target__": f"{target.page.title} {target.page.text}"}
    for c in cands:
        if c.page and c.page.reachable and c.page.text:
            docs[c.ascii] = f"{c.page.title} {c.page.text}"
    if len(docs) < 2:
        return
    r = ctx.reporter
    r.stage("nlp", "NLP content similarity", None)
    index = TfidfIndex(docs)
    for c in cands:
        if c.ascii in docs:
            c.text_similarity = index.similarity("__target__", c.ascii)
    summary = f"{len(docs) - 1} pages compared (TF-IDF)"
    if ctx.settings.deep:
        ctx.embedder = EmbeddingModel()
        if await ctx.embedder.load():
            others = {k: v for k, v in docs.items() if k != "__target__"}
            sims = await ctx.embedder.similarities(docs["__target__"], others)
            for c in cands:
                if c.ascii in sims:
                    c.semantic_similarity = sims[c.ascii]
            summary += " + multilingual embeddings"
        else:
            r.note(f"embeddings disabled: {ctx.embedder.error}", "warn")
    r.done("nlp", summary)


async def ensure_browser(ctx: ScanContext) -> bool:
    """
    Start the headless browser, installing Chromium once if it is missing.

    Args:
        ctx (ScanContext): Scan context.
    Returns:
        bool: True when screenshots are available.
    """
    ctx.screens = Screenshotter(ctx.out_dir / "screenshots", ctx.settings)
    if await ctx.screens.start():
        return True
    if ctx.screens.error and "playwright not installed" not in ctx.screens.error:
        ctx.reporter.note("downloading headless Chromium for screenshots (one-time)...")
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "playwright", "install", "chromium",
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        await proc.wait()
        ctx.screens = Screenshotter(ctx.out_dir / "screenshots", ctx.settings)
        if await ctx.screens.start():
            return True
    ctx.reporter.note(f"screenshots disabled: {ctx.screens.error}", "warn")
    return False


async def screenshot_diff(ctx: ScanContext, target: TargetProfile, cands: list[Candidate],
                          limit: int = 30) -> None:
    """
    Deep mode: screenshot target and top online candidates, compare visually.

    Args:
        ctx (ScanContext): Scan context.
        target (TargetProfile): Target profile.
        cands (list[Candidate]): Candidates sorted by preliminary score.
        limit (int): Maximum candidate screenshots.
    Returns:
        None
    """
    online = [c for c in cands if c.page and c.page.reachable and not c.page.filtered][:limit]
    if not online or not await ensure_browser(ctx):
        return
    screens = ctx.screens
    assert screens is not None
    r = ctx.reporter
    r.stage("shots", "Screenshots & visual diff", len(online) + 1)
    url = target.page.final_url if target.page and target.page.final_url else f"https://{target.ascii}/"
    tpath = await screens.capture(url, safe_name(target.ascii))
    target.screenshot_path = str(tpath) if tpath else None
    r.advance("shots", info=target.domain)
    timg = load_image(tpath.read_bytes()) if tpath else None
    thash = (phash(timg), dhash(timg)) if timg else None

    async def one(c: Candidate) -> None:
        """
        Screenshot one candidate and compare it with the target.

        Args:
            c (Candidate): Candidate.
        Returns:
            None
        """
        path = await screens.capture(c.page.final_url or f"https://{c.ascii}/", safe_name(c.ascii))
        if path:
            c.visual = c.visual or VisualMatch()
            c.visual.screenshot_path = str(path)
            img = load_image(path.read_bytes())
            if img is not None and thash:
                dp = (phash(img) ^ thash[0]).bit_count()
                dd = (dhash(img) ^ thash[1]).bit_count()
                c.visual.screenshot_similarity = round(1 - (0.6 * dp + 0.4 * dd) / 64, 4)
        r.advance("shots", info=c.domain[:40])

    await gather_limited([one(c) for c in online], 3)
    await screens.close()
    r.done("shots", f"{len(online)} pages captured")
