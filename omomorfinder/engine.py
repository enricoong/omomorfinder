"""
Scan orchestration: the staged funnel that turns one domain into a ranked
list of lookalike threats.

    resources -> target profile -> generation + discovery (CT, feeds)
      -> DNS sweep -> enrichment (RDAP/WHOIS, web, logos, CT, urlscan)
      -> AbuseIPDB -> NLP -> screenshots (deep) -> pre-score
      -> VirusTotal (top-N) -> final score

Expensive stages only see what survived the cheap ones, which keeps the
scan fast and the external services happy. The engine knows nothing about
the terminal: it reports progress through the `Reporter` protocol.
"""

from __future__ import annotations

import asyncio
import logging
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

import idna

from . import similarity
from .cache import Cache
from .config import CACHE_DIR, DATA_DIR, Settings
from .content import ContentFetcher, parking_nameservers
from .dnsresolve import DnsResolver
from .generator import DomainGenerator, to_ascii_label
from .intel import AbuseIpdbClient, CertTransparency, UrlscanClient, VirusTotalClient
from .models import Candidate, TargetProfile, VisualMatch, utcnow
from .net import HttpClient
from .nlp import EmbeddingModel, TfidfIndex, title_terms
from .registration import RegistrationLookup
from .resources import ResourceManager
from .scoring import Scorer
from .visual import Screenshotter, VisualAnalyzer, dhash, load_image, phash

log = logging.getLogger(__name__)


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
    Raised when the user-supplied target cannot be parsed as a domain.
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


def safe_name(domain: str) -> str:
    """
    File-system-safe version of a domain (for screenshot names).

    Args:
        domain (str): ASCII domain.
    Returns:
        str: Name with only [a-z0-9._-].
    """
    return re.sub(r"[^a-z0-9._-]", "_", domain.lower())[:120]


class Scanner:
    """
    Runs the whole analysis pipeline for one target.

    Args (constructor):
        settings (Settings): Scan configuration.
        reporter (Reporter): Progress sink.
        out_dir (Path): Where screenshots are written.
    """

    def __init__(self, settings: Settings, reporter: Reporter, out_dir: Path) -> None:
        """
        Build every component (no network activity yet).

        Args:
            settings (Settings): Scan configuration.
            reporter (Reporter): Progress sink.
            out_dir (Path): Output directory.
        Returns:
            None
        """
        self.s = settings
        self.r = reporter
        self.out_dir = out_dir
        self.cache = Cache(CACHE_DIR / "cache.db", enabled=settings.use_cache)
        self.http = HttpClient(settings, self.cache)
        self.resources = ResourceManager(self.http, DATA_DIR)
        self.dns = DnsResolver(settings, self.cache)
        self.registry = RegistrationLookup(self.http, self.cache, self.resources, settings.whois_limit)
        self.fetcher = ContentFetcher(self.http, settings)
        self.visual = VisualAnalyzer(self.http, settings)
        self.vt = VirusTotalClient(self.http, settings)
        self.abuse = AbuseIpdbClient(self.http, settings)
        self.ct = CertTransparency(self.http)
        self.urlscan = UrlscanClient(self.http, settings)
        self.screens: Screenshotter | None = None
        self.embedder: EmbeddingModel | None = None

    # ------------------------------------------------------------------ utils
    def parse_target(self, raw: str) -> tuple[str, str, str, str]:
        """
        Normalise user input (URL, host, IDN) to the registrable domain.

        Args:
            raw (str): e.g. "https://www.example.co.uk/path" or "exämple.de".
        Returns:
            tuple[str, str, str, str]: (unicode domain, ascii domain, name,
            suffix) where name/suffix are ASCII.
        Raises:
            InputError: When no valid registrable domain can be derived.
        """
        text = raw.strip().lower()
        host = urlsplit(text if "://" in text else f"http://{text}").hostname or ""
        host = host.strip(".")
        if not host or "." not in host:
            raise InputError(f"'{raw}' is not a valid domain")
        try:
            ascii_host = idna.encode(host, uts46=True).decode("ascii")
        except idna.IDNAError as exc:
            raise InputError(f"invalid IDN domain '{raw}': {exc}") from exc
        psl = self.resources.psl()
        _, name, suffix = psl.split(ascii_host)
        if not name:
            raise InputError(f"'{raw}' is a public suffix, not a registrable domain")
        ascii_dom = f"{name}.{suffix}"
        try:
            unicode_dom = idna.decode(ascii_dom)
        except idna.IDNAError:
            unicode_dom = ascii_dom
        return unicode_dom, ascii_dom, name, suffix

    def make_candidate(self, ascii_dom: str, target: TargetProfile, fuzzers: set[str]) -> Candidate | None:
        """
        Build a Candidate from an ASCII domain (used for discovered domains).

        Args:
            ascii_dom (str): ASCII registrable domain.
            target (TargetProfile): Target profile.
            fuzzers (set[str]): Source tags.
        Returns:
            Candidate | None: Candidate, None if the domain is unusable.
        """
        _, name, suffix = self.resources.psl().split(ascii_dom)
        if not name or to_ascii_label(name) is None and not name.startswith("xn--"):
            return None
        try:
            uname = idna.decode(name) if name.startswith("xn--") else name
        except idna.IDNAError:
            uname = name
        lex, homo = similarity.lexical_score(uname, suffix, target.name, target.suffix)
        return Candidate(domain=f"{uname}.{suffix}", ascii=f"{name}.{suffix}", name=uname,
                         suffix=suffix, fuzzers=set(fuzzers), lexical=lex, homograph=homo)

    async def gather_limited(self, coros: list[Any], limit: int) -> list[Any]:
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

    # ----------------------------------------------------------------- stages
    async def stage_resources(self) -> None:
        """
        Download / refresh every external dataset.

        Returns:
            None
        """
        from .resources import RESOURCES

        self.r.stage("res", "Syncing datasets", len(RESOURCES))

        def on_done(res: Any, state: str) -> None:
            """
            Progress callback for each dataset.

            Args:
                res (Any): Resource descriptor.
                state (str): Download state.
            Returns:
                None
            """
            self.r.advance("res", info=f"{res.label}: {state}")
            if state == "missing":
                self.r.note(f"dataset unavailable: {res.label} (using built-in fallback)", "warn")

        await self.resources.ensure_all(on_done=on_done)
        similarity.load_confusables(self.resources.confusables())
        feeds = len(self.resources.feed_hosts())
        self.r.done("res", f"{len(self.resources.tlds())} TLDs, {feeds:,} known-bad hosts")

    async def stage_target(self, raw: str) -> TargetProfile:
        """
        Profile the legitimate target (DNS, mail security, RDAP, homepage, logos).

        Args:
            raw (str): User input.
        Returns:
            TargetProfile: Target analysis.
        """
        udom, adom, name, suffix = self.parse_target(raw)
        target = TargetProfile(input=raw, domain=udom, ascii=adom, name=name, suffix=suffix)
        self.r.stage("target", f"Profiling {udom}", 4)

        async def dns_part() -> None:
            """
            Resolve target DNS and SPF/DMARC.

            Returns:
                None
            """
            target.dns = await self.dns.probe(adom, suffix)
            target.dns.spf, target.dns.dmarc = await self.dns.mail_security(adom)
            self.r.advance("target", info="DNS")

        async def reg_part() -> None:
            """
            RDAP/WHOIS lookup of the target.

            Returns:
                None
            """
            target.registration = await self.registry.lookup(adom, suffix)
            self.r.advance("target", info="RDAP/WHOIS")

        async def web_part() -> None:
            """
            Fetch the homepage and fingerprint the brand images.

            Returns:
                None
            """
            if self.s.fast:
                self.r.advance("target", 2)
                return
            target.page = await self.fetcher.fetch(adom, adom, [name])
            if not target.page.reachable:
                target.page = await self.fetcher.fetch(f"www.{adom}", adom, [name])
            self.r.advance("target", info="homepage")
            if target.page.reachable:
                target.logos = await self.visual.fingerprint_page(target.page.icon_urls, target.page.image_urls)
                fav = next((l for l in target.logos if l.kind == "favicon"), None)
                target.favicon_mmh3 = fav.mmh3 if fav else None
            self.r.advance("target", info=f"{len(target.logos)} brand images")

        await asyncio.gather(dns_part(), reg_part(), web_part())
        target.brand_terms = title_terms(target.page.title if target.page else "", name)
        if target.page and target.page.reachable:
            # recount brand mentions with the full brand vocabulary
            hay = f"{target.page.title} {target.page.text}".lower()
            target.page.brand_mentions = hay.count(name)
        self.r.done("target", f"{udom} profiled")
        return target

    def stage_generate(self, target: TargetProfile) -> dict[str, Candidate]:
        """
        Generate permutations and discover lookalikes inside threat feeds.

        Args:
            target (TargetProfile): Target profile.
        Returns:
            dict[str, Candidate]: ASCII domain -> candidate.
        """
        self.r.stage("gen", "Generating lookalikes", None)
        gen = DomainGenerator(self.resources, self.s)
        out: dict[str, Candidate] = {}
        for ascii_dom, g in gen.generate(target.name, target.suffix).items():
            lex, homo = similarity.lexical_score(g.name, g.suffix, target.name, target.suffix)
            out[ascii_dom] = Candidate(domain=g.unicode, ascii=ascii_dom, name=g.name, suffix=g.suffix,
                                       fuzzers=g.fuzzers, lexical=lex, homograph=homo)
        generated = len(out)
        exact, sub = self.resources.feed_index()
        for reg, cand in out.items():
            cand.feeds |= exact.get(reg, set())
            cand.feed_subdomains |= sub.get(reg, set())
        discovered = 0
        for index in (exact, sub):
            for reg in index:
                if reg in out or reg == target.ascii:
                    continue
                if not similarity.is_near(reg.split(".", 1)[0], target.name):
                    continue
                cand = self.make_candidate(reg, target, {"feed"})
                if cand is None:
                    continue
                out[reg] = cand
                discovered += 1
                cand.feeds |= exact.get(reg, set())
                cand.feed_subdomains |= sub.get(reg, set())
        self.r.done("gen", f"{generated:,} permutations, {discovered} from threat feeds")
        self._generated = generated
        return out

    async def stage_ct(self, target: TargetProfile, cands: dict[str, Candidate]) -> int:
        """
        Discover lookalikes through Certificate Transparency logs.

        Args:
            target (TargetProfile): Target profile.
            cands (dict[str, Candidate]): Candidate map (updated in place).
        Returns:
            int: Number of newly discovered candidates.
        """
        if self.s.fast or not self.s.ct_enabled:
            return 0
        if len(target.name) < 4:
            self.r.note("CT keyword search skipped: brand keyword shorter than 4 characters", "warn")
            return 0
        self.r.stage("ct", "Searching Certificate Transparency logs", None)
        found = await self.ct.search_keyword(target.name, self.resources.psl().registrable)
        added = 0
        for reg, info in found.items():
            if reg == target.ascii:
                continue
            label = self.resources.psl().split(reg)[1]
            try:
                ulabel = idna.decode(label) if label.startswith("xn--") else label
            except idna.IDNAError:
                ulabel = label
            if not similarity.is_near(ulabel, target.name):
                continue
            cand = cands.get(reg)
            if cand is None:
                cand = self.make_candidate(reg, target, {"ct"})
                if cand is None:
                    continue
                cands[reg] = cand
                added += 1
            else:
                cand.fuzzers.add("ct")
            cand.ct = info
        msg = f"{len(found)} domains in CT logs, {added} new lookalikes"
        if self.ct.error:
            msg += f" (crt.sh: {self.ct.error[:60]})"
        self.r.done("ct", msg)
        return added

    async def stage_dns(self, items: list[Candidate], title: str = "DNS sweep") -> None:
        """
        Resolve every candidate (NS first, then A/AAAA/MX when registered).

        Args:
            items (list[Candidate]): Candidates (updated in place).
            title (str): Stage title for the UI.
        Returns:
            None
        """
        if not items:
            return
        self.r.stage("dns", title, len(items))
        found = 0

        async def one(c: Candidate) -> None:
            """
            Probe one candidate.

            Args:
                c (Candidate): Candidate.
            Returns:
                None
            """
            nonlocal found
            c.dns = await self.dns.probe(c.ascii, c.suffix)
            if c.dns.status == "registered":
                found += 1
            self.r.advance("dns", info=f"{found} registered")

        await asyncio.gather(*(one(c) for c in items))
        retry = [c for c in items if c.dns.status == "unknown" and not c.dns.wildcard_tld]
        if retry:  # timeouts under load: retry gently (definitive answers are cached)
            self.r.advance("dns", 0, info=f"retrying {len(retry)} timeouts")
            sem = asyncio.Semaphore(40)

            async def again(c: Candidate) -> None:
                """
                Re-probe one candidate with low concurrency.

                Args:
                    c (Candidate): Candidate.
                Returns:
                    None
                """
                nonlocal found
                async with sem:
                    c.dns = await self.dns.probe(c.ascii, c.suffix)
                if c.dns.status == "registered":
                    found += 1

            await asyncio.gather(*(again(c) for c in retry))
        unknown = sum(1 for c in items if c.dns.status == "unknown")
        self.r.done("dns", f"{found} registered, {unknown} unverified, {self.dns.queries:,} queries")

    async def enrich_web(self, c: Candidate, target: TargetProfile) -> None:
        """
        Fetch and analyse a candidate website, then compare its brand images.

        Args:
            c (Candidate): Candidate (needs A/AAAA records or unknown status).
            target (TargetProfile): Target profile.
        Returns:
            None
        """
        page = await self.fetcher.fetch(c.ascii, target.ascii, target.brand_terms)
        c.page = page
        if parking_nameservers(c.dns.ns) and not page.parked and len(page.text) < 3000:
            page.parked = True
            page.parking_reasons.append("parking name servers")
        if page.reachable and target.logos:
            fps = await self.visual.fingerprint_page(page.icon_urls, page.image_urls)
            c.visual = self.visual.compare(target.logos, fps) if fps else VisualMatch()

    async def enrich_extra(self, c: Candidate) -> None:
        """
        Per-domain CT search (deep mode) and urlscan.io lookup.

        Args:
            c (Candidate): Candidate.
        Returns:
            None
        """
        if self.s.deep and c.ct is None and self.ct.available:
            c.ct = await self.ct.search_domain(c.ascii, self.resources.psl().registrable)
        if self.urlscan.enabled and (self.s.urlscan_api_key or self.s.deep):
            c.urlscan = await self.urlscan.search(c.ascii)

    async def stage_enrich(self, target: TargetProfile, cands: list[Candidate]) -> None:
        """
        Enrich every registered / unverified candidate.

        Registration lookups, web analysis and extra lookups run in three
        independent pools at the same time: slow, strictly rate-limited
        WHOIS servers never block page fetches (and vice versa), so the stage
        lasts as long as the slowest pool rather than their sum.

        Args:
            target (TargetProfile): Target profile.
            cands (list[Candidate]): Candidates to enrich.
        Returns:
            None
        """
        cands = sorted(cands, key=lambda c: -c.lexical)  # best candidates first
        web = [c for c in cands if c.dns.ips or c.dns.status == "unknown"]
        # crt.sh / urlscan are slow shared services: only the most similar
        # candidates get per-domain lookups
        extra = cands[:15] if (self.s.deep or (self.urlscan.enabled and self.s.urlscan_api_key)) else []
        self.r.stage("enrich", "RDAP/WHOIS, web content, logos", len(cands) + len(web) + len(extra))

        async def guarded(c: Candidate, coro: Any, budget: float = 150.0) -> None:
            """
            Run one enrichment step with a hard time budget, never letting
            errors escape (one hostile host must not stall the scan).

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
            self.r.advance("enrich", info=c.domain[:40])

        async def registration(c: Candidate) -> None:
            """
            RDAP/WHOIS lookup of one candidate.

            Args:
                c (Candidate): Candidate.
            Returns:
                None
            """
            c.registration = await self.registry.lookup(c.ascii, c.suffix)

        await asyncio.gather(
            # registration lookups queue on per-server limiters: generous budget
            self.gather_limited([guarded(c, registration(c), 300) for c in cands], 24),
            self.gather_limited([guarded(c, self.enrich_web(c, target), 100) for c in web],
                                self.s.http_concurrency),
            self.gather_limited([guarded(c, self.enrich_extra(c), 200) for c in extra], 4),
        )
        online = sum(1 for c in cands if c.page and c.page.reachable)
        self.r.done("enrich", f"{len(cands)} enriched, {online} websites online")
        for server in sorted(self.registry.down):
            self.r.note(f"WHOIS server {server} stopped answering (rate limit): registration data is partial", "warn")
        for server in sorted(self.registry.budget_hit - self.registry.down):
            self.r.note(f"WHOIS budget reached for {server} (--whois-limit {self.s.whois_limit}); "
                        "remaining lookups skipped to avoid a ban", "warn")

    async def stage_abuse(self, cands: list[Candidate]) -> None:
        """
        Query AbuseIPDB for the hosting IPs (deduplicated, most similar first).

        Args:
            cands (list[Candidate]): Registered candidates.
        Returns:
            None
        """
        if not self.abuse.enabled:
            return
        ips: list[str] = []
        for c in sorted(cands, key=lambda x: -x.lexical):
            for ip in c.dns.a[:2]:
                if ip not in ips:
                    ips.append(ip)
        ips = ips[: self.s.abuse_limit]
        if not ips:
            return
        self.r.stage("abuse", "AbuseIPDB reputation", len(ips))
        reports: dict[str, Any] = {}

        async def one(ip: str) -> None:
            """
            Check one IP.

            Args:
                ip (str): IP address.
            Returns:
                None
            """
            reports[ip] = await self.abuse.check(ip)
            self.r.advance("abuse", info=ip)

        await self.gather_limited([one(ip) for ip in ips], 4)
        for c in cands:
            c.abuse = [reports[ip] for ip in c.dns.a[:2] if reports.get(ip)]
        bad = sum(1 for r in reports.values() if r and r.score >= 25)
        self.r.done("abuse", f"{len(ips)} IPs checked, {bad} with abuse reports")

    async def stage_nlp(self, target: TargetProfile, cands: list[Candidate]) -> None:
        """
        Text similarity (TF-IDF, plus embeddings in deep mode).

        Args:
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
        self.r.stage("nlp", "NLP content similarity", None)
        index = TfidfIndex(docs)
        for c in cands:
            if c.ascii in docs:
                c.text_similarity = index.similarity("__target__", c.ascii)
        summary = f"{len(docs) - 1} pages compared (TF-IDF)"
        if self.s.deep:
            self.embedder = EmbeddingModel()
            if await self.embedder.load():
                others = {k: v for k, v in docs.items() if k != "__target__"}
                sims = await self.embedder.similarities(docs["__target__"], others)
                for c in cands:
                    if c.ascii in sims:
                        c.semantic_similarity = sims[c.ascii]
                summary += " + multilingual embeddings"
            else:
                self.r.note(f"embeddings disabled: {self.embedder.error}", "warn")
        self.r.done("nlp", summary)

    async def ensure_browser(self) -> bool:
        """
        Start Playwright, installing Chromium automatically if missing.

        Returns:
            bool: True when screenshots are available.
        """
        self.screens = Screenshotter(self.out_dir / "screenshots", self.s)
        if await self.screens.start():
            return True
        if self.screens.error and "playwright not installed" not in self.screens.error:
            self.r.note("downloading headless Chromium for screenshots (one-time)...", "info")
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "playwright", "install", "chromium",
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            await proc.wait()
            self.screens = Screenshotter(self.out_dir / "screenshots", self.s)
            if await self.screens.start():
                return True
        self.r.note(f"screenshots disabled: {self.screens.error}", "warn")
        return False

    async def stage_screenshots(self, target: TargetProfile, cands: list[Candidate], limit: int = 30) -> None:
        """
        Deep mode: screenshot target and top candidates, compare visually.

        Args:
            target (TargetProfile): Target profile.
            cands (list[Candidate]): Candidates sorted by preliminary score.
            limit (int): Maximum candidate screenshots.
        Returns:
            None
        """
        online = [c for c in cands if c.page and c.page.reachable][:limit]
        if not online or not await self.ensure_browser():
            return
        assert self.screens is not None
        self.r.stage("shots", "Screenshots & visual diff", len(online) + 1)
        tpath = await self.screens.capture(target.page.final_url if target.page and target.page.final_url
                                           else f"https://{target.ascii}/", safe_name(target.ascii))
        target.screenshot_path = str(tpath) if tpath else None
        self.r.advance("shots", info=target.domain)
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
            path = await self.screens.capture(c.page.final_url or f"https://{c.ascii}/", safe_name(c.ascii))
            if path:
                c.visual = c.visual or VisualMatch()
                c.visual.screenshot_path = str(path)
                img = load_image(path.read_bytes())
                if img is not None and thash:
                    dp = (phash(img) ^ thash[0]).bit_count()
                    dd = (dhash(img) ^ thash[1]).bit_count()
                    c.visual.screenshot_similarity = round(1 - (0.6 * dp + 0.4 * dd) / 64, 4)
            self.r.advance("shots", info=c.domain[:40])

        await self.gather_limited([one(c) for c in online], 3)
        await self.screens.close()
        self.r.done("shots", f"{len(online)} pages captured")

    async def stage_virustotal(self, cands: list[Candidate]) -> None:
        """
        Query VirusTotal for the highest-scoring registered candidates.

        Args:
            cands (list[Candidate]): Registered candidates sorted by score.
        Returns:
            None
        """
        if not self.vt.enabled or self.s.vt_limit <= 0:
            return
        todo = cands[: self.s.vt_limit]
        if not todo:
            return
        eta = len(todo) * 60 / max(self.s.vt_rate_per_min, 0.1)
        self.r.stage("vt", f"VirusTotal (quota-paced, up to ~{eta / 60:.0f} min)", len(todo))

        async def one(c: Candidate) -> None:
            """
            Fetch one VirusTotal report.

            Args:
                c (Candidate): Candidate.
            Returns:
                None
            """
            if self.vt.enabled:
                c.vt = await self.vt.domain(c.ascii)
            self.r.advance("vt", info=c.domain[:40])

        await self.gather_limited([one(c) for c in todo], 2)
        flagged = sum(1 for c in todo if c.vt and c.vt.malicious)
        msg = f"{len(todo)} domains checked, {flagged} flagged"
        if self.vt.disabled_reason:
            msg += f" (stopped: {self.vt.disabled_reason})"
        self.r.done("vt", msg)

    # ------------------------------------------------------------------- main
    async def run(self, raw_target: str) -> ScanResult:
        """
        Execute the whole pipeline.

        Args:
            raw_target (str): Domain or URL supplied by the user.
        Returns:
            ScanResult: Ranked candidates and scan metadata.
        Raises:
            InputError: When the target is not a valid domain.
        """
        t0 = time.monotonic()
        started = utcnow()
        try:
            await self.stage_resources()
            target = await self.stage_target(raw_target)
            result = ScanResult(target=target, started=started)
            cands = self.stage_generate(target)
            result.generated = self._generated
            first_wave = list(cands.values())
            # CT discovery (slow, remote) runs while the DNS sweep resolves
            # the generated candidates; its discoveries are resolved after.
            ct_task = asyncio.create_task(self.stage_ct(target, cands))
            await self.stage_dns(first_wave)
            ct_added = await ct_task
            result.discovered = len(cands) - self._generated
            if ct_added:
                seen = {id(c) for c in first_wave}
                await self.stage_dns([c for c in cands.values() if id(c) not in seen], "DNS sweep (CT discoveries)")

            scorer = Scorer(target)
            all_cands = list(cands.values())
            to_enrich = [c for c in all_cands if c.dns.status in ("registered", "unknown")]
            if not self.s.fast:
                await self.stage_enrich(target, to_enrich)
                registered = [c for c in to_enrich if c.registered]
                await self.stage_abuse(registered)
                await self.stage_nlp(target, registered)
                for c in registered:
                    scorer.score(c)
                registered.sort(key=lambda c: (-c.score, -c.lexical))
                if self.s.deep:
                    await self.stage_screenshots(target, registered)
                    for c in registered:
                        scorer.score(c)
                    registered.sort(key=lambda c: (-c.score, -c.lexical))
                await self.stage_virustotal([c for c in registered if c.category != "DEFENSIVE"])
            for c in all_cands:
                scorer.score(c)
            all_cands.sort(key=lambda c: (-c.score, -c.lexical, c.domain))
            result.candidates = all_cands
            result.services = self.service_status()
            result.duration = time.monotonic() - t0
            result.stats = {
                "dns_queries": self.dns.queries,
                "http_requests": self.http.requests_sent,
                "bytes_downloaded": self.http.bytes_received,
                "cache_hits": self.cache.hits,
                "cache_misses": self.cache.misses,
                "vt_calls": self.vt.used,
                "abuseipdb_calls": self.abuse.used,
            }
            result.settings = {
                "profile": self.s.profile, "tld_mode": self.s.tld_mode, "keyboard": self.s.keyboard,
                "vt_limit": self.s.vt_limit, "abuse_limit": self.s.abuse_limit,
            }
            return result
        finally:
            if self.screens is not None:
                await self.screens.close()
            await self.http.close()
            self.cache.close()

    def service_status(self) -> dict[str, str]:
        """
        Human readable status of every external service.

        Returns:
            dict[str, str]: Service -> "on", "off: <reason>" or "error: ...".
        """
        status = {
            "VirusTotal": "on" if self.vt.enabled else f"off: {self.vt.disabled_reason}",
            "AbuseIPDB": "on" if self.abuse.enabled else f"off: {self.abuse.disabled_reason}",
            "crt.sh": ("off: fast profile" if self.s.fast else
                       f"error: {self.ct.error[:50]}" if self.ct.error else "on"),
            "urlscan.io": ("on" if (self.s.urlscan_api_key or self.s.deep) and self.urlscan.enabled
                           else "off: no API key (URLSCAN_API_KEY) or --deep"),
            "Threat feeds": f"on ({len(self.resources.feed_hosts()):,} hosts)",
            "RDAP/WHOIS": ("off: fast profile" if self.s.fast else
                           f"error: blocked by {', '.join(sorted(self.registry.down))}" if self.registry.down
                           else "on"),
        }
        if self.s.deep:
            status["Screenshots"] = "on" if self.screens and not self.screens.error else \
                f"off: {self.screens.error if self.screens else 'no online candidates'}"
            status["Embeddings"] = "on" if self.embedder and not self.embedder.error else \
                f"off: {self.embedder.error if self.embedder else 'not needed'}"
        return status
