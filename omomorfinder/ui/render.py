"""
Final report rendered in the terminal: banner, target card, service status,
summary, ranked tables with a "Why" column, explainable detail cards,
recommendations and run statistics.
"""

from __future__ import annotations

from collections import Counter

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from .. import __version__
from ..config import Settings
from ..models import Candidate, TargetProfile, utcnow
from ..pipeline import ScanResult
from .theme import (
    ACCENT,
    BANNER_NARROW,
    BANNER_WIDE,
    CATEGORY_STYLE,
    DIM,
    MUTED,
    PALETTE,
    RISK_STYLE,
    blend,
    gradient,
)
from .widgets import badge, human_age, policy_text, score_bar, signal_tags, why_text


class ResultRenderer:
    """
    Prints every part of the final terminal report.

    Args (constructor):
        console (Console): Rich console.
    """

    def __init__(self, console: Console) -> None:
        """
        Store the console.

        Args:
            console (Console): Rich console.
        Returns:
            None
        """
        self.console = console

    # ------------------------------------------------------------ header
    def banner(self, settings: Settings) -> None:
        """
        Print the gradient banner and the run configuration line.

        Args:
            settings (Settings): Scan configuration.
        Returns:
            None
        """
        art = BANNER_WIDE if self.console.width >= 106 else BANNER_NARROW
        self.console.print()
        self.console.print(Padding(gradient(art), (0, 1)))
        sub = Text("  ")
        sub.append("lookalike domain threat intelligence", style=f"italic {MUTED}")
        sub.append("   v" + __version__, style=f"bold {ACCENT}")
        sub.append("   profile ", style=MUTED)
        sub.append(settings.profile.upper(), style=f"bold {PALETTE[0]}")
        self.console.print(sub)
        self.console.print()

    def section(self, title: str) -> None:
        """
        Print a section separator.

        Args:
            title (str): Section title.
        Returns:
            None
        """
        self.console.print()
        self.console.print(Rule(gradient(f" {title} ", bold=True), style="grey27", characters="─"))

    # ------------------------------------------------------------ target
    def target(self, t: TargetProfile) -> None:
        """
        Print the target profile card.

        Args:
            t (TargetProfile): Target profile.
        Returns:
            None
        """
        self.section("TARGET")
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=f"bold {PALETTE[1]}", justify="right")
        grid.add_column()
        reg = t.registration
        grid.add_row("domain", Text(t.domain, style="bold white") + Text(
            f"  ({t.ascii})" if t.ascii != t.domain else "", style=MUTED))
        if reg:
            grid.add_row("registrar", reg.registrar or "-")
            owner = reg.registrant_org or reg.registrant_name or ("redacted" if reg.privacy else "-")
            grid.add_row("registrant", owner)
            created = reg.created.date().isoformat() if reg.created else "-"
            grid.add_row("created", f"{created}   [{MUTED}]via {reg.source.upper()}[/]")
        grid.add_row("name servers", ", ".join(t.dns.ns[:4]) or "-")
        grid.add_row("mail (MX)", ", ".join(t.dns.mx[:3]) or "-")
        grid.add_row("SPF", policy_text(t.dns.spf, "spf"))
        grid.add_row("DMARC", policy_text(t.dns.dmarc, "dmarc"))
        if t.page:
            grid.add_row("homepage", (t.page.title or "-")[:90] if t.page.reachable else
                         Text(f"unreachable ({t.page.error or 'n/a'})"[:90], style="#ff7b00"))
            grid.add_row("brand images", f"{len(t.logos)} fingerprinted" +
                         (f"   [{MUTED}]favicon mmh3[/] [bold]{t.favicon_mmh3}[/]" if t.favicon_mmh3 is not None else ""))
        grid.add_row("brand terms", ", ".join(t.brand_terms))
        self.console.print(Padding(grid, (1, 2, 0, 2)))

    def services(self, services: dict[str, str]) -> None:
        """
        Print the status of every external service.

        Args:
            services (dict[str, str]): Service -> status text.
        Returns:
            None
        """
        parts: list[Text] = []
        for name, status in services.items():
            on = status.startswith("on")
            dot = Text("● ", style="#2ec4b6" if on else ("#ff2e63" if status.startswith("error") else DIM))
            detail = status.split(": ", 1)[1] if ": " in status else ""
            parts.append(dot + Text(name, style="bold" if on else MUTED) +
                         Text(f"  {detail}" if detail else "", style=DIM))
        self.console.print(Padding(Columns(parts, padding=(0, 3)), (1, 2, 0, 2)))

    # ----------------------------------------------------------- summary
    def summary(self, result: ScanResult) -> None:
        """
        Print the category counters and headline numbers.

        Args:
            result (ScanResult): Scan result.
        Returns:
            None
        """
        self.section("SUMMARY")
        counts = Counter(c.category for c in result.candidates)
        pills = [badge(cat, CATEGORY_STYLE[cat]) + Text(f" {counts[cat]:,}", style="bold")
                 for cat in CATEGORY_STYLE if counts.get(cat)]
        head = Text.assemble(
            ("  analysed ", MUTED), (f"{len(result.candidates):,}", "bold"),
            ("  ·  generated ", MUTED), (f"{result.generated:,}", "bold"),
            ("  ·  discovered (CT/feeds) ", MUTED), (f"{result.discovered:,}", "bold"),
            ("  ·  registered ", MUTED), (f"{len(result.registered):,}", f"bold {PALETTE[0]}"),
        )
        self.console.print(Padding(head, (1, 0, 0, 0)))
        self.console.print(Padding(Columns(pills, padding=(0, 2)), (1, 2, 0, 2)))
        legend = Text.assemble(
            ("  danger index 0-100: ", MUTED), ("80+ CRITICAL", RISK_STYLE["CRITICAL"]), ("  ", ""),
            ("60+ HIGH", RISK_STYLE["HIGH"]), ("  ", ""), ("40+ MEDIUM", RISK_STYLE["MEDIUM"]), ("  ", ""),
            ("20+ LOW", RISK_STYLE["LOW"]), ("  ", ""), ("<20 INFO", RISK_STYLE["INFO"]),
        )
        self.console.print(Padding(legend, (1, 0, 0, 0)))

    # ------------------------------------------------------------ tables
    def table(self, rows: list[Candidate], title: str, start: int = 1) -> Table:
        """
        Ranked table: danger index, category and the reasons behind it.

        Args:
            rows (list[Candidate]): Candidates to show.
            title (str): Table title.
            start (int): Rank of the first row.
        Returns:
            Table: Rich table.
        """
        table = Table(
            title=Text(title, style=f"bold {PALETTE[0]}"), title_justify="left",
            box=box.SIMPLE_HEAD, header_style=f"bold {PALETTE[1]}", border_style="grey30",
            row_styles=["", "on #14161c"], expand=True, pad_edge=False,
        )
        table.add_column("#", justify="right", style=DIM, width=3, no_wrap=True)
        table.add_column("Domain · technique", ratio=4, overflow="fold")
        table.add_column("Danger", no_wrap=True, width=21)
        table.add_column("Category", no_wrap=True, width=12)
        table.add_column("Age", justify="right", no_wrap=True, width=5)
        table.add_column("Why", ratio=5, overflow="fold")
        for i, c in enumerate(rows, start):
            dom = Text(c.domain, style="bold white" if c.registered else "white")
            if c.ascii != c.domain:
                dom.append(f"\n{c.ascii}", style=DIM)
            for sd in [sd for sd in c.subdomains if sd.brand][:2]:
                dom.append(f"\n↳ {sd.name}", style="#ff7b00")
            dom.append("\n" + ", ".join(sorted(c.fuzzers))[:48], style=MUTED)
            tags = signal_tags(c)
            if tags.plain:
                dom.append("  ")
                dom.append_text(tags)
            age = c.registration.age_days if c.registration else None
            table.add_row(
                str(i), dom, score_bar(c.score, c.risk, width=8, show_risk=True),
                badge(c.category[:10], CATEGORY_STYLE.get(c.category, "")),
                human_age(age), why_text(c),
            )
        return table

    def results(self, result: ScanResult, top: int, show_available: int, min_score: int,
                show_all: bool = False) -> None:
        """
        Print the ranked threats and the best unregistered lookalikes.

        Args:
            result (ScanResult): Scan result.
            top (int): Max registered rows.
            show_available (int): Max unregistered rows (0 = hide).
            min_score (int): Hide rows below this score.
            show_all (bool): Show every candidate (ignores top/available).
        Returns:
            None
        """
        self.section("THREATS")
        active = [c for c in result.candidates if c.category != "AVAILABLE" and c.score >= min_score]
        limit = len(active) if show_all else top
        if active:
            self.console.print(self.table(active[:limit], f"Registered lookalikes  ({len(active)} total)"))
            if len(active) > limit:
                self.console.print(Text(f"  … {len(active) - limit} more (--top N or --all to show them, "
                                        "-o DIR to export)", style=MUTED))
        else:
            self.console.print(Padding(Text("No registered lookalike above the threshold.",
                                            style="bold #2ec4b6"), (1, 2)))
        free = sorted((c for c in result.candidates if c.category == "AVAILABLE"),
                      key=lambda c: (-c.homograph, -c.lexical))
        free_limit = len(free) if show_all else show_available
        if free and free_limit:
            self.console.print()
            self.console.print(self.table(free[:free_limit],
                                          f"Unregistered lookalikes worth a defensive registration  ({len(free)} total)"))

    # ----------------------------------------------------------- details
    def details(self, cands: list[Candidate]) -> None:
        """
        Print explainable detail cards (facts + full score breakdown).

        Args:
            cands (list[Candidate]): Candidates to detail.
        Returns:
            None
        """
        if not cands:
            return
        self.section("DETAILS")
        for c in cands:
            body = Table.grid(expand=True, padding=(0, 3))
            body.add_column(ratio=1)
            body.add_column(ratio=1)
            body.add_row(self._facts(c), self._breakdown(c))
            title = Text.assemble((f" {c.domain} ", "bold white"), " ",
                                  badge(c.category, CATEGORY_STYLE.get(c.category, "")),
                                  " ", score_bar(c.score, c.risk, show_risk=True), " ")
            self.console.print(Panel(body, title=title, title_align="left",
                                     border_style=blend(PALETTE, c.score / 100), box=box.ROUNDED, padding=(1, 2)))

    @staticmethod
    def _facts(c: Candidate) -> Table:
        """
        Left column of a detail card: what was observed.

        Args:
            c (Candidate): Candidate.
        Returns:
            Table: Key/value grid.
        """
        facts = Table.grid(padding=(0, 2))
        facts.add_column(style=f"bold {PALETTE[1]}", justify="right", no_wrap=True)
        facts.add_column(overflow="fold")
        reg, p, v = c.registration, c.page, c.visual
        facts.add_row("ascii", c.ascii)
        facts.add_row("ips", ", ".join(c.dns.ips[:4]) or "-")
        if c.abuse:
            facts.add_row("hosting", ", ".join(f"{a.isp or '?'} [{a.country or '?'}] abuse {a.score}" for a in c.abuse[:2]))
        facts.add_row("ns", ", ".join(c.dns.ns[:3]) or "-")
        facts.add_row("mx", ", ".join(c.dns.mx[:3]) or "-")
        if reg:
            facts.add_row("registrar", reg.registrar or "-")
            facts.add_row("registrant", reg.registrant_org or reg.registrant_name or ("redacted" if reg.privacy else "-"))
            facts.add_row("created", reg.created.date().isoformat() if reg.created else "-")
        if p and p.reachable and not p.filtered:
            facts.add_row("final url", (p.final_url or "-")[:100])
            facts.add_row("title", (p.title or "-")[:100])
            if p.phishing_keywords:
                facts.add_row("lexicon", ", ".join(p.phishing_keywords[:6]))
            if p.parking_reasons:
                facts.add_row("parking", "; ".join(p.parking_reasons[:3]))
        elif p and p.error:
            facts.add_row("web", Text(p.error[:100], style=MUTED))
        if c.subdomains or c.wildcard_dns:
            facts.add_row("subdomains", ResultRenderer._subdomains(c))
        if v and v.matched_url:
            facts.add_row("logo match", f"{v.logo_similarity:.0%}  {v.matched_url[:80]}")
        if v and v.screenshot_path:
            facts.add_row("screenshot", v.screenshot_path)
        if c.vt and not c.vt.error:
            facts.add_row("virustotal", f"{c.vt.malicious} malicious / {c.vt.suspicious} suspicious, rep {c.vt.reputation}")
        if c.ct and c.ct.count:
            last = c.ct.last_seen.date().isoformat() if c.ct.last_seen else "?"
            facts.add_row("ct logs", f"{c.ct.count} certs, latest {last} ({', '.join(c.ct.issuers[:2])})")
        if c.urlscan and c.urlscan.result_url:
            facts.add_row("urlscan", c.urlscan.result_url)
        return facts

    @staticmethod
    def _subdomains(c: Candidate, limit: int = 8) -> Text:
        """
        Subdomain list with brand / credential markers.

        Args:
            c (Candidate): Candidate.
            limit (int): Maximum subdomains listed.
        Returns:
            Text: One subdomain per line.
        """
        out = Text()
        if c.wildcard_dns:
            out.append("wildcard DNS (*." + c.ascii + ")", style="#ffd000")
        ranked = sorted(c.subdomains, key=lambda s: (not s.brand, not s.credential, s.name))
        for sd in ranked[:limit]:
            if out.plain:
                out.append("\n")
            style = "#ff2e63" if sd.brand else ("#ff7b00" if sd.credential else "white")
            out.append(sd.name, style=style)
            marks = [m for m, on in (("brand", sd.brand), ("credential", sd.credential)) if on]
            meta = ", ".join([*marks, "/".join(sorted(sd.sources))] + ([sd.ips[0]] if sd.ips else []))
            out.append(f"  {meta}", style=DIM)
        if len(ranked) > limit:
            out.append(f"\n… {len(ranked) - limit} more", style=DIM)
        return out

    @staticmethod
    def _breakdown(c: Candidate) -> Table:
        """
        Right column of a detail card: every point of the score, explained.

        Args:
            c (Candidate): Candidate.
        Returns:
            Table: Points / group / reason grid.
        """
        why = Table.grid(padding=(0, 1))
        why.add_column(justify="right", no_wrap=True, width=6)
        why.add_column(style=MUTED, no_wrap=True, width=12)
        why.add_column(overflow="fold")
        for item in sorted(c.breakdown, key=lambda i: -abs(i.points)):
            pts = Text(f"{item.points:+.0f}", style="bold #2ec4b6" if item.points < 0 else "bold #ff7b00")
            why.add_row(pts, item.group, item.label)
        if not c.breakdown:
            why.add_row("", "", Text("no significant signal", style=MUTED))
        return why

    # --------------------------------------------------- recommendations
    def recommendations(self, result: ScanResult) -> None:
        """
        Print actionable recommendations derived from the findings.

        Args:
            result (ScanResult): Scan result.
        Returns:
            None
        """
        t = result.target
        cands = result.candidates
        recs: list[tuple[str, str]] = []

        def listing(items: list[str], n: int = 6) -> str:
            """
            Join the first items, with an ellipsis when truncated.

            Args:
                items (list[str]): Items.
                n (int): Maximum items shown.
            Returns:
                str: Comma separated list.
            """
            return ", ".join(items[:n]) + (" …" if len(items) > n else "")

        # domains found only because one of their subdomains abuses the brand
        # (often shared hosting) go into the "hosts to block" list instead
        only_sub = {c.ascii for c in cands if c.fuzzers <= {"brand-subdomain", "ct"} and "brand-subdomain" in c.fuzzers}
        malicious = [c.domain for c in cands if c.category == "MALICIOUS" and c.ascii not in only_sub]
        suspicious = [c.domain for c in cands if c.category == "SUSPICIOUS"]
        brand_hosts = [sd.name for c in cands if c.category != "DEFENSIVE" for sd in c.subdomains if sd.brand]
        mail = [c.domain for c in cands if c.registered and c.dns.mx and c.category != "DEFENSIVE"]
        free = [c.domain for c in sorted(cands, key=lambda x: (-x.homograph, -x.lexical)) if c.category == "AVAILABLE"]
        if malicious:
            recs.append(("#ff2e63", f"Request takedown and block at proxy/DNS level: {listing(malicious)}"))
        if brand_hosts:
            recs.append(("#ff2e63", f"Block hosts impersonating the brand in a subdomain: {listing(brand_hosts)}"))
        if suspicious:
            recs.append(("#ff7b00", f"Monitor closely (content may switch to phishing): {listing(suspicious)}"))
        if mail:
            recs.append(("#ffd000", f"Add mail-enabled lookalikes to the e-mail gateway blocklist ({len(mail)}): "
                         f"{listing(mail, 5)}"))
        if not t.dns.dmarc or "p=none" in (t.dns.dmarc or "").lower().replace(" ", ""):
            recs.append(("#ffd000", f"Publish an enforcing DMARC policy for {t.domain} (p=quarantine or p=reject)"))
        if not t.dns.spf:
            recs.append(("#ffd000", f"Publish an SPF record ending in -all for {t.domain}"))
        if free:
            recs.append(("#4cc9f0", f"Consider defensive registration of: {listing(free)}"))
        if t.favicon_mmh3 is not None:
            recs.append(("#4cc9f0", f"Hunt clones on Shodan: http.favicon.hash:{t.favicon_mmh3}"))
        if not recs:
            return
        self.section("RECOMMENDATIONS")
        grid = Table.grid(padding=(0, 1))
        grid.add_column(no_wrap=True)
        grid.add_column(overflow="fold")
        for color, text in recs:
            grid.add_row(Text("▸", style=f"bold {color}"), text)
        self.console.print(Padding(grid, (1, 2, 0, 2)))

    # ------------------------------------------------------------ footer
    def footer(self, result: ScanResult, outputs: list[str]) -> None:
        """
        Print run statistics and exported files.

        Args:
            result (ScanResult): Scan result.
            outputs (list[str]): Paths of exported files.
        Returns:
            None
        """
        st = result.stats
        hits, misses = st.get("cache_hits", 0), st.get("cache_misses", 0)
        ratio = hits / max(hits + misses, 1)
        line = Text.assemble(
            ("  ◆ ", PALETTE[0]), (f"{result.duration:.1f}s", "bold"),
            ("   dns ", MUTED), (f"{st.get('dns_queries', 0):,}", "bold"),
            ("   http ", MUTED), (f"{st.get('http_requests', 0):,}", "bold"),
            ("   downloaded ", MUTED), (f"{st.get('bytes_downloaded', 0) / 1_048_576:.1f} MB", "bold"),
            ("   cache hit ", MUTED), (f"{ratio:.0%}", "bold"),
            ("   finished ", MUTED), (utcnow().strftime("%Y-%m-%d %H:%M UTC"), "bold"),
        )
        self.console.print()
        self.console.print(Rule(style="grey27"))
        self.console.print(line)
        for path in outputs:
            self.console.print(Text.assemble(("  ↳ ", PALETTE[2]), ("export  ", MUTED),
                                             (path, f"bold {PALETTE[0]} underline")))
        self.console.print()
