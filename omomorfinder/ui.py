"""
Terminal user interface built on `rich`.

Design goals: a cohesive cyan -> violet -> magenta palette, gradient
banner, live multi-stage progress, badge-style categories, compact signal
tags, explainable detail cards and actionable recommendations. Colours are
semantic (red = malicious, orange = suspicious, teal = defensive, ...) so
the eye can triage the table at a glance. No emoji, only geometric glyphs.
"""

from __future__ import annotations

import time
from collections import Counter
from contextlib import contextmanager
from collections.abc import Iterator

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.padding import Padding
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from . import __version__
from .config import Settings
from .engine import ScanResult
from .models import Candidate, TargetProfile, utcnow

PALETTE: tuple[str, ...] = ("#00e5ff", "#4f8bff", "#9b5cff", "#ff4fd8")
ACCENT = "#9b5cff"
MUTED = "grey58"

CATEGORY_STYLE: dict[str, str] = {
    "MALICIOUS": "bold white on #d7263d",
    "SUSPICIOUS": "bold black on #ff9f1c",
    "PARKED": "bold black on #e9c46a",
    "COMPETITOR": "bold white on #3a86ff",
    "REGISTERED": "bold white on #5c677d",
    "DEFENSIVE": "bold black on #2ec4b6",
    "UNVERIFIED": "bold white on #495057",
    "AVAILABLE": "#ced4da on #2b2d42",
}
RISK_STYLE: dict[str, str] = {
    "CRITICAL": "bold #ff2e63", "HIGH": "bold #ff7b00", "MEDIUM": "bold #ffd000",
    "LOW": "#4cc9f0", "INFO": MUTED,
}
RISK_BAR: dict[str, str] = {
    "CRITICAL": "#ff2e63", "HIGH": "#ff7b00", "MEDIUM": "#ffd000", "LOW": "#4cc9f0", "INFO": "grey42",
}

_BANNER_WIDE = r"""
 ██████╗ ███╗   ███╗ ██████╗ ███╗   ███╗ ██████╗ ██████╗ ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗
██╔═══██╗████╗ ████║██╔═══██╗████╗ ████║██╔═══██╗██╔══██╗██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
██║   ██║██╔████╔██║██║   ██║██╔████╔██║██║   ██║██████╔╝█████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
██║   ██║██║╚██╔╝██║██║   ██║██║╚██╔╝██║██║   ██║██╔══██╗██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
╚██████╔╝██║ ╚═╝ ██║╚██████╔╝██║ ╚═╝ ██║╚██████╔╝██║  ██║██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
 ╚═════╝ ╚═╝     ╚═╝ ╚═════╝ ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
""".strip("\n")

_BANNER_NARROW = r"""
  ____                            _____         __
 / __ \__ _  ___  __ _  ___  ____/ __(_)__  ___/ /__ ____
/ /_/ /  ' \/ _ \/  ' \/ _ \/ __/ _// / _ \/ _  / -_) __/
\____/_/_/_/\___/_/_/_/\___/_/ /_/ /_/_//_/\_,_/\__/_/
""".strip("\n")


def _hex_to_rgb(color: str) -> tuple[int, int, int]:
    """
    Convert "#rrggbb" to an RGB tuple.

    Args:
        color (str): Hex colour.
    Returns:
        tuple[int, int, int]: Red, green, blue (0-255).
    """
    c = color.lstrip("#")
    return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)


def blend(colors: tuple[str, ...], t: float) -> str:
    """
    Interpolate along a multi-stop colour gradient.

    Args:
        colors (tuple[str, ...]): Hex colour stops.
        t (float): Position in [0, 1].
    Returns:
        str: Interpolated "#rrggbb" colour.
    """
    t = min(max(t, 0.0), 1.0)
    seg = t * (len(colors) - 1)
    i = min(int(seg), len(colors) - 2)
    f = seg - i
    a, b = _hex_to_rgb(colors[i]), _hex_to_rgb(colors[i + 1])
    r, g, bl = (round(x + (y - x) * f) for x, y in zip(a, b))
    return f"#{r:02x}{g:02x}{bl:02x}"


def gradient(text: str, colors: tuple[str, ...] = PALETTE, bold: bool = True) -> Text:
    """
    Colour multi-line text with a horizontal gradient.

    Args:
        text (str): Text (may contain newlines).
        colors (tuple[str, ...]): Gradient stops.
        bold (bool): Bold glyphs.
    Returns:
        Text: Styled rich Text.
    """
    lines = text.splitlines() or [text]
    width = max((len(l) for l in lines), default=1) or 1
    out = Text()
    for n, line in enumerate(lines):
        for x, ch in enumerate(line):
            style = f"{'bold ' if bold else ''}{blend(colors, x / max(width - 1, 1))}"
            out.append(ch, style=style)
        if n < len(lines) - 1:
            out.append("\n")
    return out


def badge(label: str, style: str) -> Text:
    """
    Pill-shaped badge.

    Args:
        label (str): Badge text.
        style (str): Rich style.
    Returns:
        Text: " LABEL " styled.
    """
    return Text(f" {label} ", style=style)


def score_bar(score: int, risk: str, width: int = 10) -> Text:
    """
    Compact segmented score bar with the numeric value.

    Args:
        score (int): Score 0-100.
        risk (str): Risk level (bar colour).
        width (int): Number of segments.
    Returns:
        Text: e.g. "▰▰▰▰▰▰▱▱▱▱  63".
    """
    filled = round(score / 100 * width)
    t = Text()
    t.append("▰" * filled, style=RISK_BAR.get(risk, "white"))
    t.append("▱" * (width - filled), style="grey30")
    t.append(f" {score:>3}", style=RISK_STYLE.get(risk, "white"))
    return t


def human_age(days: int | None) -> str:
    """
    Short human readable age.

    Args:
        days (int | None): Age in days.
    Returns:
        str: "12d", "5mo", "3y" or "-".
    """
    if days is None:
        return "-"
    if days < 60:
        return f"{days}d"
    if days < 730:
        return f"{days // 30}mo"
    return f"{days // 365}y"


def signal_tags(c: Candidate) -> Text:
    """
    Compact coloured tags summarising the strongest signals.

    Args:
        c (Candidate): Scored candidate.
    Returns:
        Text: e.g. "feed  VT 4  login  logo 97%  MX".
    """
    tags: list[tuple[str, str]] = []
    if c.feeds:
        tags.append(("feed", "bold #ff2e63"))
    elif c.feed_subdomains:
        tags.append(("feed:sub", "#ff7b00"))
    if c.page and c.page.filtered:
        tags.append(("filtered", "#ff7b00"))
    if c.vt and c.vt.malicious:
        tags.append((f"VT {c.vt.malicious}", "bold #ff2e63"))
    if c.urlscan and c.urlscan.malicious:
        tags.append(("urlscan", "bold #ff2e63"))
    p, v = c.page, c.visual
    if p and p.has_password:
        tags.append(("password", "#ff7b00"))
    elif p and p.has_login_form:
        tags.append(("login", "#ff7b00"))
    if v and v.favicon_match:
        tags.append(("favicon=", "#ff7b00"))
    elif v and v.logo_similarity >= 0.85:
        tags.append((f"logo {v.logo_similarity:.0%}", "#ff7b00"))
    if v and v.screenshot_similarity >= 0.85:
        tags.append((f"look {v.screenshot_similarity:.0%}", "#ff7b00"))
    if p and p.brand_mentions:
        tags.append(("brand", "#ffd000"))
    sim = max(c.text_similarity, c.semantic_similarity or 0)
    if sim >= 0.35:
        tags.append((f"text {sim:.0%}", "#ffd000"))
    if c.dns.mx:
        tags.append(("MX", "#4cc9f0"))
    if c.max_abuse >= 25:
        tags.append((f"abuse {c.max_abuse}", "#ff7b00"))
    if c.ct and c.ct.count:
        tags.append(("CT", "#4cc9f0"))
    if p and p.parked:
        tags.append(("parked", "#e9c46a"))
    if p and p.reachable and not p.parked and not tags:
        tags.append(("web", MUTED))
    if c.homograph:
        tags.append(("homograph", "#ff4fd8"))
    if c.ascii != c.domain:
        tags.append(("IDN", "#ff4fd8"))
    out = Text()
    for i, (label, style) in enumerate(tags[:7]):
        if i:
            out.append(" ")
        out.append(label, style=style)
    return out


class TerminalUI:
    """
    Rich-based implementation of the engine `Reporter` protocol plus every
    result renderer.

    Args (constructor):
        console (Console): Rich console.
        quiet (bool): Suppress progress output.
    """

    def __init__(self, console: Console, quiet: bool = False) -> None:
        """
        Initialise UI state.

        Args:
            console (Console): Rich console.
            quiet (bool): When True, only final results are printed.
        Returns:
            None
        """
        self.console = console
        self.quiet = quiet
        self.progress: Progress | None = None
        self._tasks: dict[str, TaskID] = {}
        self._titles: dict[str, str] = {}
        self._started: dict[str, float] = {}

    # ------------------------------------------------------------ header
    def banner(self, settings: Settings) -> None:
        """
        Print the gradient banner and the run configuration line.

        Args:
            settings (Settings): Scan configuration.
        Returns:
            None
        """
        art = _BANNER_WIDE if self.console.width >= 106 else _BANNER_NARROW
        self.console.print()
        self.console.print(Padding(gradient(art), (0, 1)))
        sub = Text("  ")
        sub.append("lookalike domain threat intelligence", style=f"italic {MUTED}")
        sub.append("   v" + __version__, style=f"bold {ACCENT}")
        sub.append("   profile ", style=MUTED)
        sub.append(settings.profile.upper(), style="bold #00e5ff")
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

    # --------------------------------------------------------- progress
    @contextmanager
    def live(self) -> Iterator[None]:
        """
        Context manager showing the live progress display.

        Returns:
            Iterator[None]: Yields while the display is active.
        """
        if self.quiet:
            yield
            return
        self.progress = Progress(
            SpinnerColumn("dots12", style=ACCENT),
            TextColumn("[bold]{task.description:<38}"),
            BarColumn(bar_width=32, style="grey23", complete_style=PALETTE[1], finished_style=PALETTE[0],
                      pulse_style=PALETTE[2]),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TextColumn("[grey58]{task.fields[info]}"),
            console=self.console,
            transient=True,
            refresh_per_second=12,
        )
        with self.progress:
            yield
        self.progress = None

    def stage(self, key: str, title: str, total: int | None = None) -> None:
        """
        Open a progress stage (Reporter protocol).

        Args:
            key (str): Stage identifier.
            title (str): Stage title.
            total (int | None): Steps, None for indeterminate.
        Returns:
            None
        """
        self._titles[key] = title
        self._started[key] = time.monotonic()
        if self.progress is not None:
            self._tasks[key] = self.progress.add_task(title, total=total, info="")

    def advance(self, key: str, n: int = 1, info: str = "") -> None:
        """
        Advance a stage (Reporter protocol).

        Args:
            key (str): Stage identifier.
            n (int): Steps done.
            info (str): Live detail text.
        Returns:
            None
        """
        if self.progress is not None and key in self._tasks:
            self.progress.update(self._tasks[key], advance=n, info=info[:48])

    def done(self, key: str, summary: str = "") -> None:
        """
        Close a stage and print its summary line (Reporter protocol).

        Args:
            key (str): Stage identifier.
            summary (str): Summary text.
        Returns:
            None
        """
        elapsed = time.monotonic() - self._started.get(key, time.monotonic())
        if self.progress is not None and key in self._tasks:
            self.progress.remove_task(self._tasks.pop(key))
        if self.quiet:
            return
        line = Text("  ")
        line.append("✓ ", style=f"bold {PALETTE[0]}")
        line.append(f"{self._titles.get(key, key):<40}", style="bold")
        line.append(summary, style=MUTED)
        line.append(f"  {elapsed:5.1f}s", style="grey42")
        self.console.print(line)

    def note(self, message: str, level: str = "info") -> None:
        """
        Print a message above the progress bars (Reporter protocol).

        Args:
            message (str): Text (rich markup allowed).
            level (str): "info", "warn" or "error".
        Returns:
            None
        """
        if self.quiet and level == "info":
            return
        glyph, style = {"warn": ("▲", "#ffd000"), "error": ("✗", "#ff2e63")}.get(level, ("•", PALETTE[0]))
        self.console.print(Text.assemble("  ", (glyph + " ", f"bold {style}"), Text.from_markup(message, style=MUTED)))

    # ---------------------------------------------------------- renders
    def render_target(self, t: TargetProfile) -> None:
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
            grid.add_row("created", f"{created}   [grey58]via {reg.source.upper()}[/]")
        grid.add_row("name servers", ", ".join(t.dns.ns[:4]) or "-")
        grid.add_row("mail (MX)", ", ".join(t.dns.mx[:3]) or "-")
        grid.add_row("SPF", self._policy(t.dns.spf, "spf"))
        grid.add_row("DMARC", self._policy(t.dns.dmarc, "dmarc"))
        if t.page:
            grid.add_row("homepage", (t.page.title or "-")[:90] if t.page.reachable else
                         Text(f"unreachable ({t.page.error or 'n/a'})"[:90], style="#ff7b00"))
            grid.add_row("brand images", f"{len(t.logos)} fingerprinted" +
                         (f"   [grey58]favicon mmh3[/] [bold]{t.favicon_mmh3}[/]" if t.favicon_mmh3 is not None else ""))
        grid.add_row("brand terms", ", ".join(t.brand_terms))
        self.console.print(Padding(grid, (1, 2, 0, 2)))

    @staticmethod
    def _policy(record: str | None, kind: str) -> Text:
        """
        Colour an SPF/DMARC record by strength.

        Args:
            record (str | None): Raw TXT record.
            kind (str): "spf" or "dmarc".
        Returns:
            Text: Styled record or a "missing" warning.
        """
        if not record:
            return Text("missing  (spoofing of the real domain is easier)", style="bold #ff2e63")
        low = record.lower().replace(" ", "")
        strong = ("-all" in low) if kind == "spf" else ("p=reject" in low or "p=quarantine" in low)
        return Text(record[:90], style="#2ec4b6" if strong else "#ffd000")

    def render_services(self, services: dict[str, str]) -> None:
        """
        Print the status line of external services.

        Args:
            services (dict[str, str]): Service -> status.
        Returns:
            None
        """
        parts: list[Text] = []
        for name, status in services.items():
            on = status.startswith("on")
            dot = Text("● ", style="#2ec4b6" if on else ("#ff2e63" if status.startswith("error") else "grey42"))
            detail = status.split(": ", 1)[1] if ": " in status else status[2:].strip()
            parts.append(dot + Text(name, style="bold" if on else MUTED) +
                         Text(f"  {detail}" if detail else "", style="grey42"))
        self.console.print(Padding(Columns(parts, padding=(0, 3)), (1, 2, 0, 2)))

    def render_summary(self, result: ScanResult) -> None:
        """
        Print the category counters and headline numbers.

        Args:
            result (ScanResult): Scan result.
        Returns:
            None
        """
        self.section("SUMMARY")
        counts = Counter(c.category for c in result.candidates)
        pills: list[Text] = []
        for cat in CATEGORY_STYLE:
            if counts.get(cat):
                pills.append(badge(cat, CATEGORY_STYLE[cat]) + Text(f" {counts[cat]:,}", style="bold"))
        head = Text.assemble(
            ("  analysed ", MUTED), (f"{len(result.candidates):,}", "bold"),
            ("  ·  generated ", MUTED), (f"{result.generated:,}", "bold"),
            ("  ·  discovered (CT/feeds) ", MUTED), (f"{result.discovered:,}", "bold"),
            ("  ·  registered ", MUTED), (f"{len(result.registered):,}", f"bold {PALETTE[0]}"),
        )
        self.console.print(Padding(head, (1, 0, 0, 0)))
        self.console.print(Padding(Columns(pills, padding=(0, 2)), (1, 2, 0, 2)))

    def results_table(self, rows: list[Candidate], title: str, start: int = 1) -> Table:
        """
        Build the main ranked results table.

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
        table.add_column("#", justify="right", style="grey42", width=3, no_wrap=True)
        table.add_column("Domain", ratio=3, overflow="fold")
        table.add_column("Score", no_wrap=True, width=15)
        table.add_column("Category", no_wrap=True, width=12)
        table.add_column("Age", justify="right", no_wrap=True, width=5)
        table.add_column("Signals", ratio=3)
        table.add_column("Technique", ratio=2, style="grey58", overflow="fold")
        for i, c in enumerate(rows, start):
            dom = Text(c.domain, style="bold white" if c.registered else "white")
            if c.ascii != c.domain:
                dom.append(f"\n{c.ascii}", style="grey42")
            age = c.registration.age_days if c.registration else None
            table.add_row(
                str(i), dom, score_bar(c.score, c.risk),
                badge(c.category[:10], CATEGORY_STYLE.get(c.category, "")),
                human_age(age), signal_tags(c), ", ".join(sorted(c.fuzzers))[:60],
            )
        return table

    def render_results(self, result: ScanResult, top: int, show_available: int, min_score: int) -> None:
        """
        Print the ranked threats and the best available lookalikes.

        Args:
            result (ScanResult): Scan result.
            top (int): Max registered rows.
            show_available (int): Max available rows (0 = hide).
            min_score (int): Hide rows below this score.
        Returns:
            None
        """
        self.section("THREATS")
        active = [c for c in result.candidates if c.category not in ("AVAILABLE",) and c.score >= min_score]
        if active:
            self.console.print(self.results_table(active[:top], f"Registered lookalikes  ({len(active)} total)"))
            if len(active) > top:
                self.console.print(Text(f"  … {len(active) - top} more (--top N to show them, -o DIR to export all)",
                                        style=MUTED))
        else:
            self.console.print(Padding(Text("No registered lookalike above the threshold.", style="bold #2ec4b6"), (1, 2)))
        if show_available:
            free = sorted((c for c in result.candidates if c.category == "AVAILABLE"),
                          key=lambda c: (-c.homograph, -c.lexical))[:show_available]
            if free:
                self.console.print()
                self.console.print(self.results_table(free, "Unregistered lookalikes worth a defensive registration"))

    def render_details(self, cands: list[Candidate]) -> None:
        """
        Print explainable detail cards.

        Args:
            cands (list[Candidate]): Candidates to detail.
        Returns:
            None
        """
        if not cands:
            return
        self.section("DETAILS")
        for c in cands:
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
            if p and p.reachable:
                facts.add_row("final url", (p.final_url or "-")[:100])
                facts.add_row("title", (p.title or "-")[:100])
                if p.phishing_keywords:
                    facts.add_row("lexicon", ", ".join(p.phishing_keywords[:6]))
                if p.parking_reasons:
                    facts.add_row("parking", "; ".join(p.parking_reasons[:3]))
            elif p and p.error:
                facts.add_row("web", Text(p.error[:100], style=MUTED))
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

            why = Table.grid(padding=(0, 1))
            why.add_column(justify="right", no_wrap=True, width=6)
            why.add_column(style=MUTED, no_wrap=True, width=12)
            why.add_column(overflow="fold")
            for item in sorted(c.breakdown, key=lambda i: -abs(i.points)):
                pts = Text(f"{item.points:+.0f}", style="bold #2ec4b6" if item.points < 0 else "bold #ff7b00")
                why.add_row(pts, item.group, item.label)
            if not c.breakdown:
                why.add_row("", "", Text("no significant signal", style=MUTED))

            title = Text.assemble((f" {c.domain} ", "bold white"), " ", badge(c.category, CATEGORY_STYLE.get(c.category, "")),
                                  " ", score_bar(c.score, c.risk), " ", (c.risk, RISK_STYLE.get(c.risk, "")), " ")
            body = Table.grid(expand=True, padding=(0, 3))
            body.add_column(ratio=1)
            body.add_column(ratio=1)
            body.add_row(facts, why)
            self.console.print(Panel(body, title=title, title_align="left", border_style=blend(PALETTE, c.score / 100),
                                     box=box.ROUNDED, padding=(1, 2)))

    def render_recommendations(self, result: ScanResult) -> None:
        """
        Print actionable recommendations derived from the findings.

        Args:
            result (ScanResult): Scan result.
        Returns:
            None
        """
        t = result.target
        recs: list[tuple[str, str]] = []
        malicious = [c.domain for c in result.candidates if c.category == "MALICIOUS"]
        suspicious = [c.domain for c in result.candidates if c.category == "SUSPICIOUS"]
        mail = [c.domain for c in result.candidates if c.registered and c.dns.mx and c.category != "DEFENSIVE"]
        free = [c.domain for c in sorted(result.candidates, key=lambda x: (-x.homograph, -x.lexical))
                if c.category == "AVAILABLE"][:6]
        if malicious:
            recs.append(("#ff2e63", f"Request takedown and block at proxy/DNS level: {', '.join(malicious[:6])}"
                         + (" …" if len(malicious) > 6 else "")))
        if suspicious:
            recs.append(("#ff7b00", f"Monitor closely (content may switch to phishing): {', '.join(suspicious[:6])}"
                         + (" …" if len(suspicious) > 6 else "")))
        if mail:
            recs.append(("#ffd000", f"Add mail-enabled lookalikes to the e-mail gateway blocklist ({len(mail)}): "
                         f"{', '.join(mail[:5])}" + (" …" if len(mail) > 5 else "")))
        if not t.dns.dmarc or "p=none" in (t.dns.dmarc or "").lower().replace(" ", ""):
            recs.append(("#ffd000", f"Publish an enforcing DMARC policy for {t.domain} (p=quarantine or p=reject)"))
        if not t.dns.spf:
            recs.append(("#ffd000", f"Publish an SPF record ending in -all for {t.domain}"))
        if free:
            recs.append(("#4cc9f0", f"Consider defensive registration of: {', '.join(free)}"))
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

    def render_footer(self, result: ScanResult, outputs: list[str]) -> None:
        """
        Print run statistics and exported files.

        Args:
            result (ScanResult): Scan result.
            outputs (list[str]): Paths of exported reports.
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
            self.console.print(Text.assemble(("  ↳ ", PALETTE[2]), ("export  ", MUTED), (path, f"bold {PALETTE[0]} underline")))
        self.console.print()


class SilentReporter:
    """
    Reporter that discards every progress event (used with --quiet/--json).
    """

    def stage(self, key: str, title: str, total: int | None = None) -> None:
        """
        Ignore a stage start.

        Args:
            key (str): Stage identifier.
            title (str): Title.
            total (int | None): Steps.
        Returns:
            None
        """

    def advance(self, key: str, n: int = 1, info: str = "") -> None:
        """
        Ignore progress.

        Args:
            key (str): Stage identifier.
            n (int): Steps.
            info (str): Detail.
        Returns:
            None
        """

    def done(self, key: str, summary: str = "") -> None:
        """
        Ignore a stage end.

        Args:
            key (str): Stage identifier.
            summary (str): Summary.
        Returns:
            None
        """

    def note(self, message: str, level: str = "info") -> None:
        """
        Ignore a message.

        Args:
            message (str): Text.
            level (str): Level.
        Returns:
            None
        """
