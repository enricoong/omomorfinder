"""
Live view shown while a scan runs.

  * stage progress bars (spinner, bar, counters, elapsed time, detail);
  * the "live commands" panel: the latest equivalent shell commands
    (dig / whois / curl / chromium ...) published on `activity.FEED`, with
    per-kind counters, so the analyst always sees what is being executed;
  * one summary line per completed stage, printed above the live area.

`LiveReporter` implements the pipeline's `Reporter` protocol;
`SilentReporter` is the no-op variant for --json / --quiet runs.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager

from rich import box
from rich.console import Console, Group, RenderableType
from rich.live import Live
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
from rich.table import Table
from rich.text import Text

from ..activity import FEED, ActivityFeed
from .theme import ACCENT, DIM, KIND_STYLE, MUTED, PALETTE


class ActivityView:
    """
    Renderable panel with the most recent background commands.

    Args (constructor):
        feed (ActivityFeed): Activity source.
        lines (int): Number of commands shown (fixed height, no flicker).
    """

    def __init__(self, feed: ActivityFeed, lines: int = 6) -> None:
        """
        Store the feed and the panel height.

        Args:
            feed (ActivityFeed): Activity source.
            lines (int): Visible commands.
        Returns:
            None
        """
        self.feed = feed
        self.lines = lines

    def __rich__(self) -> RenderableType:
        """
        Build the panel (called by `Live` at every refresh).

        Returns:
            RenderableType: The commands panel.
        """
        grid = Table.grid(padding=(0, 1), expand=True)
        grid.add_column(style=DIM, no_wrap=True, width=8)
        grid.add_column(no_wrap=True, width=7)
        grid.add_column(no_wrap=True, width=1)
        grid.add_column(no_wrap=True, overflow="ellipsis", ratio=1)
        items = self.feed.recent(self.lines)
        for item in items:
            style = KIND_STYLE.get(item.kind, MUTED)
            grid.add_row(time.strftime("%H:%M:%S", time.localtime(item.ts)), Text(item.kind, style=f"bold {style}"),
                         Text("$", style=f"bold {ACCENT}"), Text(item.command, style="grey74"))
        for _ in range(self.lines - len(items)):
            grid.add_row("", "", "", "")
        counts = "  ".join(f"{kind} {n:,}" for kind, n in self.feed.counts.most_common())
        return Panel(
            grid, box=box.ROUNDED, border_style="grey27", padding=(0, 1),
            title=Text(" ◆ live commands ", style=f"bold {PALETTE[0]}"), title_align="left",
            subtitle=Text(f" {counts} " if counts else "", style=MUTED), subtitle_align="right",
        )


class LiveReporter:
    """
    Rich implementation of the pipeline `Reporter` protocol.

    Args (constructor):
        console (Console): Rich console.
        quiet (bool): Suppress all progress output.
        show_activity (bool): Show the live commands panel.
    """

    def __init__(self, console: Console, quiet: bool = False, show_activity: bool = True) -> None:
        """
        Initialise reporter state.

        Args:
            console (Console): Rich console.
            quiet (bool): Suppress progress output.
            show_activity (bool): Show the live commands panel.
        Returns:
            None
        """
        self.console = console
        self.quiet = quiet
        self.show_activity = show_activity
        self.progress: Progress | None = None
        self._tasks: dict[str, TaskID] = {}
        self._titles: dict[str, str] = {}
        self._started: dict[str, float] = {}

    @contextmanager
    def live(self) -> Iterator[None]:
        """
        Context manager showing progress bars and the commands panel.

        Returns:
            Iterator[None]: Yields while the live display is active.
        """
        if self.quiet:
            yield
            return
        FEED.reset()
        self.progress = Progress(
            SpinnerColumn("dots12", style=ACCENT),
            TextColumn("[bold]{task.description:<38}"),
            BarColumn(bar_width=32, style="grey23", complete_style=PALETTE[1], finished_style=PALETTE[0],
                      pulse_style=PALETTE[2]),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TextColumn("[grey58]{task.fields[info]}"),
            console=self.console,
        )
        view: RenderableType = Group(self.progress, ActivityView(FEED)) if self.show_activity else self.progress
        with Live(view, console=self.console, refresh_per_second=10, transient=True):
            yield
        self.progress = None

    def stage(self, key: str, title: str, total: int | None = None) -> None:
        """
        Open a progress stage.

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
        Advance a stage.

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
        Close a stage and print its summary line.

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
        line.append(f"  {elapsed:5.1f}s", style=DIM)
        self.console.print(line)

    def note(self, message: str, level: str = "info") -> None:
        """
        Print a message above the live display.

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


class SilentReporter:
    """
    Reporter that discards every progress event (used with --json/--quiet).
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
