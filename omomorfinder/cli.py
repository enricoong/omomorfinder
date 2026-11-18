"""
Command-line entry point.

Parses arguments, builds `Settings`, runs the `Scanner` inside the live
terminal UI, renders the results and exports the reports. Also provides
maintenance commands (`--setup`, `--clear-cache`).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

from . import __app_name__, __version__
from .cache import Cache
from .config import CACHE_DIR, DATA_DIR, Settings, load_dotenv_files
from .engine import InputError, Scanner
from .generator import DomainGenerator
from .report import export
from .ui import SilentReporter, TerminalUI

EXAMPLES = """
examples:
  omomorfinder example.com
  omomorfinder https://www.example.it --deep --detail 5
  omomorfinder example.com --fast --tlds all
  omomorfinder example.com --top 50 -o results     (also export JSON + CSV)
  omomorfinder example.com --proxy socks5://127.0.0.1:9050 --resolvers 1.1.1.1,9.9.9.9
  omomorfinder --setup

api keys (environment or .env in the current dir / ~/.config/omomorfinder/.env):
  VT_API_KEY, ABUSEIPDB_API_KEY, URLSCAN_API_KEY, VT_RATE_PER_MIN (default 4)
"""


def build_parser() -> argparse.ArgumentParser:
    """
    Define every command-line option.

    Returns:
        argparse.ArgumentParser: Configured parser.
    """
    p = argparse.ArgumentParser(
        prog="omomorfinder",
        description=f"{__app_name__} {__version__} - find homomorphic / lookalike domains of a company "
                    "and rank them by phishing, spoofing and competitor relevance.",
        epilog=EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?", help="company domain or URL (e.g. example.com)")

    prof = p.add_argument_group("profile")
    mx = prof.add_mutually_exclusive_group()
    mx.add_argument("--fast", action="store_true", help="generation + DNS + lexical scoring only")
    mx.add_argument("--deep", action="store_true",
                    help="add screenshots, ORB logo matching, embeddings, per-domain CT, urlscan")

    gen = p.add_argument_group("generation")
    gen.add_argument("--tlds", default="popular", metavar="MODE",
                     help="TLD swap pool: 'popular' (default), 'all' (IANA list) or a list 'com,net,shop'")
    gen.add_argument("--keyboard", choices=("qwerty", "qwertz", "azerty"), default="qwerty",
                     help="keyboard layout for typo generation (default qwerty, also valid for Italian)")
    gen.add_argument("--fuzzers", metavar="LIST",
                     help="comma separated subset of: " + ", ".join(DomainGenerator.FUZZERS))
    gen.add_argument("--dictionary", type=Path, metavar="FILE", help="extra combosquatting words (one per line)")
    gen.add_argument("--mixed-script", action="store_true",
                     help="also generate mixed-script IDN labels (rarely registrable)")

    net = p.add_argument_group("network & politeness")
    net.add_argument("--resolvers", metavar="IPS", help="custom DNS resolvers, e.g. 1.1.1.1,9.9.9.9")
    net.add_argument("--dns-concurrency", type=int, default=150, metavar="N", help="parallel DNS queries (150)")
    net.add_argument("--http-concurrency", type=int, default=16, metavar="N", help="parallel site analyses (16)")
    net.add_argument("--timeout", type=float, default=12.0, metavar="SEC", help="HTTP timeout (12)")
    net.add_argument("--proxy", metavar="URL", help="HTTP/SOCKS proxy for web requests (Tor, Burp)")
    net.add_argument("--user-agent", metavar="UA", help="override the User-Agent header")
    net.add_argument("--no-ct", action="store_true", help="skip Certificate Transparency (crt.sh)")
    net.add_argument("--vt-limit", type=int, default=25, metavar="N", help="max domains sent to VirusTotal (25)")
    net.add_argument("--abuse-limit", type=int, default=80, metavar="N", help="max IPs sent to AbuseIPDB (80)")
    net.add_argument("--whois-limit", type=int, default=80, metavar="N",
                     help="max uncached queries per port-43 WHOIS server (80; registries ban heavy clients)")
    net.add_argument("--no-cache", action="store_true", help="ignore cached answers (they are still refreshed)")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--output", type=Path, default=None, metavar="DIR",
                     help="also export the results to DIR (nothing is written without it)")
    out.add_argument("--format", default="json,csv", metavar="LIST",
                     help="export formats used with -o: json,csv (default both)")
    out.add_argument("--top", type=int, default=30, metavar="N", help="rows of the threats table (30)")
    out.add_argument("--available", type=int, default=10, metavar="N",
                     help="rows of the unregistered-lookalikes table (10, 0 hides it)")
    out.add_argument("--min-score", type=int, default=0, metavar="N", help="hide registered rows below this score")
    out.add_argument("--detail", type=int, default=5, metavar="N", help="detail cards for the top N threats (5)")
    out.add_argument("--json", action="store_true", help="print the JSON result on stdout (no UI)")
    out.add_argument("-q", "--quiet", action="store_true", help="no progress output")
    out.add_argument("--no-color", action="store_true", help="disable colours")
    out.add_argument("-v", "--verbose", action="store_true", help="debug logging")

    maint = p.add_argument_group("maintenance")
    maint.add_argument("--setup", action="store_true",
                       help="download every dataset, headless Chromium and the NLP model, then exit")
    maint.add_argument("--clear-cache", action="store_true", help="delete the HTTP/DNS cache and exit")
    p.add_argument("-V", "--version", action="version", version=f"{__app_name__} {__version__}")
    return p


def settings_from_args(args: argparse.Namespace) -> Settings:
    """
    Translate parsed arguments into a `Settings` object.

    Args:
        args (argparse.Namespace): Parsed arguments.
    Returns:
        Settings: Ready-to-use configuration (API keys loaded).
    """
    s = Settings()
    s.profile = "fast" if args.fast else "deep" if args.deep else "standard"
    s.tld_mode = args.tlds
    s.keyboard = args.keyboard
    if args.fuzzers:
        wanted = {f.strip() for f in args.fuzzers.split(",") if f.strip()}
        unknown = wanted - set(DomainGenerator.FUZZERS)
        if unknown:
            raise SystemExit(f"unknown fuzzer(s): {', '.join(sorted(unknown))}")
        s.fuzzers = wanted
    if args.dictionary:
        s.extra_words = [w.strip().lower() for w in args.dictionary.read_text(encoding="utf-8").splitlines()
                         if w.strip() and not w.startswith("#")]
    s.include_mixed_script = args.mixed_script
    s.resolvers = [r.strip() for r in (args.resolvers or "").split(",") if r.strip()]
    s.dns_concurrency = max(1, args.dns_concurrency)
    s.http_concurrency = max(1, args.http_concurrency)
    s.http_timeout = args.timeout
    s.proxy = args.proxy
    if args.user_agent:
        s.user_agent = args.user_agent
    s.ct_enabled = not args.no_ct
    s.vt_limit = max(0, args.vt_limit)
    s.abuse_limit = max(0, args.abuse_limit)
    s.whois_limit = max(0, args.whois_limit)
    s.use_cache = not args.no_cache
    s.load_api_keys()
    s.build_rate_rules()
    return s


async def run_setup(console: Console) -> int:
    """
    Pre-download every external resource (datasets, Chromium, NLP model).

    Args:
        console (Console): Rich console.
    Returns:
        int: Process exit code.
    """
    from .net import HttpClient
    from .nlp import EmbeddingModel
    from .resources import ResourceManager

    s = Settings()
    s.build_rate_rules()
    cache = Cache(CACHE_DIR / "cache.db")
    http = HttpClient(s, cache)
    res = ResourceManager(http, DATA_DIR)
    console.print("[bold #00e5ff]› datasets[/]")
    for name, state in (await res.ensure_all(force=True)).items():
        colour = "#2ec4b6" if state in ("downloaded", "fresh") else "#ff2e63"
        console.print(f"   [{colour}]●[/] {name:<14} {state}")
    await http.close()
    cache.close()
    console.print("[bold #00e5ff]› headless Chromium (Playwright)[/]")
    try:
        import playwright  # noqa: F401

        rc = subprocess.call([sys.executable, "-m", "playwright", "install", "chromium"])
        console.print("   [#2ec4b6]●[/] installed" if rc == 0 else f"   [#ff2e63]●[/] failed (exit {rc})")
    except ImportError:
        console.print("   [grey58]● skipped: pip install playwright (optional, deep mode)[/]")
    console.print("[bold #00e5ff]› multilingual embedding model[/]")
    model = EmbeddingModel()
    if await model.load():
        console.print("   [#2ec4b6]●[/] ready")
    else:
        console.print(f"   [grey58]● skipped: {model.error} (optional, deep mode)[/]")
    console.print(f"\n[grey58]data dir:[/] {DATA_DIR}\n[grey58]cache dir:[/] {CACHE_DIR}")
    return 0


async def run_scan(args: argparse.Namespace, console: Console) -> int:
    """
    Run a full scan and render/export the results.

    Args:
        args (argparse.Namespace): Parsed arguments.
        console (Console): Rich console.
    Returns:
        int: Process exit code (0 ok, 2 invalid input).
    """
    settings = settings_from_args(args)
    headless = args.json or args.quiet
    ui = TerminalUI(console, quiet=headless)
    reporter = SilentReporter() if headless else ui
    if not headless:
        ui.banner(settings)
    work_dir = args.output or (CACHE_DIR / "screenshots-tmp")  # deep-mode screenshots only
    scanner = Scanner(settings, reporter, work_dir)
    try:
        if headless:
            result = await scanner.run(args.target)
        else:
            with ui.live():
                result = await scanner.run(args.target)
    except InputError as exc:
        console.print(f"[bold #ff2e63]✗[/] {exc}")
        return 2

    formats = {f.strip().lower() for f in args.format.split(",")} & {"json", "csv"}
    outputs = export(result, args.output, formats) if args.output and formats else []
    if args.json:
        import json

        from .models import to_jsonable

        sys.stdout.write(json.dumps(to_jsonable(result), ensure_ascii=False, indent=2) + "\n")
        return 0
    ui.render_target(result.target)
    ui.render_services(result.services)
    ui.render_summary(result)
    ui.render_results(result, args.top, args.available, args.min_score)
    threats = [c for c in result.candidates if c.registered and c.category not in ("DEFENSIVE",)]
    ui.render_details(threats[: max(0, args.detail)])
    ui.render_recommendations(result)
    ui.render_footer(result, outputs)
    return 0


def main(argv: list[str] | None = None) -> int:
    """
    Program entry point.

    Args:
        argv (list[str] | None): Arguments (defaults to sys.argv[1:]).
    Returns:
        int: Process exit code.
    """
    args = build_parser().parse_args(argv)
    console = Console(highlight=False, no_color=args.no_color, stderr=args.json, soft_wrap=False)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.ERROR, format="%(message)s",
        handlers=[RichHandler(console=console, show_path=False, markup=False)],
    )
    for noisy in ("httpx", "httpcore", "hpack", "asyncio", "PIL"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    load_dotenv_files()

    if args.clear_cache:
        Cache(CACHE_DIR / "cache.db").clear()
        console.print("[#2ec4b6]●[/] cache cleared")
        return 0
    if args.setup:
        return asyncio.run(run_setup(console))
    if not args.target:
        build_parser().print_help()
        return 1
    try:
        return asyncio.run(run_scan(args, console))
    except KeyboardInterrupt:
        console.print("\n[bold #ffd000]▲[/] interrupted by user")
        return 130
