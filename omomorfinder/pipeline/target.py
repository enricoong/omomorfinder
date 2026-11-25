"""
Stage 0-1: input validation, dataset sync and profiling of the real domain.

The tool takes a *domain* (e.g. "example.com" or an IDN such as
"exämple.de"), never a URL: schemes, paths, ports, credentials, IP
addresses and unknown TLDs are rejected with an explicit message. A host
name such as "login.example.com" is accepted and reduced to its
registrable domain ("example.com"), which is what attackers imitate.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re

import idna

from .. import similarity
from ..models import TargetProfile
from ..nlp import title_terms
from ..resources import RESOURCES, PublicSuffixList
from .context import InputError, ScanContext

_LDH_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_URL_CHARS = set("/\\?#@ \t\r\n")


def validate_domain(raw: str) -> str:
    """
    Syntactic validation of a domain typed by the user (no network, no PSL).

    Args:
        raw (str): User input.
    Returns:
        str: Normalised domain (lower case, no trailing dot, Unicode kept).
    Raises:
        InputError: With a human readable explanation of what is wrong.
    """
    text = (raw or "").strip().lower()
    if not text:
        raise InputError("empty input: pass a domain such as example.com")
    if "://" in text or any(ch in _URL_CHARS for ch in text):
        raise InputError(f"'{raw}' looks like a URL: pass only the domain, e.g. example.com "
                         "(no http://, paths, spaces or credentials)")
    if ":" in text:
        raise InputError(f"'{raw}' contains a port or an IPv6 address: pass only the domain")
    text = text.rstrip(".")
    try:
        ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        raise InputError(f"'{raw}' is an IP address: pass a domain name")
    if "." not in text:
        raise InputError(f"'{raw}' has no top-level domain: pass e.g. {text}.com")
    if text.startswith("*."):
        raise InputError("wildcards are not allowed: pass the domain itself")
    try:
        ascii_text = idna.encode(text, uts46=True).decode("ascii")
    except (idna.IDNAError, UnicodeError) as exc:
        raise InputError(f"'{raw}' is not a valid (IDN) domain: {exc}") from exc
    if len(ascii_text) > 253 or not all(_LDH_LABEL.match(lbl) for lbl in ascii_text.split(".")):
        raise InputError(f"'{raw}' is not a valid domain name")
    if ascii_text.rsplit(".", 1)[-1].isdigit():
        raise InputError(f"'{raw}' is not a valid domain name (numeric TLD)")
    return text


def parse_target(raw: str, psl: PublicSuffixList, tlds: set[str]) -> tuple[str, str, str, str, str | None]:
    """
    Reduce a validated domain to its registrable form using the PSL.

    Args:
        raw (str): User input.
        psl (PublicSuffixList): Public suffix matcher.
        tlds (set[str]): Delegated TLDs (empty = skip the check).
    Returns:
        tuple: (unicode domain, ascii domain, ascii name, ascii suffix,
        note shown to the user when the input was a subdomain, or None).
    Raises:
        InputError: Invalid domain, unknown TLD or bare public suffix.
    """
    text = validate_domain(raw)
    ascii_host = idna.encode(text, uts46=True).decode("ascii")
    tld = ascii_host.rsplit(".", 1)[-1]
    if tlds and tld not in tlds and not tld.startswith("xn--"):
        raise InputError(f"'.{tld}' is not a delegated top-level domain (IANA list)")
    sub, name, suffix = psl.split(ascii_host)
    if not name:
        raise InputError(f"'{raw}' is a public suffix, not a registrable domain")
    ascii_dom = f"{name}.{suffix}"
    try:
        unicode_dom = idna.decode(ascii_dom)
    except idna.IDNAError:
        unicode_dom = ascii_dom
    note = None
    if sub and sub != "www":
        note = f"'{text}' is a host name: analysing its registrable domain [bold]{unicode_dom}[/]"
    return unicode_dom, ascii_dom, name, suffix, note


async def sync_datasets(ctx: ScanContext) -> None:
    """
    Download / refresh every external dataset and load the confusables.

    Args:
        ctx (ScanContext): Scan context.
    Returns:
        None
    """
    r = ctx.reporter
    r.stage("res", "Syncing datasets", len(RESOURCES))

    def on_done(res: object, state: str) -> None:
        """
        Progress callback for each dataset.

        Args:
            res (object): Resource descriptor.
            state (str): Download state.
        Returns:
            None
        """
        r.advance("res", info=f"{getattr(res, 'label', '?')}: {state}")
        if state == "missing":
            r.note(f"dataset unavailable: {getattr(res, 'label', '?')} (using built-in fallback)", "warn")

    await ctx.resources.ensure_all(on_done=on_done)
    similarity.load_confusables(ctx.resources.confusables())
    feeds = len(ctx.resources.feed_hosts())
    r.done("res", f"{len(ctx.resources.tlds())} TLDs, {feeds:,} known-bad hosts")


async def profile_target(ctx: ScanContext, raw: str) -> TargetProfile:
    """
    Profile the legitimate domain: DNS, SPF/DMARC, RDAP/WHOIS, homepage, logos.

    Args:
        ctx (ScanContext): Scan context.
        raw (str): User input (already syntactically validated).
    Returns:
        TargetProfile: Target analysis.
    Raises:
        InputError: When the domain is not registrable / TLD unknown.
    """
    # the TLD check needs the real IANA list (the built-in fallback is partial)
    tlds = ctx.resources.tlds() if ctx.resources.path("tlds").exists() else set()
    udom, adom, name, suffix, note = parse_target(raw, ctx.resources.psl(), tlds)
    if note:
        ctx.reporter.note(note)
    target = TargetProfile(input=raw, domain=udom, ascii=adom, name=name, suffix=suffix)
    r = ctx.reporter
    r.stage("target", f"Profiling {udom}", 4)

    async def dns_part() -> None:
        """
        Resolve target DNS and SPF/DMARC.

        Returns:
            None
        """
        target.dns = await ctx.dns.probe(adom, suffix)
        target.dns.spf, target.dns.dmarc = await ctx.dns.mail_security(adom)
        r.advance("target", info="DNS")

    async def reg_part() -> None:
        """
        RDAP/WHOIS lookup of the target.

        Returns:
            None
        """
        target.registration = await ctx.registry.lookup(adom, suffix)
        r.advance("target", info="RDAP/WHOIS")

    async def web_part() -> None:
        """
        Fetch the homepage and fingerprint the brand images.

        Returns:
            None
        """
        if ctx.settings.fast:
            r.advance("target", 2)
            return
        target.page = await ctx.fetcher.fetch(adom, adom, [name])
        if not target.page.reachable:
            target.page = await ctx.fetcher.fetch(f"www.{adom}", adom, [name])
        r.advance("target", info="homepage")
        if target.page.reachable:
            target.logos = await ctx.visual.fingerprint_page(target.page.icon_urls, target.page.image_urls)
            fav = next((fp for fp in target.logos if fp.kind == "favicon"), None)
            target.favicon_mmh3 = fav.mmh3 if fav else None
        r.advance("target", info=f"{len(target.logos)} brand images")

    await asyncio.gather(dns_part(), reg_part(), web_part())
    target.brand_terms = title_terms(target.page.title if target.page else "", name)
    r.done("target", f"{udom} profiled")
    return target
