"""
Stage 2: building the candidate list.

Three sources feed it:

  1. the permutation engine (`generator.DomainGenerator`);
  2. the local threat feeds: registrable domains close to the brand, and
     domains whose *subdomains* carry the brand
     ("example.it.verify-account.com", a very common phishing pattern);
  3. Certificate Transparency (crt.sh): same two checks on every hostname
     that appeared in a recently issued certificate.
"""

from __future__ import annotations

import re

import idna

from .. import similarity
from ..generator import DomainGenerator, to_ascii_label
from ..models import Candidate, TargetProfile
from .context import ScanContext

CREDENTIAL_LABEL = re.compile(
    r"login|log-in|signin|sign-in|secure|account|auth|sso|verif|pay|bank|wallet|webmail|portal|"
    r"accedi|accesso|password|update|aggiorna|billing|fattur|clienti|customer|owa|recovery|unlock|sblocc",
    re.I,
)


def decode_label(label: str) -> str:
    """
    Unicode form of a (possibly punycode) label.

    Args:
        label (str): ASCII label.
    Returns:
        str: Unicode label (unchanged when not IDN or undecodable).
    """
    if not label.startswith("xn--"):
        return label
    try:
        return idna.decode(label)
    except idna.IDNAError:
        return label


def brand_in_labels(labels: list[str], brand: str) -> bool:
    """
    Whether any label imitates the brand (exact, as a word, or as a homograph).

    Args:
        labels (list[str]): Host labels to inspect (e.g. the subdomain part).
        brand (str): Target label.
    Returns:
        bool: True when a label impersonates the brand.
    """
    sk_brand = similarity.skeleton(brand)
    for raw in labels:
        label = decode_label(raw)
        if label == brand or similarity.contains_brand(label, brand) or similarity.skeleton(label) == sk_brand:
            return True
    return False


def credential_label(labels: list[str]) -> bool:
    """
    Whether any label is credential / payment themed.

    Args:
        labels (list[str]): Host labels.
    Returns:
        bool: True for labels such as "login", "secure", "pay", "accedi".
    """
    return any(CREDENTIAL_LABEL.search(lbl) for lbl in labels)


def make_candidate(ctx: ScanContext, ascii_dom: str, target: TargetProfile, fuzzers: set[str],
                   brand_host: str | None = None) -> Candidate | None:
    """
    Build a Candidate for a discovered registrable domain.

    For brand-in-subdomain discoveries the lexical similarity stays the one
    of the registrable name (often unrelated, e.g. a hosting platform): the
    impersonation is scored separately as a "brand used in subdomain"
    signal, so the explanation shown to the analyst is accurate.

    Args:
        ctx (ScanContext): Scan context.
        ascii_dom (str): ASCII registrable domain.
        target (TargetProfile): Target profile.
        fuzzers (set[str]): Source tags.
        brand_host (str | None): Full host carrying the brand in a subdomain.
    Returns:
        Candidate | None: Candidate, None if the domain is unusable.
    """
    _, name, suffix = ctx.resources.psl().split(ascii_dom)
    if not name or (to_ascii_label(name) is None and not name.startswith("xn--")):
        return None
    uname = decode_label(name)
    lex, homo = similarity.lexical_score(uname, suffix, target.name, target.suffix)
    cand = Candidate(domain=f"{uname}.{suffix}", ascii=f"{name}.{suffix}", name=uname,
                     suffix=suffix, fuzzers=set(fuzzers), lexical=lex, homograph=homo)
    if brand_host:
        labels = brand_host[: -len(ascii_dom)].rstrip(".").split(".")
        cand.add_subdomain(brand_host, "ct" if "ct" in fuzzers else "feed", brand=True,
                           credential=credential_label(labels))
    return cand


def generate_candidates(ctx: ScanContext, target: TargetProfile) -> tuple[dict[str, Candidate], int]:
    """
    Permutations plus lookalikes found in the local threat feeds.

    Args:
        ctx (ScanContext): Scan context.
        target (TargetProfile): Target profile.
    Returns:
        tuple[dict[str, Candidate], int]: (ASCII domain -> candidate,
        number of generated permutations).
    """
    r = ctx.reporter
    r.stage("gen", "Generating lookalikes", None)
    gen = DomainGenerator(ctx.resources, ctx.settings)
    out: dict[str, Candidate] = {}
    for ascii_dom, g in gen.generate(target.name, target.suffix).items():
        lex, homo = similarity.lexical_score(g.name, g.suffix, target.name, target.suffix)
        out[ascii_dom] = Candidate(domain=g.unicode, ascii=ascii_dom, name=g.name, suffix=g.suffix,
                                   fuzzers=g.fuzzers, lexical=lex, homograph=homo)
    generated = len(out)

    # (a) feed listings of generated domains, (b) close registrable domains
    exact, sub = ctx.resources.feed_index()
    for reg, cand in out.items():
        cand.feeds |= exact.get(reg, set())
        cand.feed_subdomains |= sub.get(reg, set())
    near = 0
    for index in (exact, sub):
        for reg in index:
            if reg in out or reg == target.ascii or not similarity.is_near(reg.split(".", 1)[0], target.name):
                continue
            cand = make_candidate(ctx, reg, target, {"feed"})
            if cand is not None:
                out[reg] = cand
                near += 1
                cand.feeds |= exact.get(reg, set())
                cand.feed_subdomains |= sub.get(reg, set())

    # (c) feed hosts carrying the brand in a subdomain
    in_sub = discover_feed_brand_subdomains(ctx, target, out)
    r.done("gen", f"{generated:,} permutations, {near} close domains + {in_sub} brand-in-subdomain from feeds")
    return out, generated


def discover_feed_brand_subdomains(ctx: ScanContext, target: TargetProfile, out: dict[str, Candidate]) -> int:
    """
    Find feed-listed hosts such as "brand.it.verify-login.com".

    A cheap substring test filters the (hundreds of thousands of) feed hosts
    before the PSL split, so the scan stays fast.

    Args:
        ctx (ScanContext): Scan context.
        target (TargetProfile): Target profile.
        out (dict[str, Candidate]): Candidate map (updated in place).
    Returns:
        int: Number of new candidates.
    """
    psl = ctx.resources.psl()
    brand = target.name
    added = 0
    for host, feeds in ctx.resources.feed_hosts().items():
        if brand not in host:
            continue
        sub, name, suffix = psl.split(host)
        reg = f"{name}.{suffix}" if name else ""
        if not sub or not reg or reg == target.ascii or not brand_in_labels(sub.split("."), brand):
            continue
        cand = out.get(reg)
        if cand is None:
            cand = make_candidate(ctx, reg, target, {"brand-subdomain"}, brand_host=host)
            if cand is None:
                continue
            out[reg] = cand
            added += 1
        else:
            cand.fuzzers.add("brand-subdomain")
            cand.add_subdomain(host, "feed", brand=True, credential=credential_label(sub.split(".")))
        cand.feed_subdomains |= feeds
    return added


async def discover_ct(ctx: ScanContext, target: TargetProfile, cands: dict[str, Candidate]) -> int:
    """
    Discover lookalikes through Certificate Transparency logs.

    Args:
        ctx (ScanContext): Scan context.
        target (TargetProfile): Target profile.
        cands (dict[str, Candidate]): Candidate map (updated in place).
    Returns:
        int: Number of newly discovered candidates.
    """
    r = ctx.reporter
    if ctx.settings.fast or not ctx.settings.ct_enabled:
        return 0
    if len(target.name) < 4:
        r.note("CT keyword search skipped: brand keyword shorter than 4 characters", "warn")
        return 0
    r.stage("ct", "Searching Certificate Transparency logs", None)
    psl = ctx.resources.psl()
    found = await ctx.ct.search_keyword(target.name, psl.registrable)
    added = in_sub = 0
    for reg, info in found.items():
        if reg == target.ascii:
            continue
        label = decode_label(psl.split(reg)[1])
        brand_hosts = [h for h in info.names
                       if h != reg and h.endswith("." + reg)
                       and brand_in_labels(h[: -len(reg)].rstrip(".").split("."), target.name)]
        close = similarity.is_near(label, target.name)
        if not close and not brand_hosts:
            continue
        cand = cands.get(reg)
        if cand is None:
            tag = {"ct"} if close else {"ct", "brand-subdomain"}
            cand = make_candidate(ctx, reg, target, tag, brand_host=None if close else brand_hosts[0])
            if cand is None:
                continue
            cands[reg] = cand
            added += 1
            in_sub += 0 if close else 1
        else:
            cand.fuzzers.add("ct")
        for host in brand_hosts:
            labels = host[: -len(reg)].rstrip(".").split(".")
            cand.add_subdomain(host, "ct", brand=True, credential=credential_label(labels))
        cand.ct = info
    msg = f"{len(found)} domains in CT logs, {added} new lookalikes ({in_sub} brand-in-subdomain)"
    if ctx.ct.error:
        msg += f" (crt.sh: {ctx.ct.error[:60]})"
    r.done("ct", msg)
    return added
