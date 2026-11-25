"""
Stage 5: subdomain analysis of registered lookalikes.

Phishing rarely lives on the bare lookalike: it sits on hosts such as
"login.examp1e.com" or "example.it.secure-verify.com". For the most
relevant registered candidates this stage:

  * imports the hostnames already seen in CT logs and threat feeds;
  * detects wildcard DNS ("*.domain": every subdomain resolves, a feature
    phishing kits use to accept arbitrary brand-looking links);
  * otherwise probes a short wordlist of high-value labels (login, secure,
    account, webmail, pay, the brand itself, ...) with plain DNS queries;
  * flags subdomains that impersonate the brand or are credential themed.
"""

from __future__ import annotations

from ..models import Candidate, TargetProfile
from .context import ScanContext, gather_limited
from .discovery import brand_in_labels, credential_label

SUBDOMAIN_WORDS: tuple[str, ...] = (
    "www", "mail", "webmail", "login", "signin", "secure", "account", "accounts", "auth", "sso",
    "verify", "portal", "my", "app", "online", "pay", "payment", "bank", "support", "help",
    "owa", "vpn", "area-clienti", "accedi", "clienti",
)


def labels_before(host: str, domain: str) -> list[str]:
    """
    Labels of a host that precede its registrable domain.

    Args:
        host (str): Full hostname ("a.b.example.com").
        domain (str): Registrable domain ("example.com").
    Returns:
        list[str]: e.g. ["a", "b"].
    """
    return [lbl for lbl in host[: -len(domain)].rstrip(".").split(".") if lbl]


async def scan_one(ctx: ScanContext, c: Candidate, target: TargetProfile) -> None:
    """
    Collect and classify the subdomains of one candidate.

    Args:
        ctx (ScanContext): Scan context.
        c (Candidate): Registered candidate (updated in place).
        target (TargetProfile): Target profile.
    Returns:
        None
    """
    # 1. hostnames already known from CT certificates
    for host in (c.ct.names if c.ct else []):
        if host != c.ascii and host.endswith("." + c.ascii):
            labels = labels_before(host, c.ascii)
            c.add_subdomain(host, "ct", brand=brand_in_labels(labels, target.name),
                            credential=credential_label(labels))
    # 2. wildcard detection, then wordlist probing
    c.wildcard_dns = await ctx.dns.is_wildcard_zone(c.ascii)
    words = list(dict.fromkeys([*SUBDOMAIN_WORDS, target.name]))
    if not c.wildcard_dns:
        async def probe(word: str) -> None:
            """
            Resolve one candidate subdomain.

            Args:
                word (str): Subdomain label.
            Returns:
                None
            """
            host = f"{word}.{c.ascii}"
            status, ips = await ctx.dns.query(host, "A")
            if status == "ok" and ips:
                c.add_subdomain(host, "dns", brand=brand_in_labels([word], target.name),
                                credential=credential_label([word]), ips=ips)

        await gather_limited([probe(w) for w in words], 12)
    # 3. resolve brand / credential subdomains learnt from CT or feeds
    for sub in c.subdomains:
        if (sub.brand or sub.credential) and not sub.ips:
            status, ips = await ctx.dns.query(sub.name, "A")
            if status == "ok":
                sub.ips = ips


async def analyse_subdomains(ctx: ScanContext, target: TargetProfile, cands: list[Candidate],
                             limit: int = 80) -> None:
    """
    Subdomain analysis of the most relevant registered candidates.

    Args:
        ctx (ScanContext): Scan context.
        target (TargetProfile): Target profile.
        cands (list[Candidate]): Registered candidates.
        limit (int): Maximum candidates probed with the wordlist.
    Returns:
        None
    """
    r = ctx.reporter
    ranked = sorted(cands, key=lambda c: (-bool(c.subdomains), -c.lexical))[:limit]
    if not ranked:
        return
    r.stage("subs", "Subdomain analysis", len(ranked))

    async def one(c: Candidate) -> None:
        """
        Analyse one candidate and advance the progress bar.

        Args:
            c (Candidate): Candidate.
        Returns:
            None
        """
        await scan_one(ctx, c, target)
        r.advance("subs", info=c.domain[:40])

    await gather_limited([one(c) for c in ranked], 8)
    brand = sum(1 for c in ranked if any(s.brand for s in c.subdomains))
    cred = sum(1 for c in ranked if any(s.credential and s.ips for s in c.subdomains))
    wild = sum(1 for c in ranked if c.wildcard_dns)
    r.done("subs", f"{len(ranked)} domains: {brand} brand subdomains, {cred} credential-themed, {wild} wildcard")
