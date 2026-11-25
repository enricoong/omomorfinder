"""
Automatic download and parsing of every external dataset.

Datasets (all public, all downloaded on demand and refreshed by age):
  * IANA TLD list            -> TLD swapping
  * Public Suffix List       -> registrable-domain extraction
  * Unicode confusables.txt  -> homoglyph generation and visual skeletons
  * IANA RDAP bootstrap      -> RDAP server discovery per TLD
  * OpenPhish / URLhaus / Phishing Army feeds -> known-bad hosts

When a download fails, a stale copy is used; when no copy exists at all,
built-in fallbacks keep the tool working (with reduced coverage).
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .net import HttpClient

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Resource:
    """
    Description of one downloadable dataset.

    Attributes:
        name (str): Internal identifier.
        url (str): Download URL.
        filename (str): Local file name inside the data directory.
        ttl (int): Maximum age in seconds before a refresh is attempted.
        label (str): Human readable name for the UI.
        feed (bool): True for threat-intelligence feeds.
    """

    name: str
    url: str
    filename: str
    ttl: int
    label: str
    feed: bool = False


DAY = 86400
RESOURCES: tuple[Resource, ...] = (
    Resource("tlds", "https://data.iana.org/TLD/tlds-alpha-by-domain.txt",
             "tlds.txt", 7 * DAY, "IANA TLD list"),
    Resource("psl", "https://publicsuffix.org/list/public_suffix_list.dat",
             "public_suffix_list.dat", 7 * DAY, "Public Suffix List"),
    Resource("confusables", "https://www.unicode.org/Public/security/latest/confusables.txt",
             "confusables.txt", 30 * DAY, "Unicode confusables"),
    Resource("rdap", "https://data.iana.org/rdap/dns.json",
             "rdap_dns.json", 1 * DAY, "IANA RDAP bootstrap"),
    Resource("openphish", "https://openphish.com/feed.txt",
             "feed_openphish.txt", 6 * 3600, "OpenPhish feed", feed=True),
    Resource("urlhaus", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains-online.txt",
             "feed_urlhaus.txt", 6 * 3600, "URLhaus feed", feed=True),
    Resource("phishingarmy", "https://phishing.army/download/phishing_army_blocklist.txt",
             "feed_phishingarmy.txt", 12 * 3600, "Phishing Army feed", feed=True),
    Resource("phishingdb", "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
             "feed_phishingdb.txt", 12 * 3600, "Phishing.Database feed", feed=True),
)

# Popular TLDs used for TLD swapping in the default ("popular") mode.
POPULAR_TLDS: tuple[str, ...] = (
    "com", "net", "org", "info", "biz", "it", "eu", "de", "fr", "es", "nl", "be",
    "ch", "at", "uk", "co.uk", "co", "io", "ai", "app", "dev", "online", "site",
    "shop", "store", "xyz", "top", "club", "live", "tech", "cloud", "email",
    "space", "website", "services", "support", "solutions", "group", "company",
    "center", "world", "today", "news", "blog", "ltd", "icu", "vip", "cc", "tv",
    "me", "us", "ca", "in", "ru", "cn", "pl", "pt", "se", "no", "dk", "fi", "gr",
    "ro", "cz", "hu", "sk", "ie", "lu", "li", "mobi", "pro", "asia", "link",
    "click", "page", "digital", "network", "systems", "agency", "media", "global",
    "finance", "bank", "money", "pay", "security", "help", "one", "host", "fun",
    "win", "bond", "cfd", "sbs", "rest", "cyou", "buzz", "monster", "lol",
    "com.br", "com.au", "com.mx", "su", "ws", "to", "sh", "gg", "ly", "tk", "ml",
)

_FALLBACK_PSL = (
    "com net org info biz eu it de fr es co io app dev uk co.uk org.uk ac.uk gov.uk "
    "com.au net.au org.au com.br com.mx co.jp ne.jp co.in co.za com.tr com.cn "
    "com.ar co.nz com.sg com.hk"
).split()

_FALLBACK_CONFUSABLES: dict[str, str] = {
    "a": "аɑαàáâãäåąǎȧ", "b": "ЬƅḃɓЪ", "c": "сϲçćĉċč", "d": "ԁɗďđḋ",
    "e": "еёęėéèêëēěȩ", "f": "ƒḟ", "g": "ɡġğĝģǵ", "h": "һĥħḣ",
    "i": "іıíìîïɩīĭįǐ", "j": "јĵ", "k": "κкķḳ", "l": "ӏɩłľĺļḷ",
    "m": "ṁṃ", "n": "ոηñńņňṅ", "o": "оοӧöóòôõøơōŏő", "p": "рρṗ",
    "q": "ԛ", "r": "гŕřŗṙ", "s": "ѕśşšŝșṡ", "t": "ţťŧțṫ",
    "u": "υսüúùûūŭůűųǔ", "v": "νѵ", "w": "ԝѡŵẁẃẅ", "x": "хχẋ",
    "y": "уүýÿŷẏ", "z": "żźžẓ",
}


class PublicSuffixList:
    """
    Parser and matcher for the Mozilla Public Suffix List.

    Supports normal, wildcard ("*.ck") and exception ("!www.ck") rules.
    Rules are stored both in Unicode and in punycode so any host form works.

    Args (constructor):
        lines (list[str]): Raw lines of the PSL file.
    """

    def __init__(self, lines: list[str]) -> None:
        """
        Parse PSL rules.

        Args:
            lines (list[str]): Raw lines (comments and blanks are ignored).
        Returns:
            None
        """
        self.rules: set[str] = set()
        self.wildcards: set[str] = set()
        self.exceptions: set[str] = set()
        for raw in lines:
            line = raw.strip().split(" ")[0].lower()
            if not line or line.startswith("//"):
                continue
            for form in {line, _to_ascii(line)}:
                if not form:
                    continue
                if form.startswith("!"):
                    self.exceptions.add(form[1:])
                elif form.startswith("*."):
                    self.wildcards.add(form[2:])
                else:
                    self.rules.add(form)

    def suffix(self, host: str) -> str:
        """
        Return the public suffix of a host.

        Args:
            host (str): Hostname (Unicode or punycode), without trailing dot.
        Returns:
            str: Public suffix (e.g. "co.uk"); the last label when no rule
            matches (PSL default "*" rule).
        """
        labels = host.lower().strip(".").split(".")
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            if cand in self.exceptions:
                return ".".join(labels[i + 1:])
            if cand in self.rules:
                return cand
            parent = ".".join(labels[i + 1:])
            if parent and parent in self.wildcards:
                return cand
        return labels[-1]

    def split(self, host: str) -> tuple[str, str, str]:
        """
        Split a host into (subdomain, name, suffix).

        Args:
            host (str): Hostname, e.g. "login.example.co.uk".
        Returns:
            tuple[str, str, str]: e.g. ("login", "example", "co.uk"). The name
            is empty when the host itself is a public suffix.
        """
        host = host.lower().strip(".")
        suffix = self.suffix(host)
        rest = host[: -len(suffix)].rstrip(".") if host != suffix else ""
        if not rest:
            return "", "", suffix
        parts = rest.split(".")
        return ".".join(parts[:-1]), parts[-1], suffix

    def registrable(self, host: str) -> str | None:
        """
        Return the registrable domain (eTLD+1) of a host.

        Args:
            host (str): Hostname.
        Returns:
            str | None: e.g. "example.co.uk", or None for bare suffixes.
        """
        _, name, suffix = self.split(host)
        return f"{name}.{suffix}" if name else None


def _to_ascii(domain: str) -> str:
    """
    Convert a (possibly Unicode) domain to punycode, best effort.

    Args:
        domain (str): Domain or PSL rule (may start with "*." or "!").
    Returns:
        str: ASCII form, or an empty string when conversion fails.
    """
    prefix = ""
    if domain.startswith("!"):
        prefix, domain = "!", domain[1:]
    try:
        labels = [
            lbl if lbl == "*" or lbl.isascii() else "xn--" + lbl.encode("punycode").decode("ascii")
            for lbl in domain.split(".")
        ]
        return prefix + ".".join(labels)
    except (UnicodeError, ValueError):
        return ""


class ResourceManager:
    """
    Downloads, refreshes and parses the external datasets.

    Parsed structures are memoised on the instance, so each file is parsed
    at most once per run.

    Args (constructor):
        http (HttpClient): Shared HTTP client.
        data_dir (Path): Directory where datasets are stored.
    """

    def __init__(self, http: HttpClient, data_dir: Path) -> None:
        """
        Prepare the manager (no I/O happens here).

        Args:
            http (HttpClient): Shared HTTP client.
            data_dir (Path): Storage directory (created if missing).
        Returns:
            None
        """
        self.http = http
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.status: dict[str, str] = {}
        self._psl: PublicSuffixList | None = None
        self._tlds: set[str] | None = None
        self._confusables: dict[str, set[str]] | None = None
        self._rdap: dict[str, str] | None = None
        self._feeds: dict[str, set[str]] | None = None
        self._feed_index: tuple[dict[str, set[str]], dict[str, set[str]]] | None = None

    def path(self, name: str) -> Path:
        """
        Local path of a dataset.

        Args:
            name (str): Resource name.
        Returns:
            Path: File location (may not exist).
        """
        res = next(r for r in RESOURCES if r.name == name)
        return self.data_dir / res.filename

    async def ensure(self, res: Resource, force: bool = False) -> str:
        """
        Make sure a dataset is present and fresh, downloading it if needed.

        Args:
            res (Resource): Dataset to check.
            force (bool): Download even when the local copy is fresh.
        Returns:
            str: One of "fresh", "downloaded", "stale" (download failed but
            an old copy exists) or "missing".
        """
        target = self.data_dir / res.filename
        if target.exists() and not force and time.time() - target.stat().st_mtime < res.ttl:
            self.status[res.name] = "fresh"
            return "fresh"
        result = await self.http.get(res.url, max_bytes=60_000_000, retries=2)
        if result.ok and result.content and not result.truncated:
            tmp = target.with_suffix(target.suffix + ".part")
            tmp.write_bytes(result.content)
            tmp.replace(target)
            state = "downloaded"
        else:
            log.warning("download failed for %s: %s", res.url, result.error or result.status)
            state = "stale" if target.exists() else "missing"
        self.status[res.name] = state
        return state

    async def ensure_all(
        self,
        include_feeds: bool = True,
        force: bool = False,
        on_done: Callable[[Resource, str], Awaitable[None] | None] | None = None,
    ) -> dict[str, str]:
        """
        Ensure every dataset concurrently.

        Args:
            include_feeds (bool): Also refresh threat feeds.
            force (bool): Force re-download.
            on_done (Callable | None): Callback `(resource, state)` invoked as
                each dataset completes (used for progress bars).
        Returns:
            dict[str, str]: Map resource name -> state.
        """
        import asyncio

        async def one(res: Resource) -> None:
            """
            Ensure a single resource and notify the callback.

            Args:
                res (Resource): Dataset to ensure.
            Returns:
                None
            """
            state = await self.ensure(res, force)
            if on_done is not None:
                maybe = on_done(res, state)
                if asyncio.iscoroutine(maybe):
                    await maybe

        await asyncio.gather(*(one(r) for r in RESOURCES if include_feeds or not r.feed))
        return dict(self.status)

    def _read_lines(self, name: str) -> list[str]:
        """
        Read a dataset as text lines (empty list if unavailable).

        Args:
            name (str): Resource name.
        Returns:
            list[str]: File lines.
        """
        p = self.path(name)
        if not p.exists():
            return []
        try:
            return p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []

    def psl(self) -> PublicSuffixList:
        """
        Parsed Public Suffix List (with built-in fallback).

        Returns:
            PublicSuffixList: Matcher instance.
        """
        if self._psl is None:
            lines = self._read_lines("psl") or _FALLBACK_PSL
            self._psl = PublicSuffixList(lines)
        return self._psl

    def tlds(self) -> set[str]:
        """
        Set of every delegated TLD (lower-case, ASCII, no IDN TLDs).

        Returns:
            set[str]: TLDs; falls back to the popular list.
        """
        if self._tlds is None:
            lines = self._read_lines("tlds")
            tlds = {
                ln.strip().lower() for ln in lines
                if ln.strip() and not ln.startswith("#") and not ln.lower().startswith("xn--")
            }
            self._tlds = tlds or {t for t in POPULAR_TLDS if "." not in t}
        return self._tlds

    def confusables(self) -> dict[str, set[str]]:
        """
        Map each ASCII letter/digit to the Unicode characters confusable with it.

        Built from Unicode's confusables.txt: only single-codepoint sources
        whose prototype is a single ASCII alphanumeric are kept. The built-in
        table is merged in, so common Latin diacritics are always present.

        Returns:
            dict[str, set[str]]: e.g. {"a": {"а", "ɑ", ...}, ...}.
        """
        if self._confusables is not None:
            return self._confusables
        table: dict[str, set[str]] = {k: set(v) for k, v in _FALLBACK_CONFUSABLES.items()}
        for line in self._read_lines("confusables"):
            if not line or line.startswith("#"):
                continue
            fields = line.split(";")
            if len(fields) < 2:
                continue
            try:
                src = [chr(int(h, 16)) for h in fields[0].split()]
                dst = [chr(int(h, 16)) for h in fields[1].split()]
            except ValueError:
                continue
            if len(src) != 1 or len(dst) != 1:
                continue
            proto = dst[0].lower()
            if proto.isascii() and proto.isalnum() and not src[0].isascii():
                table.setdefault(proto, set()).add(src[0])
        self._confusables = table
        return table

    def rdap_servers(self) -> dict[str, str]:
        """
        Map each TLD to its RDAP base URL from the IANA bootstrap file.

        Returns:
            dict[str, str]: e.g. {"com": "https://rdap.verisign.com/com/v1/"}.
        """
        if self._rdap is not None:
            return self._rdap
        servers: dict[str, str] = {}
        p = self.path("rdap")
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                for tlds, urls in data.get("services", []):
                    https = [u for u in urls if u.startswith("https://")] or urls
                    if not https:
                        continue
                    base = https[0] if https[0].endswith("/") else https[0] + "/"
                    for tld in tlds:
                        servers[tld.lower()] = base
            except (OSError, ValueError, TypeError):
                log.warning("invalid RDAP bootstrap file")
        self._rdap = servers
        return servers

    def feed_hosts(self) -> dict[str, set[str]]:
        """
        Collect every host listed in the threat feeds.

        Returns:
            dict[str, set[str]]: Map lower-case host -> names of the feeds that
            list it (e.g. {"paypa1-login.com": {"OpenPhish"}}).
        """
        if self._feeds is not None:
            return self._feeds
        hosts: dict[str, set[str]] = {}
        for res in RESOURCES:
            if not res.feed:
                continue
            label = res.label.replace(" feed", "")
            for line in self._read_lines(res.name):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                host = urlsplit(line).hostname if "://" in line else line.split("/")[0]
                if host:
                    hosts.setdefault(host.lower().strip("."), set()).add(label)
        self._feeds = hosts
        return hosts

    def feed_index(self) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
        """
        Threat-feed hits grouped by registrable domain.

        Two maps are returned because precision matters: a feed listing the
        registrable domain itself (or its "www") is strong evidence, while a
        feed listing only *subdomains* often points to a shared hosting or
        dynamic-DNS platform abused by third parties.

        Uses a fast "PSL-lite" split (multi-level suffixes from the PSL rule
        set, no wildcard handling) because feeds hold hundreds of thousands
        of hosts and full PSL matching would dominate the run time.

        Returns:
            tuple[dict[str, set[str]], dict[str, set[str]]]: (exact hits,
            subdomain-only hits), each registrable domain -> feed names.
        """
        if self._feed_index is not None:
            return self._feed_index
        rules = self.psl().rules
        exact: dict[str, set[str]] = {}
        sub: dict[str, set[str]] = {}
        for host, feeds in self.feed_hosts().items():
            labels = host.split(".")
            if len(labels) < 2:
                continue
            last2 = ".".join(labels[-2:])
            key = ".".join(labels[-3:]) if len(labels) >= 3 and last2 in rules else last2
            if key in rules:
                continue
            index = exact if host == key or host == "www." + key else sub
            bucket = index.get(key)
            if bucket is None:
                index[key] = set(feeds)
            else:
                bucket.update(feeds)
        self._feed_index = (exact, sub)
        return self._feed_index
