"""
Runtime configuration for OmomorFinder.

This module centralises every tunable value (profiles, rate limits, cache
TTLs, paths, API keys) so the rest of the code never hard-codes them.
API keys are read from environment variables or from `.env` files located in
the current directory or in the user's config directory.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from . import __app_name__, __version__

APP_SLUG = "omomorfinder"


def _xdg_dir(env_var: str, fallback: str) -> Path:
    """
    Resolve an XDG base directory for the application.

    Args:
        env_var (str): XDG environment variable name (e.g. "XDG_CACHE_HOME").
        fallback (str): Path relative to the home directory used when the
            variable is not set (e.g. ".cache").
    Returns:
        Path: Application-specific directory (not yet created).
    """
    base = os.environ.get(env_var)
    root = Path(base) if base else Path.home() / fallback
    return root / APP_SLUG


CACHE_DIR: Path = _xdg_dir("XDG_CACHE_HOME", ".cache")
DATA_DIR: Path = _xdg_dir("XDG_DATA_HOME", ".local/share")
CONFIG_DIR: Path = _xdg_dir("XDG_CONFIG_HOME", ".config")

USER_AGENT = (
    f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    f"Chrome/131.0 Safari/537.36 {__app_name__}/{__version__}"
)


def load_dotenv_files() -> list[Path]:
    """
    Load KEY=VALUE pairs from `.env` files into `os.environ`.

    Looks in the current working directory and in the application config
    directory. Existing environment variables are never overwritten, so a
    variable exported in the shell always wins.

    Returns:
        list[Path]: The `.env` files that were found and loaded.
    """
    loaded: list[Path] = []
    for candidate in (Path.cwd() / ".env", CONFIG_DIR / ".env"):
        if not candidate.is_file():
            continue
        try:
            lines = candidate.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip().removeprefix("export ").strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
        loaded.append(candidate)
    return loaded


@dataclass(slots=True)
class RateRule:
    """
    Politeness rule applied to every request towards one host.

    Attributes:
        min_interval (float): Minimum seconds between two requests.
        jitter (float): Extra random delay in seconds (0..jitter) added to
            every wait, to avoid a robotic request pattern.
        concurrency (int): Maximum simultaneous in-flight requests.
    """

    min_interval: float = 0.25
    jitter: float = 0.25
    concurrency: int = 4


@dataclass(slots=True)
class Settings:
    """
    Complete runtime configuration for one scan.

    Attributes:
        profile (str): "fast", "standard" or "deep".
        tld_mode (str): "popular", "all" or a comma separated TLD list.
        keyboard (str): Keyboard layout for typo generation.
        fuzzers (set[str] | None): Restrict generation to these fuzzers.
        extra_words (list[str]): Additional combosquatting dictionary words.
        resolvers (list[str]): Custom DNS resolvers (empty = system).
        dns_concurrency (int): Parallel DNS queries.
        http_concurrency (int): Parallel content fetches (global).
        http_timeout (float): Per-request timeout in seconds.
        max_page_bytes (int): Hard cap on downloaded HTML size.
        max_image_bytes (int): Hard cap on downloaded image size.
        vt_limit (int): Max domains sent to VirusTotal per scan.
        abuse_limit (int): Max IPs sent to AbuseIPDB per scan.
        whois_limit (int): Max uncached queries per port-43 WHOIS server.
        ct_enabled (bool): Query Certificate Transparency.
        use_cache (bool): Read from the persistent cache.
        include_mixed_script (bool): Keep mixed-script IDN candidates.
        user_agent (str): User-Agent header.
        proxy (str | None): Optional HTTP/SOCKS proxy URL for web requests
            (e.g. "socks5://127.0.0.1:9050" for Tor, or Burp).
        vt_api_key (str | None): VirusTotal key.
        abuseipdb_api_key (str | None): AbuseIPDB key.
        urlscan_api_key (str | None): urlscan.io key.
        vt_rate_per_min (float): VirusTotal quota (4 on the free tier).
        rate_rules (dict[str, RateRule]): Per-host politeness overrides.
    """

    profile: str = "standard"
    tld_mode: str = "popular"
    keyboard: str = "qwerty"
    fuzzers: set[str] | None = None
    extra_words: list[str] = field(default_factory=list)
    resolvers: list[str] = field(default_factory=list)
    dns_concurrency: int = 150
    http_concurrency: int = 16
    http_timeout: float = 12.0
    max_page_bytes: int = 2_500_000
    max_image_bytes: int = 1_500_000
    vt_limit: int = 25
    abuse_limit: int = 80
    whois_limit: int = 80
    ct_enabled: bool = True
    use_cache: bool = True
    include_mixed_script: bool = False
    user_agent: str = USER_AGENT
    proxy: str | None = None
    vt_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    urlscan_api_key: str | None = None
    vt_rate_per_min: float = 4.0
    rate_rules: dict[str, RateRule] = field(default_factory=dict)

    @property
    def deep(self) -> bool:
        """
        Whether heavy optional analyses (screenshots, ORB, embeddings) run.

        Returns:
            bool: True only for the "deep" profile.
        """
        return self.profile == "deep"

    @property
    def fast(self) -> bool:
        """
        Whether only the cheap stages (generation + DNS + lexical) run.

        Returns:
            bool: True only for the "fast" profile.
        """
        return self.profile == "fast"

    def load_api_keys(self) -> None:
        """
        Populate API keys and quotas from the environment.

        Reads VT_API_KEY, ABUSEIPDB_API_KEY, URLSCAN_API_KEY and
        VT_RATE_PER_MIN (premium VirusTotal accounts can raise it).

        Returns:
            None
        """
        self.vt_api_key = os.environ.get("VT_API_KEY") or None
        self.abuseipdb_api_key = os.environ.get("ABUSEIPDB_API_KEY") or None
        self.urlscan_api_key = os.environ.get("URLSCAN_API_KEY") or None
        try:
            self.vt_rate_per_min = float(os.environ.get("VT_RATE_PER_MIN", "4"))
        except ValueError:
            self.vt_rate_per_min = 4.0

    def build_rate_rules(self) -> None:
        """
        Build the per-host politeness table from the current settings.

        VirusTotal gets an interval derived from its per-minute quota,
        crt.sh and WHOIS-like services get conservative intervals because
        they are shared community resources.

        Returns:
            None
        """
        vt_interval = 60.0 / max(self.vt_rate_per_min, 0.1) + 0.4
        self.rate_rules = {
            "www.virustotal.com": RateRule(vt_interval, 0.5, 1),
            "api.abuseipdb.com": RateRule(0.8, 0.4, 2),
            "crt.sh": RateRule(4.0, 1.5, 1),
            "urlscan.io": RateRule(2.2, 0.5, 1),
            "data.iana.org": RateRule(1.0, 0.3, 2),
            "publicsuffix.org": RateRule(1.0, 0.3, 1),
            "www.unicode.org": RateRule(1.0, 0.3, 1),
        }


# Default politeness for any host without a specific rule.
DEFAULT_RATE = RateRule(min_interval=0.35, jitter=0.35, concurrency=3)
# RDAP servers are shared by many domains, keep them gentle.
RDAP_RATE = RateRule(min_interval=0.5, jitter=0.3, concurrency=3)
# Port-43 WHOIS servers are the most aggressive at banning.
WHOIS_RATE = RateRule(min_interval=1.5, jitter=0.6, concurrency=1)

# Cache time-to-live values, in seconds.
TTL = {
    "dns": 3600,
    "rdap": 86400,
    "whois": 86400,
    "whois_refer": 30 * 86400,
    "vt": 86400,
    "abuseipdb": 86400,
    "crtsh": 12 * 3600,
    "urlscan": 12 * 3600,
    "page": 6 * 3600,
    "image": 3 * 86400,
}
