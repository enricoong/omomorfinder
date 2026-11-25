"""
Live activity feed: what the scanner is doing *right now*, expressed as the
equivalent shell command an analyst would type (dig, whois, curl, ...).

Every network component (DNS resolver, HTTP client, WHOIS client, headless
browser, NLP model) publishes an event here; the terminal UI subscribes and
shows the most recent commands under the progress bars. The module has no
dependency on the UI, so the pipeline stays usable headless (--json/-q).
"""

from __future__ import annotations

import shlex
import threading
import time
from collections import Counter, deque
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlencode

# Header names whose values must never be shown (API keys, cookies).
SECRET_HEADERS = frozenset({"x-apikey", "key", "api-key", "authorization", "cookie"})
# Header names omitted from the displayed command (noise, not information).
NOISE_HEADERS = frozenset({"accept", "accept-language"})


@dataclass(slots=True, frozen=True)
class Activity:
    """
    One executed operation.

    Attributes:
        ts (float): Unix timestamp.
        kind (str): Category: "dns", "http", "rdap", "whois", "ct",
            "intel", "browser", "nlp".
        command (str): Equivalent shell command (secrets redacted).
    """

    ts: float
    kind: str
    command: str


class ActivityFeed:
    """
    Thread-safe ring buffer of recent activities with listeners.

    Args (constructor):
        maxlen (int): Number of activities kept in memory.
    """

    def __init__(self, maxlen: int = 300) -> None:
        """
        Create an empty feed.

        Args:
            maxlen (int): Ring buffer size.
        Returns:
            None
        """
        self._items: deque[Activity] = deque(maxlen=maxlen)
        self._listeners: list[Callable[[Activity], None]] = []
        self._lock = threading.Lock()
        self.counts: Counter[str] = Counter()

    def emit(self, kind: str, command: str) -> None:
        """
        Publish an activity.

        Args:
            kind (str): Activity category.
            command (str): Equivalent shell command.
        Returns:
            None
        """
        item = Activity(time.time(), kind, command)
        with self._lock:
            self._items.append(item)
            self.counts[kind] += 1
            listeners = list(self._listeners)
        for listener in listeners:
            listener(item)

    def recent(self, n: int) -> list[Activity]:
        """
        The `n` most recent activities, oldest first.

        Args:
            n (int): Number of activities.
        Returns:
            list[Activity]: Recent activities.
        """
        with self._lock:
            return list(self._items)[-n:]

    def subscribe(self, listener: Callable[[Activity], None]) -> None:
        """
        Register a callback invoked for every new activity.

        Args:
            listener (Callable[[Activity], None]): Callback.
        Returns:
            None
        """
        with self._lock:
            self._listeners.append(listener)

    def reset(self) -> None:
        """
        Clear activities, counters and listeners (start of a new scan).

        Returns:
            None
        """
        with self._lock:
            self._items.clear()
            self.counts.clear()
            self._listeners.clear()


FEED = ActivityFeed()


def emit(kind: str, command: str) -> None:
    """
    Publish an activity on the global feed.

    Args:
        kind (str): Activity category.
        command (str): Equivalent shell command.
    Returns:
        None
    """
    FEED.emit(kind, command)


def dig_command(name: str, rdtype: str, resolvers: list[str] | None = None) -> str:
    """
    Equivalent `dig` command of a DNS query.

    Args:
        name (str): Queried name.
        rdtype (str): Record type.
        resolvers (list[str] | None): Custom resolvers (first one shown).
    Returns:
        str: e.g. "dig +short NS example.com @1.1.1.1".
    """
    server = f" @{resolvers[0]}" if resolvers else ""
    return f"dig +short {rdtype} {shlex.quote(name)}{server}"


def whois_command(server: str, query: str) -> str:
    """
    Equivalent `whois` command of a port-43 query.

    Args:
        server (str): WHOIS server.
        query (str): Query line.
    Returns:
        str: e.g. "whois -h whois.nic.it example.it".
    """
    return f"whois -h {server} {shlex.quote(query)}"


def curl_command(method: str, url: str, params: dict | None = None,
                 headers: dict[str, str] | None = None, verify: bool = True) -> str:
    """
    Equivalent `curl` command of an HTTP request (secrets redacted).

    Args:
        method (str): HTTP method.
        url (str): URL without query string.
        params (dict | None): Query parameters.
        headers (dict[str, str] | None): Extra request headers.
        verify (bool): TLS verification (False adds -k).
    Returns:
        str: e.g. "curl -sL -H 'x-apikey: ***' 'https://...'".
    """
    full = f"{url}?{urlencode(params)}" if params else url
    parts = ["curl -sL"]
    if method.upper() != "GET":
        parts.append(f"-X {method.upper()}")
    if not verify:
        parts.append("-k")
    for name, value in (headers or {}).items():
        if name.lower() in NOISE_HEADERS:
            continue
        shown = "***" if name.lower() in SECRET_HEADERS else value
        parts.append(f"-H {shlex.quote(f'{name}: {shown}')}")
    parts.append(shlex.quote(full))
    return " ".join(parts)
