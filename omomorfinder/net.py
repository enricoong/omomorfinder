"""
Polite, cached, asynchronous HTTP client.

Features:
  * per-host rate limiting (minimum interval + random jitter + concurrency),
  * exponential back-off with `Retry-After` support on 429 / 5xx,
  * request coalescing ("single flight"): identical concurrent requests are
    performed once and shared,
  * transparent two-level caching through `cache.Cache`,
  * streaming download with a hard byte cap (protects memory against huge or
    malicious responses),
  * HTTP/2 when the `h2` package is available, optional proxy (Tor / Burp).
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import activity
from .cache import Cache
from .config import DEFAULT_RATE, RDAP_RATE, RateRule, Settings

# Hosts of the threat-intelligence APIs (activity feed classification).
_INTEL_HOSTS = ("virustotal.com", "abuseipdb.com", "urlscan.io")


def activity_kind(host: str, url: str = "") -> str:
    """
    Classify an HTTP request for the live activity feed.

    Args:
        host (str): Request hostname.
        url (str): Full URL (RDAP endpoints may live on generic hosts).
    Returns:
        str: "rdap", "ct", "intel" or "http".
    """
    if "rdap" in host or "/rdap/" in url:
        return "rdap"
    if host == "crt.sh":
        return "ct"
    if host.endswith(_INTEL_HOSTS):
        return "intel"
    return "http"

log = logging.getLogger(__name__)

try:  # HTTP/2 is optional: it needs the `h2` package.
    import h2  # noqa: F401

    _HTTP2 = True
except ImportError:  # pragma: no cover - depends on environment
    _HTTP2 = False

RETRY_STATUSES = {429, 500, 502, 503, 504, 520, 522, 524}


class QuotaExceeded(RuntimeError):
    """
    Raised when an API reports that the daily/monthly quota is exhausted.

    The caller is expected to disable that API for the rest of the scan
    instead of retrying.
    """


@dataclass(slots=True)
class HttpResult:
    """
    Outcome of one HTTP request (successful or not).

    Attributes:
        url (str): Requested URL.
        final_url (str): URL after redirects.
        status (int): HTTP status code (0 when the request failed).
        headers (dict[str, str]): Lower-cased response headers.
        content (bytes): Response body (possibly truncated).
        history (list[str]): Redirect chain, first hop first.
        error (str | None): Error description when the request failed.
        from_cache (bool): True when served from the cache.
        tls_verified (bool): False when certificate verification was off.
        truncated (bool): True when the body exceeded the byte cap.
        elapsed (float): Seconds spent on the network.
    """

    url: str
    final_url: str = ""
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    content: bytes = b""
    history: list[str] = field(default_factory=list)
    error: str | None = None
    from_cache: bool = False
    tls_verified: bool = True
    truncated: bool = False
    elapsed: float = 0.0

    @property
    def ok(self) -> bool:
        """
        Whether the request succeeded with a 2xx status.

        Returns:
            bool: True for 200-299 responses without transport errors.
        """
        return self.error is None and 200 <= self.status < 300

    @property
    def is_tls_error(self) -> bool:
        """
        Whether the failure was caused by certificate validation.

        Returns:
            bool: True when the error message looks like a TLS failure.
        """
        if not self.error:
            return False
        msg = self.error.lower()
        return any(k in msg for k in ("certificate", "ssl", "tls", "handshake"))

    @property
    def text(self) -> str:
        """
        Decode the body using the declared charset (UTF-8 fallback).

        Returns:
            str: Decoded text; undecodable bytes are replaced.
        """
        ctype = self.headers.get("content-type", "")
        charset = "utf-8"
        if "charset=" in ctype:
            charset = ctype.split("charset=", 1)[1].split(";")[0].strip(" \"'") or "utf-8"
        try:
            return self.content.decode(charset, errors="replace")
        except LookupError:
            return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        """
        Parse the body as JSON.

        Returns:
            Any: Decoded JSON value, or None when the body is not JSON.
        """
        try:
            return json.loads(self.content)
        except (ValueError, UnicodeDecodeError):
            return None

    def to_meta(self) -> dict[str, Any]:
        """
        Serialise everything except the body for the cache.

        Returns:
            dict[str, Any]: JSON-friendly metadata.
        """
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "headers": self.headers,
            "history": self.history,
            "error": self.error,
            "tls_verified": self.tls_verified,
            "truncated": self.truncated,
        }

    @classmethod
    def from_meta(cls, meta: dict[str, Any], blob: bytes | None) -> HttpResult:
        """
        Rebuild a result from cached metadata and body.

        Args:
            meta (dict[str, Any]): Output of `to_meta`.
            blob (bytes | None): Cached body.
        Returns:
            HttpResult: Result flagged with `from_cache=True`.
        """
        return cls(
            url=meta.get("url", ""),
            final_url=meta.get("final_url", ""),
            status=int(meta.get("status", 0)),
            headers=dict(meta.get("headers") or {}),
            content=blob or b"",
            history=list(meta.get("history") or []),
            error=meta.get("error"),
            from_cache=True,
            tls_verified=bool(meta.get("tls_verified", True)),
            truncated=bool(meta.get("truncated", False)),
        )


class HostLimiter:
    """
    Async context manager enforcing a `RateRule` for a single host.

    Each `async with limiter:` waits until the host's next free slot and
    holds one of its concurrency permits for the duration of the request.

    Args (constructor):
        rule (RateRule): Interval, jitter and concurrency for the host.
    """

    def __init__(self, rule: RateRule) -> None:
        """
        Initialise the limiter state.

        Args:
            rule (RateRule): Politeness rule to enforce.
        Returns:
            None
        """
        self.rule = rule
        self._sem = asyncio.Semaphore(max(1, rule.concurrency))
        self._lock = asyncio.Lock()
        self._next_slot = 0.0

    async def penalize(self, seconds: float) -> None:
        """
        Push the next free slot forward (used after 429 / Retry-After).

        Args:
            seconds (float): Delay to add from now.
        Returns:
            None
        """
        async with self._lock:
            self._next_slot = max(self._next_slot, time.monotonic() + seconds)

    async def __aenter__(self) -> HostLimiter:
        """
        Acquire a concurrency permit and wait for the next time slot.

        Returns:
            HostLimiter: The limiter itself.
        """
        await self._sem.acquire()
        try:
            async with self._lock:
                now = time.monotonic()
                wait = max(0.0, self._next_slot - now)
                gap = self.rule.min_interval + random.uniform(0, self.rule.jitter)
                self._next_slot = max(now, self._next_slot) + gap
            if wait > 0:
                await asyncio.sleep(wait)
        except BaseException:  # cancelled while waiting: give the permit back
            self._sem.release()
            raise
        return self

    async def __aexit__(self, *exc: object) -> None:
        """
        Release the concurrency permit.

        Args:
            *exc (object): Exception info (ignored).
        Returns:
            None
        """
        self._sem.release()


class HttpClient:
    """
    Shared asynchronous HTTP client used by every module.

    Args (constructor):
        settings (Settings): Scan configuration (timeouts, proxy, rules).
        cache (Cache): Persistent cache instance.
    """

    def __init__(self, settings: Settings, cache: Cache) -> None:
        """
        Create the underlying httpx clients (verified and unverified TLS).

        Args:
            settings (Settings): Scan configuration.
            cache (Cache): Shared cache.
        Returns:
            None
        """
        self.settings = settings
        self.cache = cache
        common: dict[str, Any] = {
            "http2": _HTTP2,
            "timeout": httpx.Timeout(settings.http_timeout, connect=8.0),
            "limits": httpx.Limits(max_connections=120, max_keepalive_connections=40),
            "headers": {
                "User-Agent": settings.user_agent,
                "Accept-Language": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
            },
        }
        if settings.proxy:
            common["proxy"] = settings.proxy
        self._secure = httpx.AsyncClient(verify=True, **common)
        self._insecure = httpx.AsyncClient(verify=False, **common)
        self._limiters: dict[str, HostLimiter] = {}
        self._inflight: dict[str, asyncio.Future[HttpResult]] = {}
        self.requests_sent = 0
        self.bytes_received = 0

    def limiter_for(self, host: str) -> HostLimiter:
        """
        Return (creating it on first use) the limiter of a host.

        Args:
            host (str): Hostname of the request.
        Returns:
            HostLimiter: Limiter enforcing the host's rule.
        """
        lim = self._limiters.get(host)
        if lim is None:
            rule = self.settings.rate_rules.get(host)
            if rule is None:
                rule = RDAP_RATE if "rdap" in host else DEFAULT_RATE
            lim = HostLimiter(rule)
            self._limiters[host] = lim
        return lim

    async def get(self, url: str, **kwargs: Any) -> HttpResult:
        """
        Shortcut for `request("GET", url, ...)`.

        Args:
            url (str): Target URL.
            **kwargs (Any): Forwarded to `request`.
        Returns:
            HttpResult: Request outcome.
        """
        return await self.request("GET", url, **kwargs)

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        cache_ns: str | None = None,
        ttl: float = 0,
        error_ttl: float = 0,
        max_bytes: int = 5_000_000,
        follow_redirects: bool = True,
        verify: bool = True,
        retries: int = 2,
        retry_on_connect: bool = True,
        timeout: float | None = None,
    ) -> HttpResult:
        """
        Perform an HTTP request with caching, coalescing and politeness.

        Args:
            method (str): HTTP method.
            url (str): Absolute URL.
            headers (dict[str, str] | None): Extra headers (never part of the
                cache key, so API keys are not hashed into it).
            params (dict[str, Any] | None): Query string parameters.
            cache_ns (str | None): Cache namespace; None disables caching.
            ttl (float): Cache lifetime for successful/definitive answers.
            error_ttl (float): Cache lifetime for transport errors (0 = none).
            max_bytes (int): Body size cap; longer bodies are truncated.
            follow_redirects (bool): Follow 3xx responses.
            verify (bool): Verify TLS certificates.
            retries (int): Retries for 429/5xx and (optionally) transport
                errors.
            retry_on_connect (bool): Also retry connection errors/timeouts.
            timeout (float | None): Per-request read timeout overriding the
                client default (slow APIs such as crt.sh need more).
        Returns:
            HttpResult: Request outcome (never raises for network errors).
        """
        key = Cache.make_key(method, url, sorted((params or {}).items()), verify)
        if cache_ns and ttl:
            hit = self.cache.get(cache_ns, key)
            if hit is not None and isinstance(hit[0], dict):
                return HttpResult.from_meta(hit[0], hit[1])

        pending = self._inflight.get(key)
        if pending is not None:
            return await asyncio.shield(pending)

        future: asyncio.Future[HttpResult] = asyncio.get_running_loop().create_future()
        self._inflight[key] = future
        try:
            result = await self._perform(
                method, url, headers, params, max_bytes, follow_redirects,
                verify, retries, retry_on_connect, timeout,
            )
            if cache_ns:
                if result.error is None and result.status and result.status < 500 and ttl:
                    self.cache.set(cache_ns, key, result.to_meta(), result.content, ttl)
                elif result.error is not None and error_ttl:
                    self.cache.set(cache_ns, key, result.to_meta(), b"", error_ttl)
            future.set_result(result)
            return result
        except asyncio.CancelledError:
            if not future.done():
                future.cancel()
            raise
        except Exception as exc:  # propagate unexpected errors to waiters too
            if not future.done():
                future.set_exception(exc)
                future.exception()  # mark retrieved to silence warnings
            raise
        finally:
            self._inflight.pop(key, None)

    async def _perform(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        params: dict[str, Any] | None,
        max_bytes: int,
        follow_redirects: bool,
        verify: bool,
        retries: int,
        retry_on_connect: bool,
        timeout: float | None = None,
    ) -> HttpResult:
        """
        Network part of `request`: limiter, streaming download, retries.

        Args:
            method (str): HTTP method.
            url (str): Absolute URL.
            headers (dict[str, str] | None): Extra headers.
            params (dict[str, Any] | None): Query parameters.
            max_bytes (int): Body size cap.
            follow_redirects (bool): Follow redirects.
            verify (bool): Verify TLS certificates.
            retries (int): Maximum retries.
            retry_on_connect (bool): Retry on transport errors.
            timeout (float | None): Per-request read timeout override.
        Returns:
            HttpResult: Outcome of the last attempt.
        """
        host = urlsplit(url).hostname or ""
        limiter = self.limiter_for(host)
        client = self._secure if verify else self._insecure
        req_timeout: Any = httpx.Timeout(timeout, connect=10.0) if timeout else httpx.USE_CLIENT_DEFAULT
        # httpx timeouts apply per network operation: a tarpit server that
        # trickles one byte at a time would never time out. A hard deadline
        # on the whole exchange prevents that.
        deadline = (timeout or self.settings.http_timeout) * 2.5
        attempt = 0
        result = HttpResult(url=url, tls_verified=verify)
        while True:
            started = time.monotonic()
            result = HttpResult(url=url, tls_verified=verify)
            async with limiter:
                activity.emit(activity_kind(host, url), activity.curl_command(method, url, params, headers, verify))
                try:
                    async with asyncio.timeout(deadline):
                        async with client.stream(
                            method, url, headers=headers, params=params,
                            follow_redirects=follow_redirects, timeout=req_timeout,
                        ) as resp:
                            chunks: list[bytes] = []
                            total = 0
                            async for chunk in resp.aiter_bytes():
                                chunks.append(chunk)
                                total += len(chunk)
                                if total >= max_bytes:
                                    result.truncated = True
                                    break
                            result.content = b"".join(chunks)[:max_bytes]
                            result.status = resp.status_code
                            result.final_url = str(resp.url)
                            result.headers = {k.lower(): v for k, v in resp.headers.items()}
                            result.history = [str(r.url) for r in resp.history]
                except TimeoutError:
                    result.error = f"TotalTimeout: no complete answer within {deadline:.0f}s"
                except httpx.HTTPError as exc:
                    result.error = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
                except (OSError, ValueError) as exc:  # DNS failures, bad URLs
                    result.error = f"{type(exc).__name__}: {exc}"
            result.elapsed = time.monotonic() - started
            self.requests_sent += 1
            self.bytes_received += len(result.content)

            retryable = (
                (result.error is not None and retry_on_connect and not result.is_tls_error)
                or result.status in RETRY_STATUSES
            )
            if not retryable or attempt >= retries:
                return result
            attempt += 1
            delay = self._retry_delay(result, attempt)
            log.debug("retry %s in %.1fs (%s)", url, delay, result.error or result.status)
            await limiter.penalize(delay)
            await asyncio.sleep(delay)

    @staticmethod
    def _retry_delay(result: HttpResult, attempt: int) -> float:
        """
        Compute the back-off delay before the next attempt.

        Honors a numeric `Retry-After` header (capped at 90 s), otherwise
        uses exponential back-off with jitter.

        Args:
            result (HttpResult): Failed attempt.
            attempt (int): 1-based retry number.
        Returns:
            float: Seconds to wait.
        """
        retry_after = result.headers.get("retry-after", "")
        if retry_after.isdigit():
            return min(float(retry_after), 90.0)
        return min(2.0 ** attempt + random.uniform(0, 1.0), 30.0)

    async def close(self) -> None:
        """
        Close both underlying httpx clients.

        Returns:
            None
        """
        await asyncio.gather(self._secure.aclose(), self._insecure.aclose(), return_exceptions=True)
