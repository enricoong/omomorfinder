"""
Tests for the live activity feed and the adaptive WHOIS pacer.
"""

import asyncio

from omomorfinder import activity
from omomorfinder.whois import RATE_LIMITED, WhoisPacer


def test_curl_command_redacts_secrets() -> None:
    """
    API keys never appear in the displayed command.

    Returns:
        None
    """
    cmd = activity.curl_command("GET", "https://www.virustotal.com/api/v3/domains/x.com",
                                headers={"x-apikey": "SECRET123"}, verify=False)
    assert "SECRET123" not in cmd and "***" in cmd and " -k " in cmd


def test_dig_and_whois_commands() -> None:
    """
    DNS and WHOIS operations map to the familiar CLI tools.

    Returns:
        None
    """
    assert activity.dig_command("example.com", "NS") == "dig +short NS example.com"
    assert activity.dig_command("example.com", "A", ["1.1.1.1"]).endswith("@1.1.1.1")
    assert activity.whois_command("whois.nic.it", "example.it") == "whois -h whois.nic.it example.it"


def test_feed_ring_buffer_and_listeners() -> None:
    """
    The feed keeps the latest items, counts kinds and notifies listeners.

    Returns:
        None
    """
    feed = activity.ActivityFeed(maxlen=3)
    seen: list[str] = []
    feed.subscribe(lambda a: seen.append(a.command))
    for i in range(5):
        feed.emit("dns", f"cmd{i}")
    assert [a.command for a in feed.recent(10)] == ["cmd2", "cmd3", "cmd4"]
    assert feed.counts["dns"] == 5 and len(seen) == 5


def test_pacer_backs_off_and_recovers() -> None:
    """
    Throttling doubles the interval (capped); successes shorten it again.

    Returns:
        None
    """
    async def scenario() -> tuple[float, float, float]:
        """
        Run the pacer state machine inside an event loop.

        Returns:
            tuple[float, float, float]: Intervals after throttles/successes.
        """
        pacer = WhoisPacer()
        pacer.throttled()
        pacer.throttled()
        slowed = pacer.interval
        for _ in range(30):
            pacer.throttled()
        capped = pacer.interval
        for _ in range(60):
            pacer.success()
        return slowed, capped, pacer.interval

    slowed, capped, recovered = asyncio.run(scenario())
    assert slowed == 8.0
    assert capped == WhoisPacer().maximum
    assert recovered == WhoisPacer().base


def test_rate_limit_detection() -> None:
    """
    Typical throttling messages are recognised.

    Returns:
        None
    """
    assert RATE_LIMITED.search("Query rate limit exceeded")
    assert not RATE_LIMITED.search("Domain: example.it\nStatus: ok")
