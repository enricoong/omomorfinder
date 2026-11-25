"""
Small reusable renderables: badges, score bars, ages, signal tags and the
"why" summary of a score. Pure functions: data in, rich `Text` out.
"""

from __future__ import annotations

from rich.text import Text

from ..models import Candidate
from ..scoring import top_reasons
from .theme import DIM, MUTED, RISK_BAR, RISK_STYLE


def badge(label: str, style: str) -> Text:
    """
    Pill-shaped badge.

    Args:
        label (str): Badge text.
        style (str): Rich style.
    Returns:
        Text: " LABEL " styled.
    """
    return Text(f" {label} ", style=style)


def score_bar(score: int, risk: str, width: int = 10, show_risk: bool = False) -> Text:
    """
    Segmented danger bar with the numeric score (and optionally the level).

    Args:
        score (int): Score 0-100.
        risk (str): Risk level (bar colour).
        width (int): Number of segments.
        show_risk (bool): Append the risk level name.
    Returns:
        Text: e.g. "▰▰▰▰▰▰▱▱▱▱  63 HIGH".
    """
    filled = round(score / 100 * width)
    t = Text()
    t.append("▰" * filled, style=RISK_BAR.get(risk, "white"))
    t.append("▱" * (width - filled), style="grey30")
    t.append(f" {score:>3}", style=RISK_STYLE.get(risk, "white"))
    if show_risk:
        t.append(f" {risk}", style=RISK_STYLE.get(risk, "white"))
    return t


def human_age(days: int | None) -> str:
    """
    Short human readable age.

    Args:
        days (int | None): Age in days.
    Returns:
        str: "12d", "5mo", "3y" or "-".
    """
    if days is None:
        return "-"
    if days < 60:
        return f"{days}d"
    if days < 730:
        return f"{days // 30}mo"
    return f"{days // 365}y"


def why_text(c: Candidate, limit: int = 3) -> Text:
    """
    The reasons behind a score, strongest first, one per line.

    Args:
        c (Candidate): Scored candidate.
        limit (int): Maximum number of reasons.
    Returns:
        Text: e.g. "+35 listed in OpenPhish\\n+15 brand used in subdomain ...".
    """
    out = Text()
    items = top_reasons(c, limit)
    if not items:
        return Text("no risk signal", style=DIM)
    for n, item in enumerate(items):
        if n:
            out.append("\n")
        style = "bold #2ec4b6" if item.points < 0 else ("bold #ff2e63" if item.points >= 15 else "bold #ff7b00")
        out.append(f"{item.points:+.0f} ", style=style)
        out.append(item.label, style="white" if item.points >= 15 else MUTED)
    return out


def signal_tags(c: Candidate) -> Text:
    """
    Compact coloured tags summarising the strongest signals.

    Args:
        c (Candidate): Scored candidate.
    Returns:
        Text: e.g. "feed  VT 4  login  logo 97%  MX".
    """
    tags: list[tuple[str, str]] = []
    if c.feeds:
        tags.append(("feed", "bold #ff2e63"))
    elif c.feed_subdomains:
        tags.append(("feed:sub", "#ff7b00"))
    if any(sd.brand for sd in c.subdomains):
        tags.append(("brand-sub", "bold #ff2e63"))
    if c.page and c.page.filtered:
        tags.append(("filtered", "#ff7b00"))
    if c.vt and c.vt.malicious:
        tags.append((f"VT {c.vt.malicious}", "bold #ff2e63"))
    p, v = c.page, c.visual
    if p and p.has_password:
        tags.append(("password", "#ff7b00"))
    elif p and p.has_login_form:
        tags.append(("login", "#ff7b00"))
    if v and (v.favicon_match or v.logo_similarity >= 0.85):
        tags.append(("logo", "#ff7b00"))
    if c.dns.mx:
        tags.append(("MX", "#4cc9f0"))
    if p and p.parked:
        tags.append(("parked", "#e9c46a"))
    if c.homograph:
        tags.append(("homograph", "#ff4fd8"))
    if c.ascii != c.domain:
        tags.append(("IDN", "#ff4fd8"))
    out = Text()
    for i, (label, style) in enumerate(tags[:6]):
        if i:
            out.append(" ")
        out.append(label, style=style)
    return out


def policy_text(record: str | None, kind: str) -> Text:
    """
    Colour an SPF/DMARC record by strength.

    Args:
        record (str | None): Raw TXT record.
        kind (str): "spf" or "dmarc".
    Returns:
        Text: Styled record or a "missing" warning.
    """
    if not record:
        return Text("missing  (spoofing of the real domain is easier)", style="bold #ff2e63")
    low = record.lower().replace(" ", "")
    strong = ("-all" in low) if kind == "spf" else ("p=reject" in low or "p=quarantine" in low)
    return Text(record[:90], style="#2ec4b6" if strong else "#ffd000")
