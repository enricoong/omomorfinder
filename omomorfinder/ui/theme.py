"""
Visual identity of the terminal UI: palette, semantic styles, banner art
and the gradient helpers. Every other UI module takes its colours from
here, so the look can be changed in one place.
"""

from __future__ import annotations

from rich.text import Text

PALETTE: tuple[str, ...] = ("#00e5ff", "#4f8bff", "#9b5cff", "#ff4fd8")
ACCENT = "#9b5cff"
MUTED = "grey58"
DIM = "grey42"

CATEGORY_STYLE: dict[str, str] = {
    "MALICIOUS": "bold white on #d7263d",
    "SUSPICIOUS": "bold black on #ff9f1c",
    "PARKED": "bold black on #e9c46a",
    "COMPETITOR": "bold white on #3a86ff",
    "REGISTERED": "bold white on #5c677d",
    "DEFENSIVE": "bold black on #2ec4b6",
    "UNVERIFIED": "bold white on #495057",
    "AVAILABLE": "#ced4da on #2b2d42",
}
RISK_STYLE: dict[str, str] = {
    "CRITICAL": "bold #ff2e63", "HIGH": "bold #ff7b00", "MEDIUM": "bold #ffd000",
    "LOW": "#4cc9f0", "INFO": MUTED,
}
RISK_BAR: dict[str, str] = {
    "CRITICAL": "#ff2e63", "HIGH": "#ff7b00", "MEDIUM": "#ffd000", "LOW": "#4cc9f0", "INFO": DIM,
}
# Colour of each activity kind in the live commands panel.
KIND_STYLE: dict[str, str] = {
    "dns": "#00e5ff", "http": "#4f8bff", "rdap": "#9b5cff", "whois": "#ff4fd8",
    "ct": "#ffd000", "intel": "#ff7b00", "browser": "#2ec4b6", "nlp": "#e9c46a",
}

BANNER_WIDE = r"""
 ██████╗ ███╗   ███╗ ██████╗ ███╗   ███╗ ██████╗ ██████╗ ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗
██╔═══██╗████╗ ████║██╔═══██╗████╗ ████║██╔═══██╗██╔══██╗██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
██║   ██║██╔████╔██║██║   ██║██╔████╔██║██║   ██║██████╔╝█████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
██║   ██║██║╚██╔╝██║██║   ██║██║╚██╔╝██║██║   ██║██╔══██╗██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
╚██████╔╝██║ ╚═╝ ██║╚██████╔╝██║ ╚═╝ ██║╚██████╔╝██║  ██║██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
 ╚═════╝ ╚═╝     ╚═╝ ╚═════╝ ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
""".strip("\n")

BANNER_NARROW = r"""
  ____                            _____         __
 / __ \__ _  ___  __ _  ___  ____/ __(_)__  ___/ /__ ____
/ /_/ /  ' \/ _ \/  ' \/ _ \/ __/ _// / _ \/ _  / -_) __/
\____/_/_/_/\___/_/_/_/\___/_/ /_/ /_/_//_/\_,_/\__/_/
""".strip("\n")


def _hex_to_rgb(color: str) -> tuple[int, int, int]:
    """
    Convert "#rrggbb" to an RGB tuple.

    Args:
        color (str): Hex colour.
    Returns:
        tuple[int, int, int]: Red, green, blue (0-255).
    """
    c = color.lstrip("#")
    return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)


def blend(colors: tuple[str, ...], t: float) -> str:
    """
    Interpolate along a multi-stop colour gradient.

    Args:
        colors (tuple[str, ...]): Hex colour stops.
        t (float): Position in [0, 1].
    Returns:
        str: Interpolated "#rrggbb" colour.
    """
    t = min(max(t, 0.0), 1.0)
    seg = t * (len(colors) - 1)
    i = min(int(seg), len(colors) - 2)
    f = seg - i
    a, b = _hex_to_rgb(colors[i]), _hex_to_rgb(colors[i + 1])
    r, g, bl = (round(x + (y - x) * f) for x, y in zip(a, b, strict=True))
    return f"#{r:02x}{g:02x}{bl:02x}"


def gradient(text: str, colors: tuple[str, ...] = PALETTE, bold: bool = True) -> Text:
    """
    Colour multi-line text with a horizontal gradient.

    Args:
        text (str): Text (may contain newlines).
        colors (tuple[str, ...]): Gradient stops.
        bold (bool): Bold glyphs.
    Returns:
        Text: Styled rich Text.
    """
    lines = text.splitlines() or [text]
    width = max((len(line) for line in lines), default=1) or 1
    out = Text()
    for n, line in enumerate(lines):
        for x, ch in enumerate(line):
            style = f"{'bold ' if bold else ''}{blend(colors, x / max(width - 1, 1))}"
            out.append(ch, style=style)
        if n < len(lines) - 1:
            out.append("\n")
    return out
