"""
Terminal user interface (rich), split by responsibility:

    theme.py     palette, semantic styles, banner art, gradients
    widgets.py   badges, danger bars, "why" text, tags
    live.py      live progress + "live commands" panel (Reporter protocol)
    render.py    final report: target, summary, tables, details, advice
"""

from .live import LiveReporter, SilentReporter
from .render import ResultRenderer

__all__ = ["LiveReporter", "ResultRenderer", "SilentReporter"]
