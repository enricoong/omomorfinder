"""
Optional machine-readable exports of a scan: JSON (complete) and CSV (one
row per domain). Nothing is written unless the user asks for an output
directory with `-o/--output`.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from . import __app_name__, __version__
from .engine import ScanResult
from .models import Candidate, to_jsonable

CSV_FIELDS: tuple[str, ...] = (
    "rank", "domain", "ascii", "score", "risk", "category", "lexical", "homograph", "techniques",
    "registered", "created", "registrar", "registrant", "ips", "mx", "ns", "web_status", "final_url",
    "title", "password_form", "login_form", "brand_mentions", "logo_similarity", "favicon_match",
    "text_similarity", "semantic_similarity", "vt_malicious", "abuse_score", "feeds", "ct_certs",
    "parked", "web_filtered", "reasons",
)


def write_json(result: ScanResult, path: Path) -> Path:
    """
    Export the complete scan result as JSON.

    Args:
        result (ScanResult): Scan result.
        path (Path): Destination file.
    Returns:
        Path: The written file.
    """
    payload = {"tool": __app_name__, "version": __version__, **to_jsonable(result)}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def csv_row(rank: int, c: Candidate) -> dict[str, object]:
    """
    Flatten a candidate into one CSV row.

    Args:
        rank (int): Position in the ranking.
        c (Candidate): Candidate.
    Returns:
        dict[str, object]: Row keyed by `CSV_FIELDS`.
    """
    reg, p, v = c.registration, c.page, c.visual
    return {
        "rank": rank, "domain": c.domain, "ascii": c.ascii, "score": c.score, "risk": c.risk,
        "category": c.category, "lexical": c.lexical, "homograph": c.homograph,
        "techniques": " ".join(sorted(c.fuzzers)), "registered": c.registered,
        "created": reg.created.date().isoformat() if reg and reg.created else "",
        "registrar": reg.registrar if reg else "",
        "registrant": (reg.registrant_org or reg.registrant_name or "") if reg else "",
        "ips": " ".join(c.dns.ips), "mx": " ".join(c.dns.mx), "ns": " ".join(c.dns.ns),
        "web_status": p.status if p and p.reachable else "", "final_url": p.final_url if p else "",
        "title": p.title if p else "", "password_form": bool(p and p.has_password),
        "login_form": bool(p and p.has_login_form), "brand_mentions": p.brand_mentions if p else 0,
        "logo_similarity": v.logo_similarity if v else "", "favicon_match": bool(v and v.favicon_match),
        "text_similarity": c.text_similarity, "semantic_similarity": c.semantic_similarity or "",
        "vt_malicious": c.vt.malicious if c.vt else "", "abuse_score": c.max_abuse or "",
        "feeds": " ".join(sorted(c.feeds)), "ct_certs": c.ct.count if c.ct else "",
        "parked": bool(p and p.parked), "web_filtered": bool(p and p.filtered),
        "reasons": " | ".join(f"{i.points:+.0f} {i.label}" for i in c.breakdown),
    }


def write_csv(result: ScanResult, path: Path) -> Path:
    """
    Export every candidate as a CSV file (UTF-8 with BOM for spreadsheets).

    Args:
        result (ScanResult): Scan result.
        path (Path): Destination file.
    Returns:
        Path: The written file.
    """
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for i, c in enumerate(result.candidates, 1):
            writer.writerow(csv_row(i, c))
    return path


def export(result: ScanResult, out_dir: Path, formats: set[str]) -> list[str]:
    """
    Write every requested export format.

    Args:
        result (ScanResult): Scan result.
        out_dir (Path): Output directory (created if missing).
        formats (set[str]): Any of {"json", "csv"}.
    Returns:
        list[str]: Paths of the written files.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = result.started.strftime("%Y%m%d-%H%M%S") if result.started else "scan"
    base = out_dir / f"{result.target.ascii.replace('.', '_')}-{stamp}"
    written: list[str] = []
    if "json" in formats:
        written.append(str(write_json(result, base.with_suffix(".json"))))
    if "csv" in formats:
        written.append(str(write_csv(result, base.with_suffix(".csv"))))
    return written
