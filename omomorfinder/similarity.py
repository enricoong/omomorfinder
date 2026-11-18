"""
Lexical and visual string similarity for domain names.

The key idea is the *visual skeleton*: every character is mapped to the ASCII
prototype it is visually confused with (Unicode confusables, diacritics,
leetspeak, multi-character tricks like "rn" -> "m"). Two names with the same
skeleton look identical to a human, which is exactly what a homograph attack
exploits. Edit distances are then computed on skeletons, so "paypa1" is
correctly considered closer to "paypal" than "paypak".
"""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache

# Multi-character ASCII sequences that render like a single letter.
MULTI_GLYPHS: tuple[tuple[str, str], ...] = (
    ("rn", "m"), ("vv", "w"), ("cl", "d"),
)
# Digits / symbols commonly used as letter lookalikes.
LEET: dict[str, str] = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "|": "l"}

_reverse_confusables: dict[str, str] = {}


def load_confusables(table: dict[str, set[str]]) -> None:
    """
    Register the confusables table used to build skeletons.

    Must be called once after resources are loaded; before that, only
    Unicode decomposition and leetspeak are used.

    Args:
        table (dict[str, set[str]]): ASCII char -> confusable Unicode chars
            (output of `ResourceManager.confusables`).
    Returns:
        None
    """
    _reverse_confusables.clear()
    for proto, glyphs in table.items():
        for g in glyphs:
            _reverse_confusables.setdefault(g, proto)
    skeleton.cache_clear()


@lru_cache(maxsize=65536)
def skeleton(name: str) -> str:
    """
    Compute the visual skeleton of a domain label.

    Args:
        name (str): Domain label (Unicode allowed), e.g. "pаypa1".
    Returns:
        str: ASCII skeleton, e.g. "paypal".
    """
    out: list[str] = []
    for ch in name.lower():
        if ch.isascii():
            out.append(LEET.get(ch, ch))
            continue
        proto = _reverse_confusables.get(ch)
        if proto is None:
            base = unicodedata.normalize("NFKD", ch)
            base = "".join(c for c in base if not unicodedata.combining(c))
            proto = base if base.isascii() and base else ch
        out.append(LEET.get(proto, proto))
    sk = "".join(out)
    for seq, repl in MULTI_GLYPHS:
        sk = sk.replace(seq, repl)
    return sk


def osa_distance(a: str, b: str) -> int:
    """
    Optimal String Alignment (restricted Damerau-Levenshtein) distance.

    Counts insertions, deletions, substitutions and adjacent transpositions.

    Args:
        a (str): First string.
        b (str): Second string.
    Returns:
        int: Edit distance (0 means identical).
    """
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if not la:
        return lb
    if not lb:
        return la
    prev2: list[int] = []
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        ai = a[i - 1]
        for j in range(1, lb + 1):
            cost = 0 if ai == b[j - 1] else 1
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ai == b[j - 2] and a[i - 2] == b[j - 1]:
                v = min(v, prev2[j - 2] + 1)
            cur[j] = v
        prev2, prev = prev, cur
    return prev[lb]


def jaro_winkler(a: str, b: str, prefix_scale: float = 0.1) -> float:
    """
    Jaro-Winkler similarity (rewards shared prefixes, typical of typos).

    Args:
        a (str): First string.
        b (str): Second string.
        prefix_scale (float): Winkler prefix weight (standard 0.1).
    Returns:
        float: Similarity in [0, 1].
    """
    if a == b:
        return 1.0
    la, lb = len(a), len(b)
    if not la or not lb:
        return 0.0
    window = max(max(la, lb) // 2 - 1, 0)
    a_flags = [False] * la
    b_flags = [False] * lb
    matches = 0
    for i, ch in enumerate(a):
        lo, hi = max(0, i - window), min(i + window + 1, lb)
        for j in range(lo, hi):
            if not b_flags[j] and b[j] == ch:
                a_flags[i] = b_flags[j] = True
                matches += 1
                break
    if not matches:
        return 0.0
    transpositions = 0
    k = 0
    for i in range(la):
        if a_flags[i]:
            while not b_flags[k]:
                k += 1
            if a[i] != b[k]:
                transpositions += 1
            k += 1
    m = float(matches)
    jaro = (m / la + m / lb + (m - transpositions / 2) / m) / 3
    prefix = 0
    for x, y in zip(a[:4], b[:4]):
        if x != y:
            break
        prefix += 1
    return jaro + prefix * prefix_scale * (1 - jaro)


def contains_brand(label: str, brand: str) -> bool:
    """
    Whether a label embeds the brand as a word, not as a random substring.

    "poste-login", "laposte", "postetaliane" contain "poste"; "restposten"
    or "aaavintageposters" do not (the brand sits inside another word).

    Args:
        label (str): Candidate label.
        brand (str): Target label (>= 4 characters to be meaningful).
    Returns:
        bool: True when the brand is a prefix, suffix or hyphen/digit
        separated token of the label.
    """
    if len(brand) < 4 or brand not in label:
        return False
    if label.startswith(brand) or label.endswith(brand):
        return True
    return any(part.startswith(brand) or part.endswith(brand) for part in re.split(r"[-0-9]+", label) if part)


def tld_factor(cand_suffix: str, target_suffix: str) -> float:
    """
    Weight a candidate by how credible its TLD is next to the target's.

    Args:
        cand_suffix (str): Candidate public suffix.
        target_suffix (str): Target public suffix.
    Returns:
        float: 1.0 same suffix, 0.97 ".com", 0.92 country/generic
        classics, 0.86 anything else.
    """
    if cand_suffix == target_suffix:
        return 1.0
    if cand_suffix == "com":
        return 0.97
    if cand_suffix in {"net", "org", "it", "eu", "co", "io", "info", "app", "online", "site"}:
        return 0.92
    return 0.86


def lexical_score(cand_name: str, cand_suffix: str, target_name: str, target_suffix: str) -> tuple[float, bool]:
    """
    Overall lexical/visual similarity between a candidate and the target.

    Combines skeleton equality (homograph), OSA distance, Jaro-Winkler and
    brand containment (combosquatting), then applies the TLD factor.

    Args:
        cand_name (str): Candidate label (Unicode allowed).
        cand_suffix (str): Candidate public suffix.
        target_name (str): Target label.
        target_suffix (str): Target public suffix.
    Returns:
        tuple[float, bool]: (score in [0, 1], True when the candidate is
        visually indistinguishable from the target label).
    """
    sk_c, sk_t = skeleton(cand_name), skeleton(target_name)
    identical = sk_c == sk_t
    if identical:
        # each extra visible substitution ("p0s7e" vs "p0ste") makes the
        # fake a little easier to spot
        base = 1.0 - 0.04 * max(0, osa_distance(cand_name, target_name) - 1)
    else:
        longest = max(len(sk_c), len(sk_t)) or 1
        edit = 1 - osa_distance(sk_c, sk_t) / longest
        base = 0.6 * edit + 0.4 * jaro_winkler(sk_c, sk_t)
        if contains_brand(cand_name, target_name) or contains_brand(sk_c, sk_t):
            base = max(base, 0.70 + 0.2 * len(sk_t) / max(len(sk_c), 1))
    return round(max(0.0, min(1.0, base * tld_factor(cand_suffix, target_suffix))), 4), identical


def is_near(name: str, target_name: str, max_dist: int | None = None) -> bool:
    """
    Fast filter used to discover lookalikes in large external lists.

    Args:
        name (str): Label to test.
        target_name (str): Target label.
        max_dist (int | None): Maximum skeleton edit distance; by default 1
            for brands up to 5 characters, 2 for longer ones.
    Returns:
        bool: True if the label embeds the brand as a word or is within
        `max_dist` edits of it (on skeletons).
    """
    if contains_brand(name, target_name):
        return True
    if max_dist is None:
        max_dist = 1 if len(target_name) <= 5 else 2
    if abs(len(name) - len(target_name)) > max_dist + 1:
        return False
    sk_t = skeleton(target_name)
    sk = skeleton(name)
    if abs(len(sk) - len(sk_t)) > max_dist:
        return False
    return osa_distance(sk, sk_t) <= max_dist
