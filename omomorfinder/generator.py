"""
Lookalike (homomorphic) domain permutation engine.

Each *fuzzer* implements one technique attackers use to register domains
that look like the target. Every generated label is validated against
IDNA2008/UTS-46 rules so that only *registrable* names reach the DNS stage,
and mixed-script IDN labels (e.g. Latin + Cyrillic, refused by most
registries) are dropped unless explicitly requested.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

import idna

from .config import Settings
from .resources import POPULAR_TLDS, ResourceManager

KEYBOARDS: dict[str, tuple[str, ...]] = {
    "qwerty": ("1234567890-", "qwertyuiop", "asdfghjkl", "zxcvbnm"),
    "qwertz": ("1234567890-", "qwertzuiop", "asdfghjkl", "yxcvbnm"),
    "azerty": ("1234567890-", "azertyuiop", "qsdfghjklm", "wxcvbn"),
}

# ASCII lookalikes: single char -> replacements (may be multi-char).
ASCII_HOMOGLYPHS: dict[str, tuple[str, ...]] = {
    "a": ("4",), "b": ("6", "lb"), "d": ("cl",), "e": ("3",), "g": ("9", "q"),
    "h": ("lh",), "i": ("1", "l", "j"), "j": ("i",), "k": ("lk", "ik"),
    "l": ("1", "i"), "m": ("rn", "nn"), "n": ("r", "m"), "o": ("0",),
    "q": ("g",), "s": ("5",), "t": ("7",), "u": ("v",), "v": ("u",),
    "w": ("vv",), "z": ("2",), "0": ("o",), "1": ("l", "i"), "5": ("s",),
}
# Multi-char sequences that can be collapsed into a single lookalike.
ASCII_REVERSE: dict[str, str] = {"rn": "m", "vv": "w", "cl": "d", "nn": "m"}

VOWELS = "aeiouy"
LDH_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")

COMBO_WORDS: tuple[str, ...] = (
    # English
    "login", "signin", "secure", "security", "account", "accounts", "verify",
    "verification", "update", "support", "help", "service", "services", "online",
    "web", "app", "mail", "email", "webmail", "pay", "payment", "billing", "bank",
    "portal", "auth", "sso", "id", "my", "official", "info", "shop", "store",
    "group", "corp", "cloud", "admin", "access", "customer", "client", "team",
    "hr", "careers", "jobs", "invoice", "wallet", "connect", "mobile", "net",
    # Italian
    "accedi", "accesso", "sicurezza", "assistenza", "clienti", "verifica",
    "conto", "pagamenti", "pagamento", "area", "areaclienti", "riservata",
    "italia", "it", "servizi", "supporto", "fattura", "rimborso", "posta",
    "aggiorna", "sblocca", "online", "spa", "srl",
)

VALID_ASCII = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


@dataclass(slots=True)
class GeneratedDomain:
    """
    One generated lookalike domain.

    Attributes:
        ascii (str): Punycode / ASCII form ("xn--pypal-4ve.com").
        unicode (str): Display form ("pаypal.com").
        name (str): Unicode label without suffix.
        suffix (str): Public suffix.
        fuzzers (set[str]): Techniques that produced it.
    """

    ascii: str
    unicode: str
    name: str
    suffix: str
    fuzzers: set[str] = field(default_factory=set)


def char_script(ch: str) -> str:
    """
    Return the Unicode script family of a character.

    Args:
        ch (str): Single character.
    Returns:
        str: "COMMON" for digits/hyphen, otherwise the first word of the
        Unicode name (e.g. "LATIN", "CYRILLIC", "GREEK").
    """
    if ch.isdigit() or ch == "-":
        return "COMMON"
    try:
        return unicodedata.name(ch).split(" ", 1)[0]
    except ValueError:
        return "UNKNOWN"


def label_scripts(label: str) -> set[str]:
    """
    Set of scripts used by a label, ignoring COMMON characters.

    Args:
        label (str): Domain label.
    Returns:
        set[str]: e.g. {"LATIN"} or {"LATIN", "CYRILLIC"}.
    """
    return {s for s in map(char_script, label) if s != "COMMON"}


def to_ascii_label(label: str) -> str | None:
    """
    Validate a label and convert it to its registrable ASCII form.

    ASCII labels are checked against LDH rules; Unicode labels go through
    IDNA2008 with UTS-46 mapping and must round-trip unchanged (so the
    displayed form is exactly what a victim would see).

    Args:
        label (str): Candidate label.
    Returns:
        str | None: ASCII label (punycode for IDN), or None if invalid.
    """
    if label.isascii():
        if VALID_ASCII.match(label) and not (label[2:4] == "--"):
            return label
        return None
    try:
        encoded = idna.encode(label, uts46=True).decode("ascii")
        if idna.decode(encoded) != label or len(encoded) > 63:
            return None
        return encoded
    except (idna.IDNAError, UnicodeError, ValueError):
        return None


class DomainGenerator:
    """
    Generates lookalike domains for a target with many fuzzing techniques.

    Args (constructor):
        resources (ResourceManager): Source of TLDs and confusables.
        settings (Settings): Scan configuration (keyboard, TLD mode, ...).
    """

    FUZZERS: tuple[str, ...] = (
        "addition", "bitsquatting", "homoglyph", "idn-homoglyph", "diacritic",
        "whole-script", "hyphenation", "insertion", "omission", "repetition",
        "replacement", "transposition", "vowel-swap", "combosquatting",
        "various", "tld-swap",
    )

    def __init__(self, resources: ResourceManager, settings: Settings) -> None:
        """
        Prepare lookup tables (keyboard adjacency, Unicode glyph tables).

        Args:
            resources (ResourceManager): Loaded datasets.
            settings (Settings): Scan configuration.
        Returns:
            None
        """
        self.settings = settings
        self.resources = resources
        self.enabled = set(settings.fuzzers) if settings.fuzzers else set(self.FUZZERS)
        self.adjacent = self._build_adjacency(KEYBOARDS.get(settings.keyboard, KEYBOARDS["qwerty"]))
        self.latin_glyphs, self.script_glyphs = self._build_glyph_tables(resources.confusables())
        self.diacritics = self._build_diacritics()
        self.words = tuple(dict.fromkeys([*COMBO_WORDS, *settings.extra_words]))

    @staticmethod
    def _build_adjacency(rows: tuple[str, ...]) -> dict[str, str]:
        """
        Compute the physically adjacent keys of every key.

        Args:
            rows (tuple[str, ...]): Keyboard rows, top to bottom.
        Returns:
            dict[str, str]: key -> string of neighbouring keys.
        """
        pos = {ch: (r, c) for r, row in enumerate(rows) for c, ch in enumerate(row)}
        adj: dict[str, str] = {}
        for ch, (r, c) in pos.items():
            near = []
            for dr in (-1, 0, 1):
                for dc in (-1, 0, 1):
                    if (dr or dc) and 0 <= r + dr < len(rows) and 0 <= c + dc < len(rows[r + dr]):
                        near.append(rows[r + dr][c + dc])
            adj[ch] = "".join(near)
        return adj

    @staticmethod
    def _build_glyph_tables(conf: dict[str, set[str]]) -> tuple[dict[str, list[str]], dict[str, dict[str, str]]]:
        """
        Split confusables into Latin-script glyphs and per-script glyphs.

        Only lower-case letters that survive UTS-46 mapping unchanged are kept
        (others would be normalised away by browsers and registries).

        Args:
            conf (dict[str, set[str]]): ASCII char -> confusable chars.
        Returns:
            tuple: (latin: ascii -> list of Latin glyphs,
                    scripts: script -> {ascii -> best glyph}).
        """
        latin: dict[str, list[str]] = {}
        scripts: dict[str, dict[str, str]] = {}
        for proto, glyphs in conf.items():
            for g in sorted(glyphs):
                if not unicodedata.category(g).startswith("L"):
                    continue
                if to_ascii_label(g) is None:
                    continue
                script = char_script(g)
                if script == "LATIN":
                    latin.setdefault(proto, []).append(g)
                elif script in {"CYRILLIC", "GREEK", "ARMENIAN"}:
                    scripts.setdefault(script, {}).setdefault(proto, g)
        return latin, scripts

    @staticmethod
    def _build_diacritics() -> dict[str, list[str]]:
        """
        Collect accented Latin letters (Latin-1 + Latin Extended-A).

        Returns:
            dict[str, list[str]]: base ascii letter -> accented variants.
        """
        table: dict[str, list[str]] = {}
        for cp in range(0xC0, 0x180):
            ch = chr(cp)
            if not ch.islower():
                continue
            base = unicodedata.normalize("NFD", ch)[0]
            if base.isascii() and base.isalpha() and base != ch and to_ascii_label(ch):
                table.setdefault(base, []).append(ch)
        return table

    # ------------------------------------------------------------------ fuzzers
    def f_addition(self, n: str) -> Iterator[str]:
        """
        Append or prepend one character ("example" -> "examplea").

        Args:
            n (str): Target label.
        Returns:
            Iterator[str]: Candidate labels.
        """
        for ch in "abcdefghijklmnopqrstuvwxyz0123456789":
            yield n + ch
            yield ch + n

    def f_bitsquatting(self, n: str) -> Iterator[str]:
        """
        Flip one bit of one character (hardware memory errors).

        Args:
            n (str): Target label.
        Returns:
            Iterator[str]: Candidate labels.
        """
        for i, ch in enumerate(n):
            for bit in range(8):
                flipped = chr(ord(ch) ^ (1 << bit))
                if flipped in LDH_CHARS:
                    yield n[:i] + flipped + n[i + 1:]

    def f_homoglyph(self, n: str) -> Iterator[str]:
        """
        ASCII lookalike substitutions ("o"->"0", "m"->"rn", "rn"->"m").

        Applies single substitutions plus every pair of substitutions for
        labels up to 12 characters.

        Args:
            n (str): Target label.
        Returns:
            Iterator[str]: Candidate labels.
        """
        singles: list[str] = []
        for i, ch in enumerate(n):
            for rep in ASCII_HOMOGLYPHS.get(ch, ()):
                singles.append(n[:i] + rep.lower() + n[i + 1:])
        for seq, rep in ASCII_REVERSE.items():
            start = n.find(seq)
            while start != -1:
                singles.append(n[:start] + rep + n[start + len(seq):])
                start = n.find(seq, start + 1)
        yield from singles
        if len(n) <= 12:
            for i, ch in enumerate(n):
                for rep in ASCII_HOMOGLYPHS.get(ch, ()):
                    for j in range(i + 1, len(n)):
                        for rep2 in ASCII_HOMOGLYPHS.get(n[j], ()):
                            yield n[:i] + rep + n[i + 1:j] + rep2 + n[j + 1:]

    def f_idn_homoglyph(self, n: str) -> Iterator[str]:
        """
        Replace one character with a Latin-script Unicode confusable.

        Args:
            n (str): Target label.
        Returns:
            Iterator[str]: IDN candidate labels (single-script Latin).
        """
        for i, ch in enumerate(n):
            for g in self.latin_glyphs.get(ch, ()):
                yield n[:i] + g + n[i + 1:]
        if self.settings.include_mixed_script:
            for glyphs in self.script_glyphs.values():
                for i, ch in enumerate(n):
                    if ch in glyphs:
                        yield n[:i] + glyphs[ch] + n[i + 1:]

    def f_diacritic(self, n: str) -> Iterator[str]:
        """
        Replace one letter with an accented variant ("e" -> "è", "é", ...).

        Args:
            n (str): Target label.
        Returns:
            Iterator[str]: IDN candidate labels.
        """
        for i, ch in enumerate(n):
            for g in self.diacritics.get(ch, ()):
                yield n[:i] + g + n[i + 1:]

    def f_whole_script(self, n: str) -> Iterator[str]:
        """
        Rewrite the whole label in another script (e.g. full Cyrillic "аррӏе").

        Only produced when every letter has a confusable in that script, so
        the result is a single-script label accepted by registries.

        Args:
            n (str): Target label.
        Returns:
            Iterator[str]: IDN candidate labels.
        """
        for glyphs in self.script_glyphs.values():
            if all(c.isdigit() or c == "-" or c in glyphs for c in n):
                yield "".join(glyphs.get(c, c) for c in n)

    def f_hyphenation(self, n: str) -> Iterator[str]:
        """
        Insert a hyphen between two characters ("exam-ple").

        Args:
            n (str): Target label.
        Returns:
            Iterator[str]: Candidate labels.
        """
        for i in range(1, len(n)):
            if n[i - 1] != "-" and n[i] != "-":
                yield n[:i] + "-" + n[i:]

    def f_insertion(self, n: str) -> Iterator[str]:
        """
        Insert a keyboard-adjacent character before/after each letter.

        Args:
            n (str): Target label.
        Returns:
            Iterator[str]: Candidate labels.
        """
        for i, ch in enumerate(n):
            for k in self.adjacent.get(ch, ""):
                yield n[:i] + k + n[i:]
                yield n[:i + 1] + k + n[i + 1:]

    def f_omission(self, n: str) -> Iterator[str]:
        """
        Remove one character ("exmple").

        Args:
            n (str): Target label.
        Returns:
            Iterator[str]: Candidate labels.
        """
        for i in range(len(n)):
            yield n[:i] + n[i + 1:]

    def f_repetition(self, n: str) -> Iterator[str]:
        """
        Double one character ("exxample").

        Args:
            n (str): Target label.
        Returns:
            Iterator[str]: Candidate labels.
        """
        for i, ch in enumerate(n):
            if ch.isalnum():
                yield n[:i] + ch + n[i:]

    def f_replacement(self, n: str) -> Iterator[str]:
        """
        Replace a character with a keyboard-adjacent one ("exampke").

        Args:
            n (str): Target label.
        Returns:
            Iterator[str]: Candidate labels.
        """
        for i, ch in enumerate(n):
            for k in self.adjacent.get(ch, ""):
                yield n[:i] + k + n[i + 1:]

    def f_transposition(self, n: str) -> Iterator[str]:
        """
        Swap two adjacent characters ("exmaple").

        Args:
            n (str): Target label.
        Returns:
            Iterator[str]: Candidate labels.
        """
        for i in range(len(n) - 1):
            if n[i] != n[i + 1]:
                yield n[:i] + n[i + 1] + n[i] + n[i + 2:]

    def f_vowel_swap(self, n: str) -> Iterator[str]:
        """
        Replace a vowel with another vowel ("exomple").

        Args:
            n (str): Target label.
        Returns:
            Iterator[str]: Candidate labels.
        """
        for i, ch in enumerate(n):
            if ch in VOWELS:
                for v in VOWELS:
                    if v != ch:
                        yield n[:i] + v + n[i + 1:]

    def f_combosquatting(self, n: str) -> Iterator[str]:
        """
        Combine the brand with dictionary words ("example-login").

        Args:
            n (str): Target label.
        Returns:
            Iterator[str]: Candidate labels.
        """
        for w in self.words:
            yield f"{n}-{w}"
            yield f"{w}-{n}"
            yield f"{n}{w}"
            yield f"{w}{n}"

    def f_various(self, n: str) -> Iterator[str]:
        """
        Miscellaneous tricks: "www" prefix, "com" glued to the name, etc.

        Args:
            n (str): Target label.
        Returns:
            Iterator[str]: Candidate labels.
        """
        yield from (f"www{n}", f"www-{n}", f"{n}com", f"{n}-com", f"{n}it",
                    f"{n}-it", f"{n}{n}", f"{n}s", f"the{n}", f"get{n}", f"go{n}")

    # --------------------------------------------------------------- generation
    def tld_pool(self, target_suffix: str) -> list[str]:
        """
        TLDs used for the "tld-swap" fuzzer.

        Args:
            target_suffix (str): Suffix of the target (excluded).
        Returns:
            list[str]: Suffixes to try.
        """
        mode = self.settings.tld_mode
        if mode == "all":
            pool = set(self.resources.tlds()) | {t for t in POPULAR_TLDS if "." in t}
        elif mode == "popular":
            pool = set(POPULAR_TLDS)
        else:
            pool = {t.strip().lower().lstrip(".") for t in mode.split(",") if t.strip()}
        pool.discard(target_suffix)
        return sorted(pool)

    def _labels(self, name: str) -> Iterator[tuple[str, str]]:
        """
        Run every enabled label fuzzer.

        Args:
            name (str): Target label.
        Returns:
            Iterator[tuple[str, str]]: (fuzzer name, candidate label).
        """
        for fz in self.FUZZERS:
            if fz == "tld-swap" or fz not in self.enabled:
                continue
            method = getattr(self, "f_" + fz.replace("-", "_"))
            for label in method(name):
                yield fz, label

    def generate(self, name: str, suffix: str) -> dict[str, GeneratedDomain]:
        """
        Produce every valid lookalike domain for a target.

        Label fuzzers are applied on the target suffix and, when the target
        is not a ".com", on ".com" too (attackers' favourite TLD). TLD-swap
        keeps the original label on every TLD of the pool.

        Args:
            name (str): Target label, e.g. "example".
            suffix (str): Target public suffix, e.g. "it".
        Returns:
            dict[str, GeneratedDomain]: ASCII domain -> generated record.
        """
        out: dict[str, GeneratedDomain] = {}
        target_ascii = f"{name}.{suffix}"
        suffixes = [suffix] if suffix == "com" else [suffix, "com"]
        labels: dict[str, set[str]] = {}
        for fz, label in self._labels(name):
            label = label.lower()
            if label != name:
                labels.setdefault(label, set()).add(fz)
        for label, fzs in labels.items():
            ascii_label = to_ascii_label(label)
            if ascii_label is None:
                continue
            scripts = label_scripts(label)
            if len(scripts) > 1 and not self.settings.include_mixed_script:
                continue
            for sfx in suffixes:
                self._add(out, ascii_label, label, sfx, fzs, target_ascii)
        if "tld-swap" in self.enabled:
            if suffix != "com":
                self._add(out, name, name, "com", {"tld-swap"}, target_ascii)
            for sfx in self.tld_pool(suffix):
                self._add(out, name, name, sfx, {"tld-swap"}, target_ascii)
        return out

    @staticmethod
    def _add(
        out: dict[str, GeneratedDomain],
        ascii_label: str,
        label: str,
        suffix: str,
        fuzzers: Iterable[str],
        target_ascii: str,
    ) -> None:
        """
        Insert (or merge) a domain into the output map.

        Args:
            out (dict[str, GeneratedDomain]): Accumulator.
            ascii_label (str): ASCII label.
            label (str): Display label.
            suffix (str): Public suffix.
            fuzzers (Iterable[str]): Producing fuzzers.
            target_ascii (str): Target domain (never added).
        Returns:
            None
        """
        ascii_dom = f"{ascii_label}.{suffix}"
        if ascii_dom == target_ascii:
            return
        entry = out.get(ascii_dom)
        if entry is None:
            out[ascii_dom] = GeneratedDomain(ascii_dom, f"{label}.{suffix}", label, suffix, set(fuzzers))
        else:
            entry.fuzzers.update(fuzzers)
