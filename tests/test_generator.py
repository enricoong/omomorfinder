"""
Tests for the lookalike permutation engine.
"""

from omomorfinder.config import Settings
from omomorfinder.generator import DomainGenerator, label_scripts, to_ascii_label


def make_generator(resources, **overrides) -> DomainGenerator:
    """
    Build a generator over offline resources.

    Args:
        resources: Stub resource manager fixture.
        **overrides: Settings attributes to override.
    Returns:
        DomainGenerator: Ready generator.
    """
    settings = Settings()
    for key, value in overrides.items():
        setattr(settings, key, value)
    return DomainGenerator(resources, settings)


def test_to_ascii_label_validation() -> None:
    """
    LDH rules for ASCII, IDNA2008 round-trip for Unicode labels.

    Returns:
        None
    """
    assert to_ascii_label("example") == "example"
    assert to_ascii_label("-bad") is None
    assert to_ascii_label("ab--cd") is None
    assert to_ascii_label("exämple").startswith("xn--")


def test_generate_excludes_target_and_is_valid(resources) -> None:
    """
    Output never contains the target and every ASCII form is LDH-valid.

    Args:
        resources: Stub resource manager fixture.
    Returns:
        None
    """
    out = make_generator(resources).generate("example", "it")
    assert "example.it" not in out
    assert len(out) > 500
    for ascii_dom, entry in out.items():
        label = ascii_dom[: -len(entry.suffix) - 1]
        assert ascii_dom.isascii()
        assert entry.fuzzers
        assert to_ascii_label(label) == label or label.startswith("xn--")


def test_generate_contains_classic_techniques(resources) -> None:
    """
    Typical typos, homoglyphs, combos and TLD swaps are produced.

    Args:
        resources: Stub resource manager fixture.
    Returns:
        None
    """
    out = make_generator(resources).generate("example", "it")
    assert "exmaple.it" in out          # transposition
    assert "examp1e.it" in out          # ASCII homoglyph
    assert "example-login.it" in out    # combosquatting
    assert "example.com" in out         # TLD swap
    assert "transposition" in out["exmaple.it"].fuzzers


def test_mixed_script_excluded_by_default(resources) -> None:
    """
    Latin+Cyrillic labels (rejected by registries) are skipped by default.

    Args:
        resources: Stub resource manager fixture.
    Returns:
        None
    """
    out = make_generator(resources).generate("example", "com")
    assert all(len(label_scripts(e.name)) <= 1 for e in out.values())


def test_fuzzer_subset(resources) -> None:
    """
    Restricting fuzzers restricts the output techniques.

    Args:
        resources: Stub resource manager fixture.
    Returns:
        None
    """
    out = make_generator(resources, fuzzers={"omission"}).generate("example", "com")
    assert out
    assert all(e.fuzzers == {"omission"} for e in out.values())
