"""
Tests for lexical / visual similarity primitives.
"""

from omomorfinder.similarity import (
    contains_brand,
    is_near,
    jaro_winkler,
    lexical_score,
    osa_distance,
    skeleton,
)


def test_osa_distance_counts_transposition_as_one(resources) -> None:
    """
    Adjacent transpositions cost 1 edit, not 2.

    Args:
        resources: Fixture loading the confusables table.
    Returns:
        None
    """
    assert osa_distance("example", "exmaple") == 1
    assert osa_distance("abc", "abc") == 0
    assert osa_distance("", "abc") == 3


def test_jaro_winkler_bounds() -> None:
    """
    Jaro-Winkler is 1 for identical strings and within [0, 1].

    Returns:
        None
    """
    assert jaro_winkler("poste", "poste") == 1.0
    assert 0.0 <= jaro_winkler("poste", "zzzzz") <= 1.0
    assert jaro_winkler("poste", "postee") > jaro_winkler("poste", "etsop")


def test_skeleton_maps_lookalikes(resources) -> None:
    """
    Leetspeak, Cyrillic homoglyphs and "rn" collapse to the same skeleton.

    Args:
        resources: Fixture loading the confusables table.
    Returns:
        None
    """
    assert skeleton("p0ste") == skeleton("poste")
    assert skeleton("pоste") == skeleton("poste")  # Cyrillic "о"
    assert skeleton("rnicrosoft") == skeleton("microsoft")


def test_contains_brand_is_word_aware() -> None:
    """
    The brand must be a prefix, suffix or separated token, not any substring.

    Returns:
        None
    """
    assert contains_brand("poste-login", "poste")
    assert contains_brand("laposte", "poste")
    assert not contains_brand("restposten", "poste")
    assert not contains_brand("aaavintageposters", "poste")


def test_lexical_score_homograph_and_penalty(resources) -> None:
    """
    Homographs score highest; extra visible substitutions lower the score.

    Args:
        resources: Fixture loading the confusables table.
    Returns:
        None
    """
    one, homo1 = lexical_score("p0ste", "it", "poste", "it")
    two, homo2 = lexical_score("p0s7e", "it", "poste", "it")
    assert homo1 and homo2
    assert one == 1.0 and two < one
    other_tld, _ = lexical_score("poste", "xyz", "poste", "it")
    assert other_tld < 1.0


def test_is_near_threshold(resources) -> None:
    """
    Short brands tolerate one edit, longer brands two.

    Args:
        resources: Fixture loading the confusables table.
    Returns:
        None
    """
    assert is_near("pste", "poste")
    assert not is_near("pxxte", "poste")
    assert is_near("exmpale", "example")
