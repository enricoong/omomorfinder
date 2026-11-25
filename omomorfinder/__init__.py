"""
OmomorFinder - homomorphic / lookalike domain threat analyzer.

Given a company domain, OmomorFinder generates every realistic lookalike
domain (homoglyphs, IDN, typos, bitsquatting, combosquatting, TLD swaps),
discovers already-registered ones through DNS, Certificate Transparency and
threat feeds, enriches them with RDAP/WHOIS, VirusTotal, AbuseIPDB, content,
logo and NLP analysis, and finally ranks them with an explainable relevance
index (0-100) and a category (MALICIOUS, SUSPICIOUS, PARKED, COMPETITOR,
DEFENSIVE, AVAILABLE).
"""

__app_name__ = "OmomorFinder"
# Single source of truth for the version (read by pyproject.toml, --version,
# the User-Agent and the JSON export). Bump it together with CHANGELOG.md.
__version__ = "1.1.0"
