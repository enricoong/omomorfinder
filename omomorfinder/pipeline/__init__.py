"""
The analysis pipeline, one module per stage:

    context.py      shared ScanContext, Reporter protocol, ScanResult
    target.py       input validation (domain only), dataset sync, target profile
    discovery.py    permutations, threat-feed and CT discovery (brand-in-subdomain too)
    dns_sweep.py    NS-first DNS filter
    enrichment.py   RDAP/WHOIS, web content and logo comparison
    subdomains.py   subdomain discovery and classification
    reputation.py   AbuseIPDB and VirusTotal
    analysis.py     NLP similarity and screenshot diff
    scanner.py      orchestrator chaining the stages
"""

from .context import InputError, Reporter, ScanResult
from .scanner import Scanner
from .target import validate_domain

__all__ = ["InputError", "Reporter", "ScanResult", "Scanner", "validate_domain"]
