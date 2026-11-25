"""
Tests for RDAP / WHOIS parsing (synthetic records, no network).
"""

from omomorfinder.registration import parse_date, parse_rdap, parse_whois

IT_WHOIS = """
*********************************************************************
* Please note that the following result could be a subgroup of      *
*********************************************************************

Domain:             example.it
Status:             ok
Created:            2001-02-03 00:00:00
Last Update:        2025-03-04 00:52:05
Expire Date:        2026-02-03

Registrant
  Organization:     Example S.p.A.
  Address:          Via Roma 1
                    Roma

Registrar
  Organization:     Register.it s.p.a.
  Name:             REGISTER-REG

Nameservers
  dns1.example.it
  dns2.example.it
"""

GENERIC_WHOIS = """
Domain Name: EXAMPLE.COM
Registrar: MarkMonitor Inc.
Creation Date: 1997-09-15T04:00:00Z
Registry Expiry Date: 2028-09-14T04:00:00Z
Registrant Organization: REDACTED FOR PRIVACY
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
Domain Status: clientTransferProhibited
"""


def test_parse_date_formats() -> None:
    """
    Common WHOIS/RDAP date formats are parsed as UTC.

    Returns:
        None
    """
    assert parse_date("2001-02-03 00:00:00").year == 2001
    assert parse_date("1997-09-15T04:00:00Z").tzinfo is not None
    assert parse_date("15-Sep-1997").month == 9
    assert parse_date("not a date") is None


def test_parse_whois_it_sections() -> None:
    """
    Sectioned .it format: registrant, registrar and name servers.

    Returns:
        None
    """
    info = parse_whois(IT_WHOIS, "example.it")
    assert info.registered is True
    assert info.registrant_org == "Example S.p.A."
    assert info.registrar == "Register.it s.p.a."
    assert info.nameservers == ["dns1.example.it", "dns2.example.it"]
    assert info.created.year == 2001


def test_parse_whois_generic_and_redaction() -> None:
    """
    Key/value format with a redacted registrant.

    Returns:
        None
    """
    info = parse_whois(GENERIC_WHOIS, "example.com")
    assert info.registered is True
    assert info.registrar == "MarkMonitor Inc."
    assert info.registrant_org is None and info.privacy
    assert "ns1.example.com" in info.nameservers


def test_parse_whois_not_found() -> None:
    """
    "Status: AVAILABLE" and "No match" mean unregistered.

    Returns:
        None
    """
    assert parse_whois("Domain: free.it\nStatus: AVAILABLE\n", "free.it").registered is False
    assert parse_whois('No match for "FREE-XYZ.COM".\n', "free-xyz.com").registered is False


def test_parse_rdap_entities() -> None:
    """
    RDAP events, nameservers and nested registrant/registrar entities.

    Returns:
        None
    """
    data = {
        "events": [{"eventAction": "registration", "eventDate": "2020-01-02T03:04:05Z"}],
        "status": ["active"],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.NET"}],
        "entities": [
            {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]},
            {"roles": ["registrant"], "vcardArray": ["vcard", [
                ["fn", {}, "text", "REDACTED FOR PRIVACY"],
                ["org", {}, "text", "Example Corp"],
                ["adr", {"cc": "IT"}, "text", ["", "", "", "", "", "", ""]],
            ]]},
        ],
    }
    info = parse_rdap(data, "https://rdap.example/domain/example.net")
    assert info.registered and info.created.year == 2020
    assert info.registrar == "Example Registrar"
    assert info.registrant_org == "Example Corp" and info.registrant_country == "IT"
    assert info.privacy is True
    assert info.nameservers == ["ns1.example.net"]
