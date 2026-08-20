"""Tests for the network enrichment helpers, with the HTTP layer mocked.

These never touch the network: they monkeypatch ``_http_get_json`` so the
parsing logic (ASN/org extraction, non-attacker short-circuit) is verified
deterministically and offline.
"""

from canary_token_analytics import enrich


def test_lookup_ip_parses_asn_and_org(monkeypatch):
    fake = {
        "city": "Lansing",
        "region": "Michigan",
        "country": "US",
        "org": "AS7018 AT&T Enterprises, LLC",
    }
    monkeypatch.setattr(enrich, "_http_get_json", lambda url, timeout=15: fake)

    result = enrich.lookup_ip("99.89.81.59")
    assert result["city"] == "Lansing"
    assert result["country"] == "US"
    assert result["asn"] == "AS7018"
    assert result["org"] == "AT&T Enterprises, LLC"


def test_lookup_ip_skips_non_attacker_sources(monkeypatch):
    # Must not even attempt a lookup for AWS-internal / blank sources.
    def _boom(*args, **kwargs):
        raise AssertionError("network lookup should not run for non-attacker IPs")

    monkeypatch.setattr(enrich, "_http_get_json", _boom)

    for ip in ("AWS Internal", ""):
        result = enrich.lookup_ip(ip)
        assert result == {
            "city": None, "region": None, "country": None,
            "asn": None, "org": None,
        }


def test_lookup_ip_returns_none_fields_on_failure(monkeypatch):
    monkeypatch.setattr(enrich, "_http_get_json", lambda url, timeout=15: None)
    monkeypatch.setattr(enrich, "_whois_org", lambda ip, timeout=20: None)

    result = enrich.lookup_ip("203.0.113.5")
    assert result["org"] is None
    assert result["country"] is None


def test_greynoise_skips_non_attacker_sources(monkeypatch):
    def _boom(*args, **kwargs):
        raise AssertionError("GreyNoise should not run for non-attacker IPs")

    monkeypatch.setattr(enrich, "_http_get_json", _boom)
    result = enrich.greynoise_community("AWS Internal")
    assert result == {
        "noise": None, "riot": None, "classification": None, "name": None,
    }
