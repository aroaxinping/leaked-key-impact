"""Unit tests for infrastructure classification (pure, deterministic)."""

import pytest

from canary_token_analytics.enrich import classify_infra_type


@pytest.mark.parametrize(
    "org, expected",
    [
        ("T-Mobile USA, Inc.", "residential/mobile"),
        ("AT&T Enterprises, LLC", "residential/mobile"),
        ("PT. Telekomunikasi Selular", "residential/mobile"),
        ("Google LLC", "cloud"),
        ("Regxa Company for Information Technology Ltd", "datacenter VPS"),
        ("Telemedia Dinamika Sarana, PT", "residential/ISP"),
    ],
)
def test_known_orgs_classify_as_expected(org, expected):
    assert classify_infra_type(org) == expected


def test_none_or_empty_org_returns_none():
    assert classify_infra_type(None) is None
    assert classify_infra_type("") is None


def test_unrecognised_org_returns_none():
    assert classify_infra_type("Totally Unknown Entity XYZ") is None
