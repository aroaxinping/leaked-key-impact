"""Data-quality tests on the produced analytical dataset.

These validate the committed ``data/processed`` outputs: shape, schema,
value domains, and internal consistency. They are what catches a broken or
partially-regenerated dataset before it reaches the analysis.
"""

import pandas as pd
import pytest

ALLOWED_PHASES = {
    "validation",
    "reconnaissance",
    "abuse-prep",
    "persistence",
    "resource-abuse",
    "defense",
}

EXPECTED_COLUMNS = {
    "seq", "datetime_utc", "date_utc", "time_utc", "source_ip", "event_name",
    "user_agent", "alert_type", "token_id", "placement", "channel",
    "city", "region", "country", "asn", "org",
    "infra_type", "asname", "is_proxy", "is_hosting", "is_mobile",
    "ua_os", "ua_python", "ua_boto3", "ua_retry_mode",
    "tool_signature", "intent_phase", "intent_description",
}


@pytest.fixture(scope="module")
def enriched(processed_dir):
    path = processed_dir / "alerts_enriched.csv"
    if not path.exists():
        pytest.skip("alerts_enriched.csv not built yet")
    return pd.read_csv(path)


@pytest.fixture(scope="module")
def ip_intel(processed_dir):
    path = processed_dir / "ip_intel.csv"
    if not path.exists():
        pytest.skip("ip_intel.csv not built yet")
    return pd.read_csv(path)


def test_event_count_is_stable_and_nontrivial(enriched):
    # Grows as the fleet fires; started at 16. Guard against an empty or
    # truncated regeneration, not against a specific frozen count.
    assert len(enriched) >= 16


def test_expected_columns_present(enriched):
    assert set(enriched.columns) == EXPECTED_COLUMNS


def test_seq_is_unique_and_complete(enriched):
    assert sorted(enriched["seq"].tolist()) == list(range(1, len(enriched) + 1))


def test_intent_phase_values_are_all_valid(enriched):
    phases = set(enriched["intent_phase"].unique())
    assert phases <= ALLOWED_PHASES
    # Every event in this dataset is mapped: none should fall through.
    assert "unknown" not in phases


def test_required_fields_are_never_null(enriched):
    for col in ("datetime_utc", "event_name", "alert_type", "intent_phase",
                "token_id", "placement", "channel"):
        assert enriched[col].notna().all(), f"null found in {col}"


def test_fleet_provenance_columns_are_populated(enriched):
    # Every event must be attributable to a token, a placement, and a channel.
    assert enriched["token_id"].notna().all()
    assert (enriched["placement"].str.len() > 0).all()
    assert (enriched["channel"].str.len() > 0).all()


def test_attacker_rows_have_ip_and_country(enriched):
    attackers = enriched[enriched["alert_type"] == "ip_triggered"]
    assert len(attackers) >= 13
    assert attackers["source_ip"].notna().all()
    assert attackers["country"].notna().all()


def test_ip_intel_covers_every_unique_attacker_ip(enriched, ip_intel):
    # One intel row per distinct attacker IP, no duplicates, no gaps.
    attacker_ips = set(enriched.loc[enriched["alert_type"] == "ip_triggered",
                                    "source_ip"])
    assert ip_intel["source_ip"].nunique() == len(ip_intel)
    assert set(ip_intel["source_ip"]) == attacker_ips
