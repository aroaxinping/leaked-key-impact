"""Tests for the robust raw-CSV reader.

The raw ``user_agent`` field contains unquoted commas, so the reader must
recover every original value exactly rather than mis-splitting columns.
"""

from canary_token_analytics.pipeline import _read_raw, RAW_COLUMNS


def test_reads_every_row_with_expected_columns(raw_csv):
    df = _read_raw(raw_csv)
    # The dataset grows as the fleet keeps firing; assert on invariants, not a
    # frozen row count. Every non-header line must parse into the full schema.
    raw_lines = raw_csv.read_text().strip().splitlines()
    assert len(df) == len(raw_lines) - 1
    assert len(df) >= 16
    assert list(df.columns) == RAW_COLUMNS


def test_unquoted_commas_in_user_agent_are_preserved(raw_csv):
    df = _read_raw(raw_csv)
    # seq 4 has 'm/D,Z,b,e' inside its user agent; the reader must keep it whole.
    row = df[df["seq"] == "4"].iloc[0]
    assert "m/D,Z,b,e" in row["user_agent"]
    assert row["user_agent"].startswith("Boto3/1.43.65")
    # The trailing alert_type column must not be swallowed by the split.
    assert row["alert_type"] == "ip_triggered"


def test_defense_rows_have_no_ip_or_user_agent(raw_csv):
    df = _read_raw(raw_csv)
    safetynet = df[df["alert_type"] == "safetynet"]
    assert len(safetynet) == 2
    assert (safetynet["source_ip"] == "").all()
    assert (safetynet["user_agent"] == "").all()
