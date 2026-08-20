"""Tests for the canarytoken alert-email parser and dedup merge."""

from canary_token_analytics.ingest import (
    parse_alert_email,
    merge_new_events,
    _dedup_key,
)

TOKEN_MAP = {"5792dirvqlq9rowicezsid1u4": ("5", "terraform.tfvars")}

SAMPLE = """Your Canarytoken was triggered!
-------------------------------

An AWS key Canarytoken has been triggered by the Source IP 192.241.104.43

Reminder:
  AWS key en terraform.tfvars de serverless-notifier (fleet)

Source IP:
  192.241.104.43

Date:
  2026/08/28

Time:
  09:44 UTC

User agent:
  Boto3/1.43.80 md/Botocore#1.43.80 ua/2.1 os/linux#6.12.43+deb13-amd64 md/arch#x86_64 lang/python#3.13.5 md/pyimpl#CPython m/b,D,e,Z cfg/retry-mode#legacy Botocore/1.43.80

Event Name:
  GetCallerIdentity

Canarytoken ID:
  5792dirvqlq9rowicezsid1u4
"""

# A body whose UA is wrapped in square brackets (seen in real alerts).
SAMPLE_BRACKETED = SAMPLE.replace(
    "  Boto3/1.43.80", "  [Boto3/1.43.80"
).replace("Botocore/1.43.80\n\nEvent", "Botocore/1.43.80]\n\nEvent")


def test_parses_core_fields():
    rec = parse_alert_email(SAMPLE, TOKEN_MAP)
    assert rec["source_ip"] == "192.241.104.43"
    assert rec["datetime_utc"] == "2026-08-28T09:44:00Z"
    assert rec["event_name"] == "GetCallerIdentity"
    assert rec["alert_type"] == "ip_triggered"
    assert rec["token_id"] == "5"
    assert rec["placement"] == "terraform.tfvars"
    assert rec["channel"] == "email"
    # UA must survive intact, commas and all.
    assert "m/b,D,e,Z" in rec["user_agent"]
    assert rec["user_agent"].startswith("Boto3/1.43.80")


def test_strips_bracketed_user_agent():
    rec = parse_alert_email(SAMPLE_BRACKETED, TOKEN_MAP)
    assert not rec["user_agent"].startswith("[")
    assert not rec["user_agent"].endswith("]")


def test_placement_falls_back_to_reminder_without_map():
    rec = parse_alert_email(SAMPLE, token_map={})
    assert rec["placement"] == "terraform.tfvars"
    assert rec["token_id"] == ""


def test_non_alert_returns_none():
    assert parse_alert_email("Just a newsletter, nothing to see here.") is None


def test_aws_internal_source_is_not_an_attacker_ip():
    # Regression: "AWS Internal" (AWS's own quarantine) must not be mistaken
    # for an IP — the old regex captured the "A" of "AWS" as a hex address.
    body = SAMPLE.replace("192.241.104.43", "AWS Internal").replace(
        "GetCallerIdentity", "AttachUserPolicy")
    rec = parse_alert_email(body, TOKEN_MAP)
    assert rec["source_ip"] == "AWS Internal"
    assert rec["alert_type"] == "aws_internal"


# An alert from the A/B *placement experiment* — its Reminder line uses the
# ``ab-exp<N>-b<M> <repo> (<placement>)`` memo, not the fleet's Spanish memo.
SAMPLE_EXPERIMENT = """Your Canarytoken was triggered!
-------------------------------

An AWS key Canarytoken has been triggered by the Source IP 54.39.181.162

Reminder:
  ab-exp1-b1 snowflake-sync-agent (.env)

Source IP:
  54.39.181.162

Date:
  2026/08/30

Time:
  13:48 UTC

User agent:
  python-requests/2.33.1

Event Name:
  GetCallerIdentity

Canarytoken ID:
  npdk4z3yi87x3lr98nkb41kpb
"""


def test_experiment_alert_is_tagged_and_not_merged_into_fleet(tmp_path):
    # It still parses (the experiment ingester relies on that), but is tagged.
    rec = parse_alert_email(SAMPLE_EXPERIMENT, TOKEN_MAP)
    assert rec is not None
    assert rec["is_experiment"] is True

    raw = tmp_path / "raw.csv"
    raw.write_text(
        "seq,datetime_utc,date_utc,time_utc,source_ip,event_name,user_agent,"
        "alert_type,token_id,placement,channel\n"
        "1,2026-08-28T09:44:00Z,2026-08-28,09:44,192.241.104.43,"
        "GetCallerIdentity,ua,ip_triggered,5,terraform.tfvars,email\n"
    )
    # Merging the experiment alert must add nothing to the fleet raw.
    combined, n = merge_new_events([rec], raw)
    assert n == 0
    assert len(combined) == 1


def test_merge_dedups_against_existing(tmp_path):
    raw = tmp_path / "raw.csv"
    raw.write_text(
        "seq,datetime_utc,date_utc,time_utc,source_ip,event_name,user_agent,"
        "alert_type,token_id,placement,channel\n"
        "1,2026-08-28T09:44:00Z,2026-08-28,09:44,192.241.104.43,"
        "GetCallerIdentity,ua,ip_triggered,5,terraform.tfvars,email\n"
    )
    rec = parse_alert_email(SAMPLE, TOKEN_MAP)
    # Re-ingesting the same event must add nothing.
    combined, n = merge_new_events([rec], raw)
    assert n == 0
    assert len(combined) == 1

    # A genuinely new event gets appended with the next seq.
    rec2 = dict(rec, time_utc="09:45", datetime_utc="2026-08-28T09:45:00Z",
                event_name="InvokeModel")
    combined, n = merge_new_events([rec2], raw)
    assert n == 1
    assert combined["seq"].astype(int).tolist() == [1, 2]
