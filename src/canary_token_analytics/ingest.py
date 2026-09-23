"""Ingest canarytoken alert emails into the raw dataset.

The parser turns one alert email's plain-text body into a structured event
record; the merge step deduplicates against the existing raw CSV and assigns
new sequence numbers. Fetching the emails themselves is deliberately kept out
of here (see ``scripts/ingest_emails.py``) so this logic stays pure and
testable: given text in, records out.
"""

import re
from pathlib import Path

import pandas as pd

RAW_COLUMNS = [
    "seq", "datetime_utc", "date_utc", "time_utc",
    "source_ip", "event_name", "user_agent", "alert_type",
    "token_id", "placement", "channel",
]

_SRC_RE = re.compile(r"Source IP:\s*\n\s*(.*)")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _is_ip(text):
    """True if ``text`` looks like a real IPv4 or IPv6 address."""
    if _IPV4_RE.match(text):
        return True
    return ":" in text and re.match(r"^[0-9A-Fa-f:.]+$", text) is not None
_DATE_RE = re.compile(r"Date:\s*\n\s*(\d{4})/(\d{2})/(\d{2})")
_TIME_RE = re.compile(r"Time:\s*\n\s*(\d{2}:\d{2})")
_UA_RE = re.compile(r"User agent:\s*\n\s*(.+)")
_EVENT_RE = re.compile(r"Event Name:\s*\n\s*(\S+)")
_TOKEN_RE = re.compile(r"Canarytoken ID:\s*\n\s*(\S+)")
_REMINDER_RE = re.compile(r"AWS key en (\S+) de")
# Alerts from the A/B *placement experiment* carry a memo of the form
# ``ab-exp1-b1 <repo_name> (<placement>)``. They belong to a separate dataset
# (see ``experiment/``) and must never be merged into the fleet raw.
_EXP_MEMO_RE = re.compile(r"ab-exp(\d+)-b(\d+)\s+(\S+)\s+\((.+)\)")


def is_experiment_email(body):
    """True if this alert body is an A/B placement-experiment alert.

    Detected by its Reminder/memo line (``ab-exp<N>-b<M> <repo> (<placement>)``),
    which distinguishes it from a fleet alert (``AWS key en <placement> de ...``).
    """
    return _EXP_MEMO_RE.search(body) is not None


def load_token_map(registry_path):
    """Return {canarytoken_id: (token_id, placement)} from fleet_registry.csv."""
    reg = pd.read_csv(registry_path, dtype=str, keep_default_na=False)
    out = {}
    for _, r in reg.iterrows():
        cid = r.get("canarytoken_id", "").strip()
        if cid:
            out[cid] = (r["token_id"], r["placement"])
    return out


def parse_alert_email(body, token_map=None):
    """Parse one canarytoken alert email body into an event record.

    Returns a dict with the raw-schema fields (minus ``seq``), or ``None`` if
    the body is not a parseable *triggered* alert (e.g. a digest or a
    format we don't recognise). ``token_map`` maps the Canarytoken ID to
    ``(token_id, placement)``; without it, placement falls back to the
    reminder line and ``token_id`` is left blank.
    """
    token_map = token_map or {}

    m_date = _DATE_RE.search(body)
    m_time = _TIME_RE.search(body)
    m_event = _EVENT_RE.search(body)
    if not (m_date and m_time and m_event):
        return None

    src_m = _SRC_RE.search(body)
    source_raw = src_m.group(1).strip() if src_m else ""
    # A real attacker IP vs AWS's own detections ("AWS Internal") or a blank
    # source (AWS-side safetynet flags). Only the former is an attacker.
    if _is_ip(source_raw):
        source_ip, alert_type = source_raw, "ip_triggered"
    elif source_raw:
        source_ip, alert_type = source_raw, "aws_internal"
    else:
        source_ip, alert_type = "", "safetynet"

    ua_m = _UA_RE.search(body)
    user_agent = ua_m.group(1).strip() if ua_m else ""
    # Some alerts wrap the UA in square brackets — strip them.
    if user_agent.startswith("[") and user_agent.endswith("]"):
        user_agent = user_agent[1:-1]

    y, mo, d = m_date.groups()
    date_utc = f"{y}-{mo}-{d}"
    time_utc = m_time.group(1)

    cid_m = _TOKEN_RE.search(body)
    canarytoken_id = cid_m.group(1) if cid_m else ""

    if is_experiment_email(body):
        # Tag experiment alerts so ``merge_new_events`` keeps them out of the
        # fleet raw. They are ingested separately by
        # ``experiment/scripts/ingest_experiment.py``.
        return {
            "datetime_utc": f"{date_utc}T{time_utc}:00Z",
            "date_utc": date_utc,
            "time_utc": time_utc,
            "source_ip": source_ip,
            "event_name": m_event.group(1),
            "user_agent": user_agent,
            "alert_type": alert_type,
            "token_id": "",
            "placement": "",
            "channel": "email",
            "is_experiment": True,
        }

    token_id, placement = "", ""
    if canarytoken_id in token_map:
        token_id, placement = token_map[canarytoken_id]
    else:
        rem_m = _REMINDER_RE.search(body)
        if rem_m:
            placement = rem_m.group(1)

    return {
        "datetime_utc": f"{date_utc}T{time_utc}:00Z",
        "date_utc": date_utc,
        "time_utc": time_utc,
        "source_ip": source_ip,
        "event_name": m_event.group(1),
        "user_agent": user_agent,
        "alert_type": alert_type,
        "token_id": token_id,
        "placement": placement,
        "channel": "email",
    }


def _dedup_key(rec):
    return (rec["date_utc"], rec["time_utc"], rec["source_ip"],
            rec["event_name"], str(rec["token_id"]))


def merge_new_events(records, raw_path):
    """Merge parsed ``records`` into the raw CSV, deduplicating.

    Dedup key is (date, time, source_ip, event_name, token_id). New events are
    appended in chronological order with sequence numbers continuing after the
    current maximum; existing rows and their seqs are left untouched. Returns
    ``(combined_df, n_added)``.
    """
    raw_path = Path(raw_path)
    existing = pd.read_csv(raw_path, dtype=str, keep_default_na=False)
    seen = {(_dedup_key(r)) for _, r in existing.iterrows()}

    fresh = []
    for rec in records:
        if rec is None:
            continue
        # A/B experiment alerts belong to a separate dataset; never let them
        # into the fleet raw even if a caller passes them in.
        if rec.get("is_experiment"):
            continue
        k = _dedup_key(rec)
        if k in seen:
            continue
        seen.add(k)
        fresh.append(rec)

    fresh.sort(key=lambda r: r["datetime_utc"])
    next_seq = (existing["seq"].astype(int).max() + 1) if len(existing) else 1
    for i, rec in enumerate(fresh):
        rec["seq"] = next_seq + i

    combined = pd.concat(
        [existing, pd.DataFrame(fresh, columns=RAW_COLUMNS)],
        ignore_index=True,
    ) if fresh else existing
    return combined, len(fresh)
