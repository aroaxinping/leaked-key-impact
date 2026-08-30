#!/usr/bin/env python3
"""Ingest the A/B placement-experiment alert emails into their own dataset.

The placement experiment (see ``experiment/DESIGN.md``) is a *separate* study
from the original 5-token fleet. Its canarytoken alerts carry a memo of the
form ``ab-exp<N>-b<M> <repo_name> (<placement>)`` and MUST NOT pollute the
fleet raw dataset. This script scans the shared email cache, keeps only the
experiment alerts, attributes each one to its block/condition by joining on
``repo_name`` against ``experiment/block_assignment.csv``, and writes the
attributed dataset to ``experiment/data/experiment_alerts.csv``.

    uv run python experiment/scripts/ingest_experiment.py

Attribution note. The memo's own placement string is only a hint (and can be
abbreviated, e.g. ``ci-deploy``); two repos may share ``.env``. The canonical
``condition`` and ``placement`` therefore come from the block assignment,
joined unambiguously on ``repo_name`` — never inferred from the memo text.
"""

import re
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from canary_token_analytics.ingest import _is_ip  # noqa: E402

CACHE = ROOT / "data" / "raw" / "emails_cache"
ASSIGN = ROOT / "experiment" / "block_assignment.csv"
OUT_DIR = ROOT / "experiment" / "data"
OUT = OUT_DIR / "experiment_alerts.csv"

OUT_COLUMNS = [
    "datetime_utc", "date_utc", "time_utc",
    "source_ip", "event_name", "alert_type",
    "experiment", "block_id", "repo_name", "condition", "placement",
    "canarytoken_id",
]

_EXP_MEMO_RE = re.compile(r"ab-exp(\d+)-b(\d+)\s+(\S+)\s+\((.+)\)")
_DATE_RE = re.compile(r"Date:\s*\n\s*(\d{4})/(\d{2})/(\d{2})")
_TIME_RE = re.compile(r"Time:\s*\n\s*(\d{2}:\d{2})")
_EVENT_RE = re.compile(r"Event Name:\s*\n\s*(\S+)")
_SRC_RE = re.compile(r"Source IP:\s*\n\s*(.*)")
_TOKEN_RE = re.compile(r"Canarytoken ID:\s*\n\s*(\S+)")


def parse_experiment_email(body, assign_map):
    """Parse one experiment alert body into an attributed record, or None.

    ``assign_map`` maps ``repo_name -> (block_id, condition, placement)`` from
    the block assignment; the memo supplies only the experiment/block numbers
    and the repo name used to look the rest up.
    """
    memo = _EXP_MEMO_RE.search(body)
    if not memo:
        return None
    m_date = _DATE_RE.search(body)
    m_time = _TIME_RE.search(body)
    m_event = _EVENT_RE.search(body)
    if not (m_date and m_time and m_event):
        return None

    experiment, _block_memo, repo_name, _placement_memo = memo.groups()

    src_m = _SRC_RE.search(body)
    source_raw = src_m.group(1).strip() if src_m else ""
    if _is_ip(source_raw):
        source_ip, alert_type = source_raw, "ip_triggered"
    else:
        # "AWS Internal" (AWS's own quarantine action) or a blank source.
        source_ip, alert_type = source_raw, "aws_internal"

    y, mo, d = m_date.groups()
    date_utc = f"{y}-{mo}-{d}"
    time_utc = m_time.group(1)

    cid_m = _TOKEN_RE.search(body)
    canarytoken_id = cid_m.group(1) if cid_m else ""

    # Canonical attribution comes from the block assignment, keyed by repo_name.
    block_id, condition, placement = assign_map.get(repo_name, ("", "", ""))

    return {
        "datetime_utc": f"{date_utc}T{time_utc}:00Z",
        "date_utc": date_utc,
        "time_utc": time_utc,
        "source_ip": source_ip,
        "event_name": m_event.group(1),
        "alert_type": alert_type,
        "experiment": experiment,
        "block_id": block_id,
        "repo_name": repo_name,
        "condition": condition,
        "placement": placement,
        "canarytoken_id": canarytoken_id,
    }


def _dedup_key(rec):
    return (rec["date_utc"], rec["time_utc"], rec["source_ip"],
            rec["event_name"], rec["canarytoken_id"])


def load_assignment(path):
    a = pd.read_csv(path, dtype=str, keep_default_na=False)
    return {
        r["repo_name"]: (r["block_id"], r["condition"], r["placement"])
        for _, r in a.iterrows()
    }


def main():
    assign_map = load_assignment(ASSIGN)
    files = sorted(p for p in CACHE.iterdir() if p.is_file())

    records, seen, unresolved = [], set(), set()
    for p in files:
        rec = parse_experiment_email(p.read_text(errors="replace"), assign_map)
        if rec is None:
            continue
        if not rec["condition"]:
            unresolved.add(rec["repo_name"])
        k = _dedup_key(rec)
        if k in seen:
            continue
        seen.add(k)
        records.append(rec)

    records.sort(key=lambda r: r["datetime_utc"])
    df = pd.DataFrame(records, columns=OUT_COLUMNS)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT, index=False)

    print(f"scanned {len(files)} cached emails")
    print(f"wrote {len(df)} experiment alerts -> {OUT.relative_to(ROOT)}")
    if not df.empty:
        print("\nper condition:")
        print(df.groupby("condition").size().to_string())
        print("\nrepos:", ", ".join(sorted(df["repo_name"].unique())))
    if unresolved:
        print("\n! repos with no block-assignment match:", sorted(unresolved))


if __name__ == "__main__":
    main()
