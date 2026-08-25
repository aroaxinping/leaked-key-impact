"""Ingest canarytoken alert emails from a directory of saved bodies.

Each file in the input directory is one alert email's plain-text body (e.g.
dumped from the Gmail API). The script parses them, deduplicates against the
existing raw CSV, appends the new events, and writes the raw CSV back.

    uv run python scripts/ingest_emails.py <dir-of-email-bodies>

The parsing/merge logic lives in ``canary_token_analytics.ingest`` and is
unit-tested; this script is just the file-to-CSV wiring, so swapping the email
source (saved files today, a live Gmail fetch later) needs no change here.
"""

import sys
from pathlib import Path

from canary_token_analytics.ingest import (
    load_token_map,
    parse_alert_email,
    merge_new_events,
)

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw" / "canary_alerts_raw.csv"
REGISTRY = ROOT / "data" / "raw" / "fleet_registry.csv"


def main(indir):
    indir = Path(indir)
    files = sorted(p for p in indir.iterdir() if p.is_file())
    token_map = load_token_map(REGISTRY)

    records, skipped = [], 0
    for p in files:
        rec = parse_alert_email(p.read_text(errors="replace"), token_map)
        if rec is None:
            skipped += 1
        else:
            records.append(rec)

    combined, n_added = merge_new_events(records, RAW)
    combined.to_csv(RAW, index=False)
    print(f"read {len(files)} files, parsed {len(records)}, skipped {skipped}")
    print(f"added {n_added} new events -> {len(combined)} total in {RAW.name}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: ingest_emails.py <dir-of-email-bodies>")
    main(sys.argv[1])
