#!/bin/bash
# Re-authorise the Gmail ingestion when the OAuth token expires.
#
# The OAuth app is in "Testing" mode, so Google expires the refresh token
# in token.json every ~7 days. When the scheduled ingest starts failing
# (see logs/ingest.log), run this once — it drops the old token and re-runs
# the fetch, which opens the browser for a single consent click and writes a
# fresh token. No data is lost: alerts accumulate in Gmail and the fetch
# pulls the whole backlog.
#
#   bash scripts/reauth_gmail.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
rm -f token.json
echo "old token removed — a browser will open for one consent click..."
uv run --extra gmail python scripts/fetch_gmail.py
