#!/bin/bash
# Scheduled ingest: pull new canarytoken alerts from Gmail and rebuild the
# analysis. Meant to be driven by launchd (see deploy/ + docs/SCHEDULER_SETUP.md),
# but also runnable by hand. Deliberately does NOT commit or push — new data is
# left in the working tree for you to review and commit yourself.
set -uo pipefail

REPO="$HOME/canary-token-analytics"
UV="/opt/homebrew/bin/uv"          # absolute: launchd runs with a minimal PATH
LOG="$REPO/logs/ingest.log"

mkdir -p "$REPO/logs"
cd "$REPO" || exit 1

echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) ingest run ===" >> "$LOG"
"$UV" run --extra gmail python scripts/fetch_gmail.py >> "$LOG" 2>&1
"$UV" run python scripts/build_dataset.py             >> "$LOG" 2>&1
# A/B experiment: attribute the pilot's alerts (fetch_gmail already cached them).
"$UV" run python experiment/scripts/ingest_experiment.py >> "$LOG" 2>&1
echo "=== done $(date -u +%H:%M:%SZ) ===" >> "$LOG"
