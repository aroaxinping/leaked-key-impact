#!/bin/bash
# Re-execute the showcase notebook with the current dataset. Driven by launchd
# at 00:05 daily (see deploy/com.aroa.canary-notebook.plist). The 6-hourly
# ingest keeps the data fresh; this just refreshes the notebook's outputs/charts
# (including the MITRE ATT&CK view). Does NOT commit — review and commit yourself.
set -uo pipefail
REPO="$HOME/canary-token-analytics"
UV="/opt/homebrew/bin/uv"
LOG="$REPO/logs/notebook.log"

mkdir -p "$REPO/logs"
cd "$REPO" || exit 1

echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) notebook refresh ===" >> "$LOG"
"$UV" run --extra dev jupyter nbconvert --to notebook --execute --inplace \
    notebooks/01_attack_anatomy.ipynb >> "$LOG" 2>&1
echo "=== done $(date -u +%H:%M:%SZ) ===" >> "$LOG"
