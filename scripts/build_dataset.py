"""Build the enriched canary-token dataset end to end.

Run from the repo root:

    python scripts/build_dataset.py

Reads data/raw/canary_alerts_raw.csv, performs live IP lookups, and writes
the processed CSVs into data/processed/.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from canary_token_analytics.pipeline import run_pipeline  # noqa: E402


def main():
    raw_path = REPO_ROOT / "data" / "raw" / "canary_alerts_raw.csv"
    processed_dir = REPO_ROOT / "data" / "processed"
    print("Building enriched canary-token dataset")
    enriched_df, ip_intel_df = run_pipeline(raw_path, processed_dir)
    print("\nInfra classification summary:")
    print(ip_intel_df[["source_ip", "country", "org", "infra_type"]].to_string(index=False))
    print("\nDone.")


if __name__ == "__main__":
    main()
