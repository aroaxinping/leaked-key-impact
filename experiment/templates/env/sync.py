"""Sync materialized features from the offline store into the online cache."""
import argparse
import logging
import os

from feature_store import FeatureStore

logging.basicConfig(level=os.getenv("LOG_LEVEL", "info").upper())
log = logging.getLogger("feature-store-sync")


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline -> online feature sync")
    parser.add_argument("--group", required=True, help="feature group to sync")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    store = FeatureStore.from_env()
    report = store.sync_group(args.group, dry_run=args.dry_run)

    log.info(
        "synced group=%s entities=%d freshness=%s",
        args.group,
        report["entities"],
        report["max_age"],
    )


if __name__ == "__main__":
    main()
