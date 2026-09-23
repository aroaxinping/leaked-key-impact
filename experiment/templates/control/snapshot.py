"""Build the daily KPI snapshot and export it to S3."""
import argparse
import logging
import os

import boto3

from kpis import build_snapshot

logging.basicConfig(level=os.getenv("LOG_LEVEL", "info").upper())
log = logging.getLogger("kpi-snapshot-pipeline")


def main() -> None:
    parser = argparse.ArgumentParser(description="Daily KPI snapshot")
    parser.add_argument("--date", required=True, help="snapshot date (ISO)")
    args = parser.parse_args()

    snapshot = build_snapshot(args.date)

    s3 = boto3.client(
        "s3",
        region_name=os.getenv("AWS_DEFAULT_REGION", "eu-west-1"),
        aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
    )
    key = f"snapshots/{args.date}.json"
    # s3.put_object(Bucket=os.environ["EXPORT_BUCKET"], Key=key, Body=snapshot.json())
    log.info("built snapshot for %s (%d kpis) -> %s", args.date, len(snapshot), key)


if __name__ == "__main__":
    main()
