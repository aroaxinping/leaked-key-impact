"""CLI entry point for the retail ETL loader."""
import argparse
import configparser
import logging

from loader.extract import S3LandingZone
from loader.transform import clean_orders

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("retail-etl-loader")


def load_config(path: str) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(path)
    return cfg


def main() -> None:
    parser = argparse.ArgumentParser(description="Retail transactions ETL")
    parser.add_argument("--config", default="config.ini")
    parser.add_argument("--since", required=True, help="ISO date lower bound")
    args = parser.parse_args()

    cfg = load_config(args.config)
    zone = S3LandingZone.from_config(cfg["aws"])

    total = 0
    for batch in zone.iter_new_objects(since=args.since):
        rows = clean_orders(batch, cfg["transform"])
        total += len(rows)
        # upsert(rows, cfg["warehouse"])  # trimmed
    log.info("loaded %d cleaned rows since %s", total, args.since)


if __name__ == "__main__":
    main()
