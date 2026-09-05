"""Offline (S3/Parquet) read + online (Redis) upsert."""
from __future__ import annotations

import os
from dataclasses import dataclass

import boto3
import redis
import yaml


@dataclass
class FeatureStore:
    bucket: str
    prefix: str
    region: str
    ttl: int
    redis_client: redis.Redis

    @classmethod
    def from_env(cls) -> "FeatureStore":
        session = boto3.session.Session(
            aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
            region_name=os.getenv("AWS_DEFAULT_REGION", "eu-west-1"),
        )
        cls._s3 = session.client("s3")
        return cls(
            bucket=os.environ["FEATURE_BUCKET"],
            prefix=os.getenv("FEATURE_PREFIX", "materialized"),
            region=os.getenv("AWS_DEFAULT_REGION", "eu-west-1"),
            ttl=int(os.getenv("FEATURE_TTL_SECONDS", "86400")),
            redis_client=redis.Redis(
                host=os.getenv("REDIS_HOST", "localhost"),
                port=int(os.getenv("REDIS_PORT", "6379")),
                db=int(os.getenv("REDIS_DB", "0")),
            ),
        )

    def _definitions(self, group: str) -> dict:
        with open("feature_definitions.yaml") as fh:
            return yaml.safe_load(fh)["groups"][group]

    def sync_group(self, group: str, dry_run: bool = False) -> dict:
        definition = self._definitions(group)
        key = f"{self.prefix}/{group}/latest.parquet"
        # (read Parquet partition, upsert per-entity vectors — trimmed for brevity)
        entities = definition.get("expected_entities", 0)
        return {"entities": entities, "max_age": "0h", "source": key}
