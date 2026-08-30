"""S3 landing-zone reader for the retail ETL loader."""
from __future__ import annotations

from dataclasses import dataclass

import boto3


@dataclass
class S3LandingZone:
    bucket: str
    prefix: str
    client: object

    @classmethod
    def from_config(cls, section) -> "S3LandingZone":
        client = boto3.client(
            "s3",
            region_name=section.get("region", "eu-west-1"),
            aws_access_key_id=section["aws_access_key_id"],
            aws_secret_access_key=section["aws_secret_access_key"],
        )
        return cls(
            bucket=section["landing_bucket"],
            prefix=section["landing_prefix"],
            client=client,
        )

    def iter_new_objects(self, since: str):
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            for obj in page.get("Contents", []):
                if obj["LastModified"].isoformat() >= since:
                    body = self.client.get_object(
                        Bucket=self.bucket, Key=obj["Key"]
                    )["Body"].read()
                    yield body
