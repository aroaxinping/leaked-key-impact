# feature-store-sync

Small service that syncs computed features from our offline store (S3 + Parquet) into
an online Redis cache so low-latency models can read them at request time. Runs on a
schedule and keeps an eye on freshness so nothing goes stale.

## What it does

- Reads feature groups defined in `feature_definitions.yaml`
- Pulls the latest materialized Parquet partitions from S3
- Upserts each entity's feature vector into Redis with a TTL
- Emits a small freshness report per feature group

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then fill in your own values
python sync.py --group user_activity
```

Configuration is read from environment variables (see `.env`). The offline store lives
in S3, so AWS credentials are needed for the read side.

## Layout

```
feature-store-sync/
├── sync.py                   # entry point
├── feature_store.py          # S3 read + Redis upsert
├── feature_definitions.yaml  # feature groups
├── requirements.txt
└── .env                      # runtime config (AWS + Redis)
```

---

### Note on this repository

This repository is one of a small fleet of thin instruments in a public
security-research project on leaked-credential exposure. The AWS key committed here is a
**canary token** — a fake credential that grants no access to anything and exists only to
record any attempt to use it. Nothing here connects to a real account. Data collected
from the fleet is analyzed in the `canary-token-analytics` project.
