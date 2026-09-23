# kpi-snapshot-pipeline

Lightweight pipeline that pulls daily metrics from a few sources, rolls them into a
single KPI snapshot table, and pushes a static dashboard export to S3 for the analytics
team to review each morning.

## What it does

- Aggregates orders, sessions, and refunds into daily KPIs
- Writes a `kpi_snapshot` table to the warehouse
- Exports a JSON snapshot to S3 that the internal dashboard reads

## Run

```bash
pip install -r requirements.txt
cp .env.example .env   # fill in your own values
python snapshot.py --date 2026-08-30
```

Configuration is read from `.env`.

## Layout

```
kpi-snapshot-pipeline/
├── snapshot.py     # entry point
├── kpis.py         # metric aggregations
├── requirements.txt
└── .env            # runtime config
```

---

### Repository note

This repository belongs to a public security-research experiment on leaked-credential
exposure. Unlike the other repositories in the fleet, this one is a **control**: the
`.env` contains only an obviously-fake placeholder AWS key, not a live canary token, so
no alert can ever fire from it. It exists to baseline how scanners react to a clearly
non-functional credential. Analysis lives in `canary-token-analytics`.
