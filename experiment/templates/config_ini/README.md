# retail-etl-loader

Batch ETL job that loads raw retail transaction exports from an S3 landing zone,
cleans and normalizes them, and writes analysis-ready tables to a Postgres warehouse.
Built to run nightly from cron or Airflow.

## Pipeline

1. **Extract** — list new CSV/JSON drops under the S3 landing prefix
2. **Transform** — dedupe, coerce types, resolve currencies, drop test orders
3. **Load** — upsert into `fact_orders` and `dim_customer`

## Running it

```bash
pip install -r requirements.txt
python -m loader.run --config config.ini --since 2026-08-01
```

All connection details (S3, warehouse) live in `config.ini`. Copy it, fill in your own
credentials, and keep your copy out of version control.

## Files

```
retail-etl-loader/
├── config.ini             # S3 + warehouse connection settings
├── loader/
│   ├── run.py             # CLI entry point
│   ├── extract.py         # S3 landing-zone reader
│   └── transform.py       # cleaning + normalization
└── requirements.txt
```

---

## About this repository

This repo is a deliberately thin instrument in a public security-research experiment on
how quickly leaked cloud credentials are discovered and abused. The AWS key in
`config.ini` is a **canary token**: a decoy credential with no access to any real
resource, wired only to log attempts to use it. It is safe by design. Aggregated results
from the wider fleet are studied in the `canary-token-analytics` project.
