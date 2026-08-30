"""Cleaning and normalization for raw retail order batches."""
from __future__ import annotations

import io
import json


def _parse(raw: bytes) -> list[dict]:
    text = raw.decode("utf-8")
    if text.lstrip().startswith("["):
        return json.loads(text)
    reader = io.StringIO(text)
    header = reader.readline().strip().split(",")
    return [dict(zip(header, line.strip().split(","))) for line in reader]


def clean_orders(raw: bytes, section) -> list[dict]:
    rows = _parse(raw)
    drop_test = section.getboolean("drop_test_orders", fallback=True)
    default_ccy = section.get("default_currency", "EUR")

    cleaned, seen = [], set()
    for row in rows:
        oid = row.get("order_id")
        if not oid or oid in seen:
            continue
        if drop_test and str(row.get("is_test", "")).lower() in {"1", "true"}:
            continue
        row.setdefault("currency", default_ccy)
        seen.add(oid)
        cleaned.append(row)
    return cleaned
