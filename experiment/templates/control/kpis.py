"""KPI aggregations for the daily snapshot."""
from __future__ import annotations


def build_snapshot(date: str) -> dict:
    """Return the day's KPI dictionary.

    In the real pipeline these are SQL rollups over the warehouse; here the shape is
    kept simple so the repo stays a thin, believable instrument.
    """
    return {
        "date": date,
        "orders": 0,
        "gross_revenue": 0.0,
        "sessions": 0,
        "refund_rate": 0.0,
        "aov": 0.0,
    }
