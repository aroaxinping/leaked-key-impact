"""Churn model loading and scoring."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ChurnModel:
    version: str

    @classmethod
    def load(cls, path: str = "artifacts/churn.pkl") -> "ChurnModel":
        # Real code would deserialize a trained estimator here.
        return cls(version="2026.08.1")

    def lookup_features(self, customer_id: str | None) -> dict[str, float]:
        return {"tenure_months": 12.0, "support_tickets_30d": 1.0, "avg_order_value": 42.5}

    def score(self, features: dict[str, float]) -> tuple[float, list[dict]]:
        # Placeholder scoring; a real model would call estimator.predict_proba.
        risk = min(1.0, features.get("support_tickets_30d", 0) * 0.15)
        contributions = [{"feature": k, "value": v} for k, v in features.items()]
        return risk, contributions
