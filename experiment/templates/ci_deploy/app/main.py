"""FastAPI churn-scoring service."""
from fastapi import FastAPI
from pydantic import BaseModel

from app.model import ChurnModel

app = FastAPI(title="churn-model-service")
model = ChurnModel.load()


class PredictRequest(BaseModel):
    customer_id: str | None = None
    features: dict[str, float] | None = None


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "model_version": model.version}


@app.post("/predict")
def predict(req: PredictRequest) -> dict:
    features = req.features or model.lookup_features(req.customer_id)
    score, contributions = model.score(features)
    return {
        "customer_id": req.customer_id,
        "churn_probability": round(score, 4),
        "top_factors": contributions[:3],
    }
