# churn-model-service

A small FastAPI service that serves a customer-churn probability model. Given a customer
id (or a feature payload), it returns a churn score and the top contributing features.
CI builds the image and deploys it to our container platform on every push to `main`.

## Local run

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
# POST /predict  {"customer_id": "c_10233"}
```

## Deployment

Deploys are handled by GitHub Actions (`.github/workflows/deploy.yml`): the workflow
builds the image, pushes it to the registry, and rolls it out. Deploy-time AWS
credentials are provided to the job as environment variables.

## Layout

```
churn-model-service/
├── app/
│   ├── main.py        # FastAPI app
│   └── model.py       # model loading + scoring
├── .github/workflows/deploy.yml
└── requirements.txt
```

---

### Research disclosure

This repository is a thin, single-purpose instrument in a public security-research
experiment measuring how fast leaked cloud keys are found in public code. The AWS
credentials referenced by the deploy workflow are a **canary token**: an inert decoy that
grants no access and only records attempts to use it. No real service or account is
behind it. The experiment's findings live in the `canary-token-analytics` repository.
