"""Cost-impact model for observed canary-token attack vectors.

Maps each observed attack vector to public AWS pricing (conservative
estimates) so the dataset can answer "what would this cost if the keys
had been real?"

Prices are from public AWS pricing pages as of 2026-09. All estimates
are *lower bounds* — they assume the cheapest resource variant and a
single concurrent stream. Real compromises run many in parallel.
"""

COST_MODEL = {
    "bedrock_llmjacking": {
        "label": "Bedrock LLMjacking",
        "events": [
            "InvokeModel",
            "InvokeModelWithResponseStream",
            "Converse",
            "ConverseStream",
        ],
        "description": "Run AI models on Bedrock at the victim's expense",
        "unit_cost_usd": 0.016,
        "unit_label": "per call (Claude Haiku, ~1K tokens)",
        "sustained_calls_per_hour": 500,
        "daily_cost_usd": 192.0,
        "source": "https://aws.amazon.com/bedrock/pricing/",
    },
    "ec2_cryptomining": {
        "label": "EC2 cryptomining",
        "events": ["RunInstances"],
        "description": "Launch GPU instances for cryptocurrency mining",
        "unit_cost_usd": 24.48,
        "unit_label": "per hour (p3.16xlarge)",
        "sustained_calls_per_hour": 10,
        "daily_cost_usd": 5_875.0,
        "source": "https://aws.amazon.com/ec2/pricing/on-demand/",
    },
    "ses_phishing": {
        "label": "SES email phishing",
        "events": ["GetSendQuota", "ListEmailIdentities"],
        "description": "Send phishing emails using Amazon's inbox reputation",
        "unit_cost_usd": 0.10,
        "unit_label": "per 1,000 emails",
        "sustained_calls_per_hour": 50_000,
        "daily_cost_usd": 120.0,
        "source": "https://aws.amazon.com/ses/pricing/",
    },
    "iam_persistence": {
        "label": "IAM persistence (backdoor)",
        "events": ["CreateUser", "PutUserPolicy", "AddUserToGroup"],
        "description": "Create backdoor IAM user that survives key revocation",
        "unit_cost_usd": None,
        "unit_label": "no direct cost",
        "sustained_calls_per_hour": None,
        "daily_cost_usd": None,
        "source": "cost is total account takeover — unlimited",
    },
}


def estimate_daily_burn(event_counts: dict[str, int]) -> dict:
    """Given a dict of {event_name: count}, return cost estimates.

    Returns a dict with per-vector breakdowns and a total.
    """
    vectors = []
    total = 0.0

    for key, model in COST_MODEL.items():
        n = sum(event_counts.get(e, 0) for e in model["events"])
        if n == 0:
            continue
        vectors.append({
            "vector": model["label"],
            "events_observed": n,
            "unit_cost": model["unit_label"],
            "daily_cost_usd": model["daily_cost_usd"],
            "source": model["source"],
        })
        if model["daily_cost_usd"]:
            total += model["daily_cost_usd"]

    return {"vectors": vectors, "total_daily_usd": total}
