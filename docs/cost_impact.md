# Cost impact: what a leaked key is worth to an attacker

Every event in this dataset is an action a bot *tried* to take with a stolen AWS
key. Because these were canary tokens, nothing actually ran — but we can price
what *would* have happened using public AWS rates. The question this answers is
not "what did we lose?" (nothing — the keys were fake) but **"what does a company
lose per hour that a real key stays exposed?"**

## Attack vectors observed and their cost

| Vector | Events observed | Unit cost | Sustained daily burn |
|---|---:|---|---:|
| **Bedrock LLMjacking** (InvokeModel, Converse, streaming variants) | 205 | ~$0.016/call (Haiku, ~1K tokens) | **$192/day** |
| **EC2 cryptomining** (RunInstances) | 13 | $24.48/hour (p3.16xlarge) | **$5,875/day** |
| **SES phishing** (GetSendQuota, ListEmailIdentities) | 413 | $0.10/1,000 emails | **$120/day** |
| **IAM persistence** (CreateUser, PutUserPolicy, AddUserToGroup) | 10 | — | **unlimited** |

**Conservative total: ~$6,187/day** ($185,610/month if undetected).

These are *lower bounds*. They assume the cheapest instance type, the smallest
model, and a single concurrent stream. Real LLMjacking operations run Claude
Opus or GPT-4-class models at 10–50× the Haiku rate; real cryptominers launch
dozens of instances in parallel.

## The real variable: time to detection

AWS auto-quarantined these keys in **~17 minutes** via its GitHub partner program.
That's the safety net. Without it:

| Time to detection | Potential loss |
|---|---:|
| 17 minutes (AWS auto-quarantine) | ~$73 |
| 1 hour | ~$258 |
| 24 hours | **$6,187** |
| 1 week | **$43,309** |
| 1 month | **$185,610** |

The IAM persistence row (`CreateUser`, `PutUserPolicy`) is not priced because
the cost is **total account takeover**. If the attacker creates a backdoor user
before quarantine kicks in, they survive key rotation — and the bill becomes
whatever they choose to run, for as long as the backdoor goes unnoticed.

## Why this matters

A leaked AWS key is not a theoretical risk — this dataset proves that
**automated bots find and attempt to exploit exposed credentials within
minutes**. The $6,187/day figure is the business case for:

- **Secrets scanning** in CI/CD (GitHub Push Protection, GitGuardian, TruffleHog)
- **AWS CloudTrail + GuardDuty** alerting on anomalous API calls
- **IAM least-privilege** — keys with narrow permissions limit blast radius
- **Short-lived credentials** (IAM Roles, STS AssumeRole) instead of long-lived access keys

## Methodology

All prices are from public AWS pricing pages (September 2026). Sustained daily
burn assumes one concurrent abuse stream running 24 hours — real attacks
parallelise across many streams, so actual costs would be higher. The model
lives in [`src/canary_token_analytics/costs.py`](../src/canary_token_analytics/costs.py)
and is used by the Streamlit dashboard.
