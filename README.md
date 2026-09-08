# canary-token-analytics

Five fake AWS credentials were deliberately planted across public GitHub repositories. They grant zero access — their only purpose is to fire an alert the moment someone tries to use them. This project captures, enriches, classifies, and prices **every real intrusion attempt** they recorded.

**1 301 events. 210 attacker IPs. 46 countries. 35 days. $6,187/day in potential damage if any key had been real.**

## What would it cost?

A leaked AWS key is a payment method wired to an infinite supermarket of compute. The bots that found these canary tokens within minutes attempted four businesses:

| Attack vector | What it does | Events observed | Sustained daily cost |
|---|---|---:|---:|
| **Bedrock LLMjacking** | Run AI models at the victim's expense | 205 | **$192/day** |
| **EC2 cryptomining** | Launch GPU instances for mining | 13 | **$5,875/day** |
| **SES phishing** | Send email using Amazon's inbox reputation | 413 | **$120/day** |
| **IAM persistence** | Create a backdoor user that survives key revocation | 10 | **unlimited** |

**Conservative total: ~$6,187/day.** That's per key, per day, using the cheapest resource variants and a single concurrent stream. Real operations parallelise.

| Time to detection | Potential loss |
|---|---:|
| 17 minutes (AWS auto-quarantine) | ~$73 |
| 1 hour | ~$258 |
| 24 hours | **$6,187** |
| 1 week | **$43,309** |
| 1 month | **$185,610** |

AWS quarantined these keys in ~17 minutes via its GitHub partner program. Without that safety net, the bill grows linearly until someone notices. IAM persistence (`CreateUser`, `PutUserPolicy`) is not priced because the cost is **total account takeover** — the attacker survives key rotation and the bill becomes whatever they choose to run.

See [`docs/cost_impact.md`](docs/cost_impact.md) for the full methodology and pricing sources.

## Key findings

- **A leaked key is hit within minutes.** Fresh placements begin drawing automated traffic almost immediately after exposure.
- **LLMjacking is the primary objective.** 219 events target AWS Bedrock — hijacking the account to run AI at the victim's expense.
- **One coordinated operator dominates `terraform.tfvars` traffic.** 53 IPs across 23 countries, identical software build, 48/53 on hosting/proxy networks. A single operator behind a rotating proxy pool, not independent attackers.
- **Placement matters.** `.env` draws volume (699 events), `terraform.tfvars` draws depth (465 events, concentrated kill-chain penetration).
- **Privilege escalation attempts observed.** `PutUserPolicy` and `CreateUser` show hands-on operators trying to create backdoors, not just automated scanners.

## MITRE ATT&CK

Every observed API action is mapped to [MITRE ATT&CK for Cloud](https://attack.mitre.org/matrices/enterprise/cloud/) ([`docs/mitre_attack.md`](docs/mitre_attack.md)):

| Tactic | Key techniques | Events |
|---|---|---:|
| Discovery | Cloud Infrastructure Discovery, Valid Accounts | 685 |
| Impact | **T1496 Resource Hijacking** (LLMjacking) | 172 |
| Credential Access | Unsecured Credentials | 124 |
| Persistence | Create Cloud Account | 2 |
| Privilege Escalation | Account Manipulation | 2 |

## The honeypot fleet

| Token | Repository | Placement | Events |
|---|---|---|---:|
| 1 | [social-metrics-vault](https://github.com/aroaxinping/social-metrics-vault) | `.env` | 699 |
| 2 | [homelab-s3-sync](https://github.com/aroaxinping/homelab-s3-sync) | `.env` | — |
| 3 | [cloud-usage-tracker](https://github.com/aroaxinping/cloud-usage-tracker) | `config.ini` | 115 |
| 4 | [sensor-data-lake](https://github.com/aroaxinping/sensor-data-lake) | `settings.yaml` | 22 |
| 5 | [infra-heartbeat](https://github.com/aroaxinping/infra-heartbeat) | `terraform.tfvars` | 465 |

Canary tokens generated with [canarytokens.org](https://canarytokens.org) by [Thinkst](https://thinkst.com). Each token is unique, so every alert is attributable to a specific repo and placement.

## Pipeline

End-to-end data pipeline — from inbox to analysis-ready dataset — in one command:

```
uv run --extra gmail python scripts/fetch_gmail.py   # pull + parse + dedup new alerts
uv run python scripts/build_dataset.py               # enrich + classify + cost model
```

1. **Ingest** — Gmail API (read-only) pulls canarytoken alert emails, parses each into a structured event, merges into the raw dataset. Idempotent and de-duplicated.
2. **Enrich** — for every source IP: geolocation, ASN, infrastructure type, proxy/hosting/mobile flags, GreyNoise mass-scanning signal.
3. **Classify** — each AWS API call mapped to an attacker-intent phase, MITRE ATT&CK technique, and cost-impact vector.

**Automated:** a macOS launchd job runs the full pipeline every 6 hours ([`docs/SCHEDULER_SETUP.md`](docs/SCHEDULER_SETUP.md)).

### OSINT tiers

- **Base tier** (in-pipeline): geo, ASN/org, infra type, ip-api flags, GreyNoise → [`ip_intel.csv`](data/processed/ip_intel.csv)
- **Deep tier** ([`enrich_deep.py`](src/canary_token_analytics/enrich_deep.py)): Shodan InternetDB (ports, tags, CVEs), whois, reverse DNS → [`ip_intel_deep.csv`](data/processed/ip_intel_deep.csv). All lookups query third-party databases about the IP; nothing connects to attacker infrastructure.

## Dashboard

Interactive Streamlit dashboard with timeline, kill chain, world map, MITRE ATT&CK breakdown, placement comparison, infrastructure analysis, and cost impact.

```bash
uv run --extra dashboard streamlit run app/dashboard.py
```

## Experiment: does placement matter? (A/B)

The fleet finding — that infrastructure-flavored keys draw faster, deeper attacks — is suggestive but confounded. To settle it, [`experiment/`](experiment/) specifies a **randomized, matched-block field experiment**: 50 repos, 10 blocks × 5 conditions, with placement assigned at random within each block. See [`experiment/DESIGN.md`](experiment/DESIGN.md).

## Repository structure

```
canary-token-analytics/
├── src/canary_token_analytics/
│   ├── ingest.py        # parse alert emails -> structured events
│   ├── enrich.py        # geo / ASN / infra type / proxy flags / GreyNoise
│   ├── enrich_deep.py   # Shodan InternetDB + whois + reverse DNS
│   ├── taxonomy.py      # AWS API call -> attacker-intent phase
│   ├── mitre.py         # event -> MITRE ATT&CK tactic + technique
│   ├── costs.py         # attack vector -> AWS pricing -> daily burn
│   └── pipeline.py      # orchestrates raw -> enriched CSVs
├── app/dashboard.py     # Streamlit dashboard
├── data/
│   ├── raw/             # source captures
│   └── processed/       # enriched, analysis-ready CSVs
├── experiment/          # randomized A/B placement experiment
├── docs/                # methodology, cost impact, MITRE, OSINT, monetisation
├── scripts/             # fetch_gmail, build_dataset, build_deep_osint
├── deploy/              # launchd plist for scheduled ingestion
├── notebooks/           # exploratory analysis and visualization
└── tests/               # 111 unit + data-quality tests
```

## Scope & limitations

- **Descriptive, not predictive.** This is threat-intelligence case analysis, not statistical modelling.
- **Cost estimates are lower bounds.** They assume cheapest resources and single streams. Real compromises parallelise.
- **No attribution of people.** Enrichment identifies infrastructure (IPs, ASNs, geography), not humans.
- **Passive OSINT only.** No authentication was attempted, no credential was ever submitted to a target.

See [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) for the full methodology, confidence grading, and ethics statement.

## How to run

```bash
uv sync
uv run python scripts/build_dataset.py                    # rebuild from raw events
uv run --extra gmail python scripts/fetch_gmail.py         # pull fresh alerts (OAuth setup required)
uv run --extra dashboard streamlit run app/dashboard.py    # launch the dashboard
```
