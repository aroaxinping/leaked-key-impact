# canary-token-analytics

Threat-intelligence analysis of **1 301 real intrusion attempts** against a fleet of deliberately leaked AWS canary tokens — 210 unique attacker IPs across 46 countries, collected over 35 days of continuous monitoring.

## What is this?

A canary token is a fake credential that grants no access. Its only job is to trip an alarm: the moment someone tries to use it, it fires an alert with the source IP, the API action attempted, and a timestamp. It is a tripwire for credential theft.

This project planted five AWS canary tokens across public GitHub repositories — each in a different kind of file — and built a complete data-analytics pipeline around the attacks they recorded: automated ingestion, IP enrichment, attacker-intent classification, MITRE ATT&CK mapping, and passive OSINT investigation.

Every event in the dataset is a real actor (an automated bot or an AWS-side defense) trying to do something with a credential that was already dead.

## Key findings

- **AWS auto-quarantined the leaked key in ~17 minutes.** Every later attempt hit a credential that had been dead since minute 17.
- **LLMjacking is the primary objective.** 219 events target AWS Bedrock (`InvokeModel`, `Converse`, `ConverseStream`) — hijacking the account to run AI models at the victim's expense.
- **One coordinated operator dominates `terraform.tfvars` traffic.** 53 IPs across 23 countries running an identical software build (same Linux kernel, boto3 version, retry mode), 48 of 53 on hosting/proxy networks (M247, HostRoyale, ServerMania, Leaseweb). A single operator behind a rotating proxy pool, not independent attackers.
- **Placement matters.** `.env` draws the most volume (699 events), `terraform.tfvars` draws the deepest kill-chain penetration (465 events, concentrated abuse). `config.ini` and `settings.yaml` trail significantly.
- **A leaked key is hit within minutes.** Fresh placements begin drawing automated traffic almost immediately.
- **Privilege escalation attempts observed.** `PutUserPolicy` (granting durable permissions) and `CreateUser` (backdoor IAM user) show hands-on operators, not just automated scanners.

## MITRE ATT&CK coverage

Every observed API action is mapped to MITRE ATT&CK for Cloud ([`docs/mitre_attack.md`](docs/mitre_attack.md)):

| Tactic | Techniques | Events |
|---|---|---:|
| Discovery | `T1580`, `T1078.004`, `T1087.004`, `T1069.003`, `T1619`, `T1201` | 685 |
| Impact | `T1496` Resource Hijacking | 172 |
| Credential Access | `T1552`, `T1552.005` | 124 |
| Persistence | `T1136.003` Create Cloud Account | 2 |
| Privilege Escalation | `T1098` Account Manipulation | 2 |

## The honeypot fleet

| Token | Repository | Placement | Events |
|---|---|---|---:|
| 1 | [social-metrics-vault](https://github.com/aroaxinping/social-metrics-vault) | `.env` | 699 |
| 2 | [homelab-s3-sync](https://github.com/aroaxinping/homelab-s3-sync) | `.env` | — |
| 3 | [cloud-usage-tracker](https://github.com/aroaxinping/cloud-usage-tracker) | `config.ini` | 115 |
| 4 | [sensor-data-lake](https://github.com/aroaxinping/sensor-data-lake) | `settings.yaml` | 22 |
| 5 | [infra-heartbeat](https://github.com/aroaxinping/infra-heartbeat) | `terraform.tfvars` | 465 |

Each token is unique, so every alert is attributable to a specific repo and placement. Those repositories are intentionally thin instruments of the experiment; this repository is where their data is collected and analyzed.

## Why a leaked key is a target

An AWS access key is a payment method wired to an infinite supermarket of compute. Anyone holding it can order Amazon services as the victim's account — the bill lands on the victim.

| AWS service | What it rents | How it's monetised | Example events |
|---|---|---|---|
| **Bedrock** | AI models | Free/resold AI on the victim's bill (**LLMjacking**) | `InvokeModel`, `Converse` |
| **SES** | Email delivery | Phishing with Amazon's inbox reputation | `GetSendQuota` |
| **S3** | Storage | Steal and sell the victim's data | `ListBuckets` |
| **IAM** | Users & permissions | Create a backdoor that survives key revocation | `CreateUser`, `PutUserPolicy` |

See [`docs/how_a_stolen_key_is_monetised.md`](docs/how_a_stolen_key_is_monetised.md) for the full walkthrough.

## Pipeline

The dataset is kept current end to end — from inbox to analysis-ready CSV — in one command:

```
uv run --extra gmail python scripts/fetch_gmail.py   # pull + parse + dedup new alerts
uv run python scripts/build_dataset.py               # enrich + classify -> data/processed/
```

1. **Ingest** — Gmail API (read-only) pulls canarytoken alert emails, parses each into a structured event (IP, AWS action, timestamp, token/placement), and merges into the raw dataset. Idempotent and de-duplicated.
2. **Enrich** — for every source IP: geolocation, ASN, infrastructure type, proxy/hosting/mobile flags (ip-api), GreyNoise mass-scanning signal.
3. **Classify** — each AWS API call mapped to an attacker-intent phase and MITRE ATT&CK technique.

**Automated:** a macOS launchd job runs the full pipeline every 6 hours ([`docs/SCHEDULER_SETUP.md`](docs/SCHEDULER_SETUP.md)).

### OSINT tiers

- **Base tier** (in-pipeline): geo, ASN/org, infra type, ip-api flags, GreyNoise → [`ip_intel.csv`](data/processed/ip_intel.csv)
- **Deep tier** ([`enrich_deep.py`](src/canary_token_analytics/enrich_deep.py)): Shodan InternetDB (ports, tags, CVEs), whois, reverse DNS → [`ip_intel_deep.csv`](data/processed/ip_intel_deep.csv). All lookups query third-party databases about the IP; nothing connects to attacker infrastructure.

## Experiment: does placement matter? (A/B)

The fleet finding — that infrastructure-flavored keys draw faster, deeper attacks — is suggestive but confounded. To settle it, [`experiment/`](experiment/) specifies a **randomized, matched-block field experiment**: 50 repos, 10 blocks × 5 conditions, with placement assigned at random within each block and launched in two waves. See [`experiment/DESIGN.md`](experiment/DESIGN.md).

## Repository structure

```
canary-token-analytics/
├── src/canary_token_analytics/
│   ├── ingest.py        # parse alert emails -> structured events
│   ├── enrich.py        # geo / ASN / infra type / proxy flags / GreyNoise
│   ├── enrich_deep.py   # Shodan InternetDB + whois + reverse DNS
│   ├── taxonomy.py      # AWS API call -> attacker-intent phase
│   ├── mitre.py         # event -> MITRE ATT&CK tactic + technique
│   └── pipeline.py      # orchestrates raw -> enriched CSVs
├── data/
│   ├── raw/             # source captures
│   └── processed/       # enriched, analysis-ready CSVs
├── experiment/          # randomized A/B placement experiment
├── app/                 # Streamlit dashboard
├── scripts/             # fetch_gmail, build_dataset, build_deep_osint
├── deploy/              # launchd plist for scheduled ingestion
├── notebooks/           # exploratory analysis and visualization
├── docs/                # methodology, MITRE mapping, OSINT, monetisation primer
└── tests/               # 111 unit + data-quality tests
```

## Scope & limitations

- **Descriptive, not predictive.** This is threat-intelligence case analysis, not statistical modelling.
- **No attribution of people.** Enrichment identifies infrastructure (IPs, ASNs, geography), not humans. Attribution stops at infrastructure.
- **Passive OSINT only.** Every technique reads publicly exposed information or queries third-party databases. No authentication was attempted, no credential was ever submitted to a target.

See [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) for the full methodology, confidence grading, and ethics statement.

## How to run

```bash
uv sync
uv run python scripts/build_dataset.py          # rebuild from raw events (no Gmail needed)
uv run --extra gmail python scripts/fetch_gmail.py  # pull fresh alerts (requires OAuth setup)
uv run --extra dashboard streamlit run app/dashboard.py  # launch the dashboard
```
