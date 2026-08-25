# Methodology

This document records how the data in this project was collected, enriched, and
classified, so the analysis is transparent and reproducible. It follows common
threat-intelligence documentation practice: every derived field names its source
and tool, findings carry a confidence level, and the collection date is recorded
because infrastructure intelligence is time-sensitive.

- **Alert data collection window:** 2026-08-03 → 2026-08-27 (16 events)
- **OSINT enrichment run:** 2026-08-27
- **Analyst posture:** passive OSINT only (see [Ethics & legal](#ethics--legal))

---

## 1. Data provenance

The primary dataset was self-generated, not downloaded.

1. **Bait.** An AWS *canary token* (a credential that grants no access but emails
   an alert whenever anyone attempts to use it) was generated with
   [canarytokens.org](https://canarytokens.org) and placed in the `.env` file of a
   public GitHub repository.
2. **Capture.** Each attempted use produced an alert email. Alerts are pulled
   from Gmail over the Gmail API (read-only scope) by
   [`scripts/fetch_gmail.py`](../scripts/fetch_gmail.py), parsed and
   de-duplicated by the unit-tested
   [`ingest`](../src/canary_token_analytics/ingest.py) module, and normalised
   into `data/raw/canary_alerts_raw.csv` with the fields as received: timestamp
   (UTC), source IP, AWS API call (`event_name`), and the raw boto3
   `User-Agent` string. Ingestion is idempotent — re-running only appends
   genuinely new events — so it can run unattended; a launchd job fetches and
   rebuilds every 6 hours (see
   [`INGESTION_SETUP.md`](INGESTION_SETUP.md) and
   [`SCHEDULER_SETUP.md`](SCHEDULER_SETUP.md)). The first month's 16 alerts were
   ingested this same way from the single original token.
3. **Scrubbing.** The canary token's ID and management/auth URL are secrets (they
   grant control of the token). They were removed and never committed to this
   repository.

The raw CSV is the single source of truth. No row was ever added, removed, or
altered during enrichment; all downstream files derive from it deterministically.

---

## 2. Tools & sources

All investigation tooling is either open-source command-line software or a free,
no-authentication API tier. No credentials were ever submitted to a target.

| Tool / source | Type | Used for |
|---|---|---|
| `whois` | open-source CLI | IP ownership, ASN, netname, allocation, abuse contact |
| `dig` (reverse DNS) | open-source CLI | PTR records / hostnames |
| `curl` | open-source CLI | HTTP(S) response headers; direct server probing |
| `openssl s_client` / `x509` | open-source CLI | TLS certificate subject/issuer and chain validation |
| `nc` (netcat) | open-source CLI | reading service banners (e.g. SSH version) |
| [ipinfo.io](https://ipinfo.io) | free API (no key) | geolocation, ASN, organisation |
| [Shodan InternetDB](https://internetdb.shodan.io) | free API (no key) | open ports, detected products/OS, tags, known CVEs |
| [GreyNoise Community](https://viz.greynoise.io) | free API (no key) | whether an IP is observed mass-scanning the internet |

**Not used, and why.** Dedicated OSINT *frameworks* (SpiderFoot, theHarvester,
Amass, Recon-ng) were not used. Those target people/domain/email footprinting; for
*IP-infrastructure* intelligence the appropriate primitives are WHOIS, reverse DNS,
port/service discovery, and TLS inspection — which is what was applied. SpiderFoot
would be a reasonable way to *automate* and broaden this process at scale and is
noted as a future improvement in [`NEXT_STEPS.md`](NEXT_STEPS.md). AbuseIPDB was
skipped because its lookup requires an API key.

---

## 3. Enrichment methodology (per field)

Enrichment runs in **two tiers**. The **base tier** runs inside the main
pipeline (`scripts/build_dataset.py`): geolocation, ASN/org, infra type,
ip-api proxy/hosting/mobile flags, GreyNoise, user-agent parsing, and intent
classification, written to `ip_intel.csv` and `alerts_enriched.csv`. A separate
**deep tier** ([`enrich_deep.py`](../src/canary_token_analytics/enrich_deep.py)
via `scripts/build_deep_osint.py`) adds a passive per-IP dossier — Shodan
InternetDB (open ports, tags, CVEs), `whois` (netblock, org, country, abuse
contact), and reverse DNS — cached and rate-throttled, written to
`ip_intel_deep.csv`. Every deep lookup queries a third-party database *about*
the IP; nothing ever connects to attacker infrastructure (see
[`osint_deep.md`](osint_deep.md) and §8).


| Derived field(s) | Source / tool | Confidence |
|---|---|---|
| `city`, `region`, `country`, `asn`, `org` | ipinfo.io (WHOIS as backup) | High |
| `infra_type` (datacenter / cloud / residential-mobile / ISP) | ASN + organisation heuristic, verified against reverse DNS and Shodan | High for named carriers/clouds; Medium where inferred |
| `reverse_dns` | `dig -x` | High |
| `open_ports`, `products_os`, `shodan_tags`, `vulns` | Shodan InternetDB | High where present; **absent** for CGNAT/mobile IPs (expected — not a failure) |
| `tls_subject`, `tls_issuer`, `tls_validates`, `camouflage_detected` | `curl` + `openssl` direct probe | High |
| `ua_os`, `ua_python`, `ua_boto3`, `ua_retry_mode`, `tool_signature` | string parsing of the boto3 `User-Agent` | High (verbatim from the request) |
| `gn_*` (GreyNoise signal) | GreyNoise Community API | High where returned; **unknown** where rate-limited |
| `intent_phase`, `intent_description` | fixed taxonomy (see §4) | High |
| `aws_service` | AWS API-to-service mapping (see `aws_service_map.csv`) | Mostly High; two flagged (§5) |

Live lookups were run once and the returned values recorded as-is. Where a lookup
returned nothing, the field is `unknown` — never a guessed value.

---

## 4. Intent classification

Each observed AWS API call was mapped to an attacker-lifecycle phase using a fixed,
documented taxonomy (`src/canary_token_analytics/taxonomy.py`), not ad-hoc
judgement:

| Phase | Meaning | Example calls |
|---|---|---|
| `validation` | confirm the key is live and whose it is | `GetCallerIdentity` |
| `reconnaissance` | enumerate identity, permissions, roles, regions, limits | `GetUser`, `ListRoles`, `ListAttachedUserPolicies`, `GetRegions`, `GetAccount`, `DescribeSeverityLevels`, `GetServiceQuota` |
| `abuse-prep` | check a resource before abusing it | `GetSendQuota` (SES) |
| `persistence` | retain access beyond the leaked key | `CreateUser` |
| `resource-abuse` | consume paid resources on the victim | `InvokeModel` (Bedrock / "LLMjacking") |
| `defense` | AWS's own detection/quarantine, not an attacker | `AttachUserPolicy` (AWS Internal), `SNS`, `AWSFRAUDGITHUBKEYCLUTCHPROD` |

The full API-to-service mapping, with what each call does and the attacker
rationale, is in [`aws_services_reference.md`](aws_services_reference.md) and
`data/processed/aws_service_map.csv`.

---

## 5. Confidence & flagged uncertainties

Findings are graded High / Medium / Low. In the spirit of source-reliability
grading used in professional intelligence work, uncertainty is surfaced explicitly
rather than smoothed over. Open items:

- **`GetRegions` → Medium.** Best fit is `account:GetRegions` (AWS Account
  Management). Flagged because region enumeration is also commonly EC2
  `DescribeRegions`; would need raw CloudTrail `eventSource` to settle.
- **`GetAccount` → Low.** No AWS service exposes a literal `GetAccount`. Likely a
  truncated/normalised label for `iam:GetAccountSummary`,
  `iam:GetAccountAuthorizationDetails`, or `account:GetAccountInformation`.
- **`182.4.101.162` classification.** ipinfo returned AS23693 *PT. Telekomunikasi
  Selular (Telkomsel)*, a mobile carrier, so it is classified `residential/mobile`.
  An earlier expectation had labelled it `residential/ISP`; the live lookup won and
  the disagreement is recorded rather than hidden.
- **GreyNoise gaps.** The free tier rate-limited after 5 lookups; four IPs
  (`99.63.197.17`, `172.58.243.229`, `182.4.101.162`, `202.179.188.22`) are
  `unknown` for GreyNoise, not "clean".

---

## 6. Reproducibility

The enrichment pipeline is deterministic and re-runnable:

```bash
uv sync
uv run python scripts/build_dataset.py
```

The per-IP OSINT primitives can be reproduced directly, e.g.:

```bash
whois <ip>
dig -x <ip> +short
curl -s  https://ipinfo.io/<ip>/json
curl -s  https://internetdb.shodan.io/<ip>
curl -s  https://api.greynoise.io/v3/community/<ip>
curl -k -sI https://<ip>                 # camouflage / redirect check
echo | openssl s_client -connect <ip>:443 2>/dev/null | openssl x509 -noout -subject -issuer
```

Because IP intelligence changes over time, re-running these later may yield
different results; the values in this repo reflect the **2026-08-27** collection
date recorded above.

---

## 7. Limitations

- **Small sample.** 16 events from a single token over ~24 days. This is a
  descriptive threat-intelligence case study, **not** a statistical or ML result.
  Growing the dataset (a fleet of tokens, longer window) is the precondition for
  any modelling — see [`NEXT_STEPS.md`](NEXT_STEPS.md).
- **Coverage gaps.** Shodan has no data for carrier-grade-NAT / mobile IPs (normal);
  GreyNoise coverage was partial due to rate limits.
- **Label normalisation.** `event_name` values are as surfaced by the alerting
  layer and, for two calls, do not map cleanly to a single public API (§5).

---

## 8. Ethics & legal

- **Passive only.** Every technique reads information a host already exposes
  publicly or queries a third-party database. No authentication was attempted, no
  credential was ever submitted to a target, and nothing intrusive (exploitation,
  brute force, port abuse) was performed.
- **Attribution stops at infrastructure.** The analysis identifies *where* traffic
  originated (hosting provider, cloud, mobile carrier, camouflaged proxy) — never
  *who*. Identifying the individuals behind an IP would require the provider's
  private records and a legal process, which is out of scope.
- **Secret hygiene.** The live token's secret and management URL are never stored
  in this repository.

---

## 9. Frameworks referenced

- **MITRE ATT&CK** — the standard vocabulary for attacker tactics/techniques; the
  intent taxonomy in §4 is a lightweight step toward a formal ATT&CK-for-Cloud
  mapping (a planned improvement).
- **Admiralty / source-reliability grading** — the practice, adopted informally
  here, of grading each finding's confidence and stating uncertainty explicitly.
- **Traffic Light Protocol (TLP)** — the standard for marking how sensitive
  intelligence may be shared, relevant if this analysis is ever distributed.
