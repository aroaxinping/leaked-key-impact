# NEXT_STEPS — evolving canary-token-analytics into a standout portfolio piece

A critical, expert review of what is actually in this repo today and a prioritized
roadmap for where to take it. Written for the owner as a working plan, not a brochure.

---

## 1. Honest assessment

### What is genuinely strong

- **The data is original and self-generated.** This is the single most valuable
  thing here. Anyone can download a Kaggle threat-intel CSV; almost nobody in a
  junior portfolio *plants their own tripwire and harvests live attacker
  behavior*. That provenance is the whole story — lead with it everywhere.
- **The LLMjacking (`InvokeModel` / Bedrock) angle is current and rare.** Stolen
  cloud creds being burned on model inference is a 2024–2026 monetization
  pattern. Having a real `InvokeModel` attempt (seq 12) in first-party data is a
  legitimately interesting artifact, not a toy.
- **The intent taxonomy is clean and defensible.** `taxonomy.py` is a small,
  readable, honest mapping (validation → reconnaissance → abuse-prep →
  persistence → resource-abuse, plus a `defense` class for AWS's own actions).
  The `CreateUser` persistence attempt (seq 10) and the SES `GetSendQuota`
  abuse-prep call (seq 5) show the taxonomy actually earns its keep.
- **Intellectual honesty is the standout trait.** The code never invents a value
  (`None` on lookup failure), the DATA_DICTIONARY flags a real disagreement
  between the expectation table and the live Telkomsel lookup, and both the
  README and notebook cell 21 state the n=16 limitation plainly. Reviewers trust
  work like this. Do not lose that voice as the project grows.
- **The enrichment/UA parsing is real signal.** Parsing `iam_masscek/2.0` and
  `DeepAWSAnalyzer/Pro` tool signatures out of the boto3 UA, and reconstructing
  the Aug 25 residential-proxy burst (3 IPs in one metro-hopping cluster inside
  ~36 min), is proper threat-intel tradecraft.

### Real limitations (name these before a reviewer does)

- **n=16 is descriptive, full stop.** 16 events, 13 attacker requests, 9 unique
  IPs. Every "chart" is really a labeled anecdote. There is no statistical claim
  the data can support, and the notebook is right to refuse to make one.
- **Single token, single repo, single placement channel.** One AWS-key canary in
  one public GitHub repo. You are observing the behavior of *one* leak vector,
  not "leaked credentials" as a class. The "escalation over the month" narrative
  (VPS → cloud → residential) is a plausible read of 9 dots — it is equally
  consistent with unrelated bots hitting the same GitHub-scraped key.
- **Short, ragged window.** ~24 days (Aug 3 → Aug 27), not the "roughly one
  month" rounded up in prose. The first 15 days are essentially empty (AWS
  quarantine on Aug 3, first attacker touch Aug 18).
- **No ground-truth labels.** `infra_type` and `intent_phase` are *your*
  heuristics. There is no external oracle saying IP X really was a proxy or that
  call Y really was persistence-motivated. Fine for descriptive work; fatal for
  any supervised ML until labels exist.
- **The "17 minutes" headline is metadata, not data.** The notebook is honest
  that the 17-min quarantine figure comes from experiment notes, not from the
  CSV. Keep that caveat visible; it is the most quotable number in the project
  and also the least reproducible from the artifact.
- **Enrichment has no ground-truth and one broken feed.** GreyNoise community
  returned 404 for all 9 IPs — a genuine null result, but it means the only
  reputation feed currently wired in contributes nothing.
- **`tests/` is advertised but does not exist**, and `pytest` is declared in
  `[dev]` with zero tests. The README's repo tree lists `tests/`. This is the
  one place the project currently overstates itself — cheap to fix (see §3).

**Bottom line:** this is an excellent *case study* and a weak *dataset*. The
roadmap below is about turning the case study into a data platform that can, in
time, back real statistics — without ever pretending it already does.

---

## 2. Grow the dataset — deploy a canary fleet

The one change that unlocks everything else. A single token can only ever be a
story; a *fleet* accumulating for months can become a dataset. The goal: go from
n=16 over 24 days to n in the thousands over 6–12 months, across multiple leak
vectors, with enough volume that the descriptive charts become distributions.

### Diversify on two axes

1. **Multiple placements (same token type).** The same class of AWS-key canary
   seeded across many public surfaces: 10–20 GitHub repos with varied
   realism (a fake `.env`, a Terraform `variables.tf`, a committed `~/.aws/credentials`,
   a Dockerfile `ENV`, a CI YAML), plus Gists, pastebin, npm/PyPI package
   metadata, a public S3 bucket, a Postman collection. This isolates the
   *placement* variable: which leak surfaces get scraped fastest.
2. **Multiple token types (Thinkst Canarytokens covers most for free).**
   - AWS API key (current) — cloud-cred abuse, LLMjacking, IAM persistence.
   - Fake `.env` with a **database URL** (Postgres/Mongo connection string) —
     catches DB-scanning bots.
   - **Slack / Discord webhook** token — catches webhook-abuse and spam bots.
   - Fake **Stripe / API bearer** token, **Azure / GCP** service-account JSON.
   - A **canarytoken'd document / URL** (unique tracking link) for lower-effort
     signal and time-to-first-touch on non-credential bait.

   Each type answers a different question and each has its own alert channel, so
   the ingestion layer must be multi-source from day one.

### Collection architecture (design for the fleet now, even at small scale)

```
                       ┌────────────── generation/registry ──────────────┐
                       │  tokens.yaml: {token_id, type, secret_ref,       │
                       │  placement_url, repo, seeded_at, channel}        │
                       └───────────────────────────────────────────────── ┘
                                            │  (secrets NEVER in repo — see §6/§8)
        placement                           ▼
  GitHub repos / gists ─┐          ┌──────────────────────────┐
  pastebin / npm / S3 ──┼─trip──►  │  alert channels          │
  Canarytokens bait ────┘          │  - Gmail (AWS/SES alerts)│
                                   │  - Canarytokens webhook  │
                                   │  - Slack/webhook echoes  │
                                   └────────────┬─────────────┘
                                                ▼
                         ┌──────── ingestion (§3) ───────┐
                         │ Gmail API poller  +  webhook   │
                         │ receiver  → normalized raw     │
                         │ event {token_id, ts, src_ip,   │
                         │ action, ua, channel}           │
                         └───────────────┬────────────────┘
                                         ▼
                            parse → enrich → classify (existing src/)
                                         ▼
                              store (DuckDB/Parquet, §3)
                                         ▼
                          notebook / dashboard / stats (§4/§5/§6)
```

The current `src/canary_token_analytics` package is already the middle of this
diagram. The work is bolting **multi-source ingestion** onto the front and a
**store** onto the back, then letting time do the rest.

**Add one column now that costs nothing and pays off later:** a `token_id` (and
`placement`/`channel`) on every event. The moment there is more than one token,
every analysis wants to group by it, and retrofitting it into historical rows is
painful. Add it to `RAW_COLUMNS` and the raw CSV even while there is only one
token.

---

## 3. Engineering upgrades — the "data engineering" layer

Frame this section, in the README, explicitly as the data-engineering half of
the project. It is what turns "I made a notebook" into "I built a pipeline."

### Quick wins (days)

- **Write the tests the README already promises.** `taxonomy.classify_intent`
  (known event → phase, unknown → `_UNKNOWN`), `parse_boto3_user_agent` (the
  tricky `m/D,Z,b,e` comma case, tool-signature extraction, empty UA),
  `classify_infra_type` (each rule + the Telkomsel "mobile beats ISP" ordering),
  and `_read_raw` (the split-from-both-ends parser on a UA containing commas).
  These are pure functions — trivial to test and they make the pipeline
  trustworthy. Also fixes the current README overstatement.
- **Data-quality checks as code, not asserts in a notebook.** Move the notebook's
  `assert len == 16` / `nunique == 9` spirit into a real validation step: every
  row has a valid ISO timestamp; `alert_type` in a known set; `intent_phase` in
  the taxonomy's range; `source_ip` parses or is a known non-attacker sentinel;
  no future timestamps. A tiny [Pandera](https://pandera.readthedocs.io) schema
  or a handful of functions is enough. Fail the build on violation.
- **Config over constants.** `IPINFO_URL`, timeouts, the `_INFRA_RULES` keyword
  tables, and `_KNOWN_TOOLS` should live in a config/YAML so adding a new tool
  fingerprint or ASN keyword is a data edit, not a code edit.

### Bigger bets (weeks)

- **Automate ingestion.** Two ingestors feeding one normalized raw event:
  - **Gmail API poller** (for AWS/SES email alerts): OAuth once, poll a label,
    parse new messages, dedupe by Gmail message-id. This replaces the manual
    email→CSV step that clearly produced `canary_alerts_raw.csv` today.
  - **Canarytokens webhook receiver** (for the fleet's non-email tokens): a
    small FastAPI/Flask endpoint (or a serverless function) that accepts
    Thinkst/webhook JSON and writes the same normalized event.
  Both should be **idempotent** — keyed on a stable event id — so re-running
  never double-counts.
- **Incremental, not rebuild-from-scratch.** Today `build_dataset.py` re-does
  live lookups for every IP on every run. Split into: (a) append-only raw event
  log, (b) an **IP-intel cache** (look each IP up once, ever — persist it), and
  (c) a derived-table build that is pure/deterministic given raw + cache. This
  makes runs cheap, reproducible offline, and kind to the ipinfo rate limit.
- **A real store.** Graduate from CSV to **DuckDB** (or Parquet + DuckDB views).
  Rationale: one file, zero server, SQL over the event log, trivial to query
  from the notebook and a dashboard, and it scales to the fleet's volume without
  a rewrite. Keep exporting the analysis-ready CSV as a published artifact for
  portability. SQLite is a fine alternative; Parquet if you want columnar files
  per token/month.
- **Scheduling.** A daily cron / GitHub Action / systemd timer that runs the
  ingest→enrich→store cycle and refreshes the dashboard. Now the project is
  *live* — a reviewer can watch the event count climb.

---

## 4. Analytics / threat-intel upgrades

These raise the ceiling on the *analysis* without needing ML, and most work at
current scale.

- **Formalize intent against MITRE ATT&CK.** Right now the taxonomy is bespoke
  ("authoritative for the project"). Keep it, but add a second column mapping
  each event to ATT&CK **tactics/techniques** for cloud, e.g.:
  - `GetCallerIdentity` → T1078 (Valid Accounts) validation / T1580 (Cloud
    Infrastructure Discovery adjacent)
  - `ListRoles`/`ListAttachedUserPolicies`/`GetAccount` → **T1069.003** (Permission
    Groups Discovery: Cloud) / **T1087.004** (Account Discovery: Cloud)
  - `CreateUser` → **T1136.003** (Create Account: Cloud Account) — persistence
  - `GetSendQuota` → precursor to **T1114** / phishing-from-account
  - `InvokeModel` → resource hijacking, **T1496** (Resource Hijacking) framing
  Speaking ATT&CK instantly makes the writeup legible to security reviewers and
  lets you cross-reference other public research. This is a high-value quick win.
- **Add more enrichment feeds (and record which feed said what):**
  - **AbuseIPDB** (free tier) — abuse confidence score per IP. Directly fills the
    reputation gap GreyNoise left empty.
  - **IPQualityScore / ipinfo Privacy** — proxy/VPN/Tor/hosting flags. This would
    let you *confirm* the "residential proxy" reading of the Aug 25 burst instead
    of inferring it from ASN keywords.
  - **Shodan** — what else is exposed on that IP (open ports, banners), hinting
    compromised-host vs. rented-proxy.
  - **GreyNoise paid** later if the free tier keeps returning nulls.
  Keep the current honesty rule: store the raw feed answer, never overwrite one
  feed with another, leave gaps as null.
- **Coordinated-campaign detection.** With the fleet's volume, cluster events by
  (time window × ASN/subnet × tool_signature × UA fingerprint) to surface
  campaigns like the Aug 25 residential burst automatically. Even now, a simple
  "same `/16` or same `iam_masscek/2.0` signature within N minutes" rule
  reconstructs that cluster mechanically instead of by eye.
- **User-agent / tool fingerprint clustering.** You already parse os/python/
  boto3/retry-mode/tool. Treat that tuple as a fingerprint and group requests by
  it — "how many distinct toolchains touched the fleet" is a real metric that
  grows more meaningful with volume.
- **Temporal patterns.** Hour-of-day / day-of-week arrival once there is volume;
  **time-to-first-touch per placement** (how fast each leak surface gets
  scraped) is the headline metric the fleet is built to produce.

---

## 5. When it becomes real Data Science (a LATER phase — be explicit)

State plainly, in the README, that ML is a *future* phase gated on data volume,
and that shipping ML on n=16 would be the exact overclaiming the project
currently avoids. Only after the fleet has produced enough labeled, varied
volume (order hundreds–thousands of events across many tokens) do these become
honest:

- **Classification.** Predict `infra_type` or `intent_phase` from UA + behavioral
  features. Only worth doing once (a) there are enough examples per class and
  (b) you have a labeling story better than "the same heuristic that generated
  the target." Otherwise the model just relearns your rules.
- **Anomaly / campaign detection.** Unsupervised clustering (DBSCAN on
  IP/time/UA features) to flag coordinated bursts — a natural fit because it
  needs no labels.
- **Survival analysis on time-to-first-touch.** Kaplan–Meier / Cox across
  placement types: "does a committed `.env` get scraped faster than a Gist?"
  This is the statistically respectable payoff of the fleet design and the most
  novel possible result. Needs many placements with recorded `seeded_at`.

Guardrail to write down: **do not fit a model until the class counts justify a
train/test split.** The credibility of this project is its refusal to overclaim;
premature ML would spend that credibility.

---

## 6. A public-facing dashboard (Streamlit)

- A **Streamlit** (or lightweight FastAPI + a chart lib) app reading the DuckDB
  store: live event count, world map of source IPs, phase kill-chain, infra-type
  breakdown, tool-signature table, and a "time since last hit" ticker. This is
  the shareable front door for the portfolio — far more compelling than a static
  notebook, and it makes the "it's live and still collecting" point viscerally.
- Deploy on Streamlit Community Cloud / a small VPS / a container. The daily
  scheduler (§3) refreshes it.
- **Keep the sensitive bits out.** The dashboard reads only derived, sanitized
  tables — never the live token secret or its Canarytokens management URL. The
  store it reads should already be scrubbed of secrets at ingestion (§8). Publish
  aggregate/enriched data only; if you ever show raw source IPs publicly,
  consider that these are very likely proxies/compromised hosts, not operators —
  keep the §8 attribution caveat on the page itself.

---

## 7. Comparisons & credibility

Situate the writeup against the public research it echoes so it reads as
"informed replication with first-party data," not a lone claim:

- **Thinkst Canarytokens / canarytokens.org** — the tooling and the whole
  honeytoken idea; cite it as prior art and as the fleet's generation layer.
- **"How fast do leaked AWS keys get abused" studies** — there is well-known work
  (git-leak experiments, cloud-provider write-ups) showing scraper-to-abuse
  times of minutes. Your ~17-minute AWS auto-quarantine and the multi-day
  attacker lag are a data point *in that conversation* — frame it as consistent-
  with/diverging-from, with the n=1 caveat.
- **LLMjacking** — reference the public reporting that named the pattern (stolen
  cloud creds used for Bedrock/model inference). Your `InvokeModel` event is a
  wild-caught instance of a documented technique; that framing is credible and
  doesn't overclaim.
- **MITRE ATT&CK for Cloud** (§4) as the shared vocabulary.

Rule for this section: reference to *situate and compare*, never to borrow
authority the data doesn't have. One honest first-party event beats ten cited
statistics you didn't produce.

---

## 8. Risks & ethics (keep these load-bearing, not boilerplate)

- **Attribution stops at infrastructure.** IP/ASN/geo/tool strings identify
  networks, not people, and the residential/mobile/cloud origins are almost
  certainly proxies or compromised hosts. Never name or imply an individual;
  identifying a human would require legal process. The current README/notebook
  language on this is good — carry it verbatim into the dashboard and any post.
- **Never commit the live token secret or its management URL.** This is the
  cardinal rule as the fleet grows. Secrets live outside the repo (a local
  `.env` / secrets manager / the existing `~/.zshrc.local` pattern), the registry
  in the repo stores only a `secret_ref`, and CI has no access to them. Audit
  that `data/raw` and any committed sample never contains a working key. (The
  planted keys are deliberately dead canaries, but treat the *management*
  credentials and any real API keys for enrichment feeds as live secrets.)
- **Everything stays passive OSINT.** Enrichment is lookups against IPs that came
  to you. Do not scan, probe, connect back to, or otherwise touch attacker
  infrastructure — that crosses from observation into action and into legal risk.
- **Don't weaponize the placements.** The bait is inert canaries by design; keep
  it that way. No placement should ever contain a credential that grants real
  access, and nothing you publish should function as a how-to for the abuse
  you're documenting.
- **Feed API keys are secrets too.** AbuseIPDB/Shodan/IPQS keys go in the
  environment, never the repo, and rate-limit/caching (§3) keeps you inside their
  terms.

---

## Priority summary

**Quick wins (do first, days):**
1. Add the `tests/` the README already promises (pure functions in
   `taxonomy.py` / `enrich.py`) + a data-quality validation step.
2. Add `token_id` / `placement` / `channel` columns to the raw schema now, while
   there is still only one token.
3. Add the MITRE ATT&CK mapping alongside the existing intent taxonomy.
4. Wire in AbuseIPDB (and a proxy/VPN flag feed) to fill the empty GreyNoise gap.

**Bigger bets (the real project, weeks–months):**
5. Deploy the **canary fleet** (multiple repos, multiple token types) and let it
   accumulate — this is the change that makes everything downstream possible.
6. Build the ingestion + incremental pipeline + DuckDB store (the data-
   engineering layer), on a scheduler.
7. Ship a Streamlit dashboard reading the store.
8. Only *after* volume arrives: campaign clustering, then survival analysis on
   time-to-first-touch, then (last) any supervised ML.
