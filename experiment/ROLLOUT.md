# ROLLOUT — deploying the honeypot fleet

Operator runbook for standing up the 50-repo placement A/B experiment. Read it
top to bottom once before touching anything; it is deliberately honest about the
parts that are fiddly or risky.

**What this experiment is.** 50 thin public GitHub repos (10 matched blocks × 5
conditions) each carry a leaked AWS canary key in a specific file type. The file
type ("placement") is the randomized factor; we measure whether it causally
changes how fast/much attackers hit the key. Design and allocation live in
`DESIGN.md` + `block_assignment.csv`. This document is the operational half:
mint tokens, build repos, push them safely, wire alerts back into the analysis
pipeline.

**Golden rules**

- The honeypot repos live on a **separate, dedicated GitHub account**. The main
  account (where this analysis repo lives) is never used to host a repo with a
  live key.
- The AWS **secret** access key never enters the git tree, the registry, or this
  document. It is passed to the build script out-of-band (env var / prompt) and
  exists only inside `experiment/build/` on the deploy machine, which is
  git-ignored.
- Nothing here is automated end-to-end on purpose. Pushing working credentials
  is a deliberate act; each step below is a human decision.

---

## 0. Prerequisites

- `gh` (GitHub CLI) installed and working.
- Python 3.10+ (the build/validate scripts are stdlib-only; no dependencies).
- The randomized plan already generated: `experiment/block_assignment.csv`
  (`python experiment/plan_blocks.py`).
- The per-condition templates present under `experiment/templates/`.

---

## 1. Prepare the separate deployment account and `gh` auth

Create (or reuse) a dedicated GitHub account for the honeypots — e.g.
`aroa-labs-honeypots`. It should own **only** these throwaway repos.

Keep its `gh` auth strictly separate from the main account. Two clean options:

**Option A — `gh auth switch` (multi-account gh):**

```bash
# one-time: log the dedicated account in alongside the main one
gh auth login --hostname github.com   # authenticate as the DEDICATED account

# list who gh knows about
gh auth status

# before any honeypot operation, switch to the dedicated account:
gh auth switch --user aroa-labs-honeypots
# ... do the honeypot work ...
gh auth switch --user aroaxinping        # switch back when done
```

**Option B — a scoped `GH_TOKEN` env var (no global state to forget):**

Create a fine-grained PAT on the dedicated account with **repo create + contents
+ administration** scope (administration is needed to toggle push protection in
step 4), then run the honeypot commands in a shell where:

```bash
export GH_TOKEN="<dedicated-account-PAT>"   # overrides gh's stored auth
gh api user -q .login                       # MUST print the dedicated account
```

Whichever you pick, **verify the active identity before every push**:

```bash
gh api user -q .login   # expect: aroa-labs-honeypots, never the main account
```

A one-line guard worth pasting before the push loop:

```bash
[ "$(gh api user -q .login)" = "aroa-labs-honeypots" ] || { echo "WRONG ACCOUNT"; return 1; }
```

---

## 2. Mint 50 canary tokens

Each non-control repo needs one **AWS-key canary token**: a fake AWS credential
(a public `AKIA…` access key ID + a secret) that fires an alert email the moment
anyone tries to use it. You need 40 live tokens (10 controls get fake,
non-firing values instead — see step 3).

### The honest state of the tooling

There is **no simple public bulk API** for `canarytokens.org`. The generator is a
single-page app: `POST https://canarytokens.org/generate` from outside the app
returns **405 Method Not Allowed**, and the real request the SPA makes is
CSRF/session-bound and undocumented. So minting 40 tokens is not a clean
`for i in ...; curl` loop. Your realistic options, with trade-offs:

| Option | What it is | Pros | Cons |
|---|---|---|---|
| **(a) Browser-drive the hosted generator** | Fill the canarytokens.org form 40× (manually, or with a browser-automation tool) selecting "AWS keys", set the reminder/memo, capture the key ID + token ID | No infra to run; tokens hosted & maintained by Thinkst; real AWS-key tokens | Tedious; SPA/anti-automation may throttle; each mint is a manual capture into the registry |
| **(b) Self-host `thinkst/canarytokens`** | Run the open-source stack (Docker) and mint via its API | Clean, scriptable API; full control; good for bulk | AWS-key tokens require **real AWS infrastructure** (an AWS account + IAM/CloudTrail wiring) to issue and monitor keys — non-trivial setup |
| **(c) Batch by hand, in sittings** | Same as (a) but explicitly spread across the two waves | Simplest; matches the staggered rollout anyway | Slow |

**Recommendation.** Since we only need 40 live tokens and they are split across
two waves (20 now, 20 later — see step 5), go with **(a): browser-drive the
hosted generator**, minting one wave at a time. It avoids standing up AWS
infrastructure for a short-lived experiment, and the manual pace naturally
staggers the deploy (which we want anyway, per step 4). Reserve **(b)** only if
you later scale far past 50 tokens and the manual capture becomes the bottleneck.

> If you automate the browser, treat it as a real login session on the dedicated
> identity — do not scrape or hammer the endpoint. Capture Instagram/other
> metrics manually rule applies in spirit here too: drive the UI, don't reverse
> the private API.

### Configure each token as you mint it

- **Type:** AWS keys.
- **Alert email / channel:** the **same Gmail the ingester reads**
  (`aroaxinping@gmail.com`) so alerts flow into the existing pipeline (step 6).
- **Memo/reminder:** encode the repo + placement, e.g.
  `honeypot: <repo_name> / <placement> / block <n> wave <w>`. The memo is your
  lifeline if a token ID is ever ambiguous.

### Record every token into `token_registry.csv`

As each token is minted, append its row to `experiment/token_registry.csv`
(schema: `token_registry_schema.md`). Fill `access_key_id`, `canarytoken_id`,
`alert_channel`, `created_utc`; copy `repo_name, block_id, wave, condition,
placement, is_control` straight from `block_assignment.csv`.

**Keep the secret out of the registry.** Store each secret only where the build
step will read it (step 3): an env var per repo, or a prompt at build time.

---

## 3. Control rows (no token, fake key)

The 10 control repos measure baseline scanner noise from a repo of this shape
that can never fire. For each control row in the registry:

- `is_control = True`
- `access_key_id = AKIAEXAMPLEFAKE00000` (an obviously fake, non-live value)
- `canarytoken_id` and `alert_channel` **left empty**
- no secret needed — `build_repos.py` bakes in fixed fake values automatically.

If a control ever produces an alert, a real key leaked into it — stop and audit.

---

## 4. Build the pushable repos

Provide the live secrets out-of-band, then build. The secret env var name is
`CANARY_SECRET__<REPO_NAME>` with the repo name upper-cased and non-alphanumerics
turned into `_` (e.g. `feature-store-sync` → `CANARY_SECRET__FEATURE_STORE_SYNC`).

```bash
# preview first — writes nothing, tolerates missing secrets:
python experiment/scripts/build_repos.py --dry-run

# supply secrets for the wave you are about to deploy (example):
export CANARY_SECRET__FEATURE_STORE_SYNC='...'
export CANARY_SECRET__CHURN_MODEL_SERVICE='...'
# ...or use --prompt-secrets to be asked for each one interactively:

python experiment/scripts/build_repos.py --prompt-secrets
```

`build_repos.py` copies each repo's `templates/<condition>/` into
`experiment/build/<repo_name>/` and substitutes `__CANARY_ACCESS_KEY_ID__` /
`__CANARY_SECRET_ACCESS_KEY__`. It **refuses to run** if a non-control repo has an
empty `access_key_id`/`canarytoken_id`, or (for a real build) no resolvable
secret. Controls get the fake values.

Then validate before touching the network:

```bash
python experiment/scripts/validate_deploy.py
```

This confirms every assigned repo is built, every non-control repo has a real
token identity, no `__CANARY_…__` placeholder survived, a live-looking key
actually landed in each non-control repo, and **no** live key landed in a
control. Do not proceed until it prints `READY to deploy`.

> Ensure `experiment/build/` is git-ignored in this analysis repo — it contains
> live secrets and must never be committed here. (The built dirs are pushed to
> the *dedicated* account as their own repos, not committed into this one.)

---

## 5. The main operational risk: GitHub push protection

**This is the step most likely to go wrong. Read it fully.**

GitHub secret-scanning **push protection** detects AWS keys on push. Publishing a
working key will **block the push** and force a bypass on **every one of the 50
repos**. Doing 50 rapid bypasses from one fresh account is exactly the pattern
that gets an account **flagged or suspended** — which would destroy the
experiment and the account.

Mitigations, in order of importance:

1. **Dedicated account isolation.** Everything runs on the throwaway account
   (step 1). If it gets flagged, the main account and this analysis repo are
   untouched. This is why the separation is non-negotiable.
2. **Spread over the two waves and over time.** Deploy wave 1 (blocks 1–5, 25
   repos) first, then wave 2 (blocks 6–10) days later. Within a wave, stagger
   pushes (minutes apart, not a tight loop). The design *wants* temporal
   replication anyway, so slow is free.
3. **Disable push protection per-repo before pushing**, so the push succeeds
   cleanly instead of needing a scary bypass:

   ```bash
   gh api -X PATCH repos/aroa-labs-honeypots/<repo> \
     -f 'security_and_analysis[secret_scanning_push_protection][status]=disabled'
   ```

   (Requires the `administration` scope from step 1B.) Re-enabling afterward is
   optional and irrelevant to the experiment — the key is already public by
   design.
4. **Do not bypass 50 times by hand.** If a push is ever blocked, prefer (3)
   over clicking through bypass URLs at speed.

Accept that this is intended, sanctioned exposure of *fake* credentials for
security research; the risk being managed here is purely *account health*, not
harm from the keys (they grant nothing).

---

## 6. Create and push each repo, staggered by wave

With the active identity verified (step 1) and a built + validated tree, create
and push one repo at a time. Loop over the rows for the wave you're deploying:

```bash
# safety: confirm the dedicated account is active
[ "$(gh api user -q .login)" = "aroa-labs-honeypots" ] || { echo "WRONG ACCOUNT"; exit 1; }

WAVE=1   # deploy wave 1 now; rerun with WAVE=2 later
OWNER=aroa-labs-honeypots

# iterate assigned repos for this wave (skip CSV header)
tail -n +2 experiment/block_assignment.csv | while IFS=, read -r repo block wave cond placement is_control; do
  [ "$wave" = "$WAVE" ] || continue
  src="experiment/build/$repo"
  [ -d "$src" ] || { echo "SKIP $repo (not built)"; continue; }

  # 1) create the empty repo on the dedicated account
  gh repo create "$OWNER/$repo" --public --description "data/ML utility" || continue

  # 2) turn OFF push protection first (see step 5)
  gh api -X PATCH "repos/$OWNER/$repo" \
    -f 'security_and_analysis[secret_scanning_push_protection][status]=disabled' || true

  # 3) init + push the built tree
  ( cd "$src" \
    && git init -q \
    && git add -A \
    && git -c user.name='aroa-labs' -c user.email='labs@example.invalid' commit -qm "initial commit" \
    && git branch -M main \
    && git remote add origin "https://github.com/$OWNER/$repo.git" \
    && git push -u origin main )

  echo "deployed $repo"
  sleep 90   # stagger; do not hammer
done
```

Tune the loop to taste (add jitter, deploy in small batches), but keep it
**staggered** and keep the account check. Deploy wave 2 by rerunning with
`WAVE=2`, ideally on a different day.

> `git`/`gh` are shown here for the operator to run on the deploy machine. The
> build/validate scripts themselves never call git or the network.

---

## 7. Wire results back into the analysis

1. **Alerts → existing pipeline.** Every token was pointed at the same Gmail the
   ingester reads (step 2), so hits arrive alongside the original fleet's alerts.
   Nothing new to configure if the tokens used that address.
2. **Link the honeypots back to the analysis repo.** Add the 50 repos to the
   fleet reference the analysis reads (the successor to
   `data/raw/fleet_registry.csv`) keyed by `repo_name` / `access_key_id` /
   `canarytoken_id`, so each incoming alert is attributable to its repo,
   placement, block, and wave via `token_registry.csv`.
3. **Attribution.** When an alert email lands, match its token ID against
   `token_registry.csv` → recover `placement`, `block_id`, `wave`. That mapping
   is the join key for analysis.

---

## 8. Analysis (per `DESIGN.md`)

The outcome is **time-to-first-hit** (and hit count) per repo. With placement as
the treatment and block as the stratifier:

- Fit **survival curves** of time-from-deploy to first attacker interaction, one
  per placement condition.
- Compare conditions with a **log-rank test** (stratified by block to honor the
  blocked design), and/or a Cox proportional-hazards model with `placement` as
  the covariate and `block` as strata, `wave` as a check on temporal
  replication.
- Controls anchor the baseline scanning rate a placement effect is measured
  against; they should show no *token* hits (they can't fire) — any alert on a
  control is a data-integrity flag, not a data point.

See `DESIGN.md` for the exact estimands, power assumptions, and stopping rule.

---

## Quick checklist

- [ ] Dedicated account created; `gh` identity verified separate from main.
- [ ] 40 live tokens minted (waved), alert email = the ingester's Gmail.
- [ ] Every token recorded in `token_registry.csv`; secrets kept out of it.
- [ ] 10 control rows set to fake key, empty token/alert.
- [ ] `build_repos.py` run; `validate_deploy.py` prints READY.
- [ ] `experiment/build/` git-ignored in this repo.
- [ ] Push protection handled per-repo; pushes staggered across two waves.
- [ ] Repos linked back to the analysis fleet reference; alerts flowing.
