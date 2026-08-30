# `token_registry.csv` — schema

The **token registry** is the ground-truth link table for the placement A/B
experiment. It is the bridge between the *randomized plan*
(`block_assignment.csv`, produced by `plan_blocks.py`) and the *live credentials*
that get planted in the honeypot repositories at deploy time.

Every row is one honeypot repository. The first six columns are copied verbatim
from `block_assignment.csv` so the registry is self-contained and auditable on its
own; the last four are filled in **during deployment**, as each canary token is
minted and each repo is created. Until a repo is deployed, its credential columns
are left empty.

Two consumers read this file:

- **`scripts/build_repos.py`** — substitutes `access_key_id` /
  `canarytoken_id`'s secret into the credential-bearing file of each built repo.
- **`scripts/validate_deploy.py`** — checks that every non-control repo actually
  carries a real minted token before anyone pushes.

> **Security note.** This file records the **access key ID** (the public
> `AKIA…` half of an AWS key — an identifier, not a secret) and the
> **canarytoken ID**. It must **never** contain the AWS *secret* access key. The
> secret is injected into a built repo at build time from a separate,
> uncommitted source (an environment variable or an operator prompt — see
> `ROLLOUT.md`) and is never persisted here or anywhere in the repo tree.

## Columns

| # | Column | Source | Example | Meaning |
|---|--------|--------|---------|---------|
| 1 | `repo_name` | plan | `feature-store-sync` | Repository name on the dedicated deployment account. Primary key; matches `block_assignment.csv`. |
| 2 | `block_id` | plan | `3` | Matched block (1–10). The 5 repos in a block are created together and differ only in placement. |
| 3 | `wave` | plan | `1` | Launch wave. Blocks 1–5 → wave 1, blocks 6–10 → wave 2. Temporal replication of the placement effect. |
| 4 | `condition` | plan | `terraform_tfvars` | Experimental condition: one of `env`, `config_ini`, `terraform_tfvars`, `ci_deploy`, `control`. Selects `templates/<condition>/`. |
| 5 | `placement` | plan | `terraform.tfvars` | The credential-bearing file inside the repo — the factor under test. Determined by `condition`. |
| 6 | `is_control` | plan | `False` | `True` for the control condition, `False` otherwise. Controls carry an obviously fake key and **no** live canarytoken. |
| 7 | `access_key_id` | deploy | `AKIA…` (live) / `AKIAEXAMPLEFAKE00000` (control) | The AWS access key ID planted in the repo. For non-control rows this is the public half of a **real minted canary token**; for control rows it is a deliberately fake, non-live value. |
| 8 | `canarytoken_id` | deploy | `88nyum1ozkpiczygq3r9yqdut` | The canarytoken's own identifier (from canarytokens.org or a self-hosted instance). Ties any alert email back to this exact repo/placement. **Empty for control rows.** |
| 9 | `alert_channel` | deploy | `aroaxinping@gmail.com` | Where this token's alert fires. Points at the same Gmail the analysis ingester reads, so alerts land in the existing pipeline. **Empty for control rows.** |
| 10 | `created_utc` | deploy | `2026-09-14` | UTC date (ISO 8601) the token was minted / the repo was deployed. Anchors survival-time (time-to-first-hit) analysis. |

## Control rows

Control repositories exist to measure **baseline scanning noise**: how much
attention a repo of this shape attracts from a key that can never fire. Because
of that:

- `is_control` is `True`.
- `access_key_id` is an **obviously fake** placeholder value
  (e.g. `AKIAEXAMPLEFAKE00000`) — never a live AWS key ID. It is only there so
  the file "looks real" to a scanner.
- `canarytoken_id` and `alert_channel` are **empty**. There is no live token, so
  there is nothing to alert.
- A control that ever produces an alert is a bug (a real key leaked into a
  control) and should halt the experiment.

## Row-count invariants

- Exactly **50 rows** (10 blocks × 5 conditions), one per assigned repo.
- Exactly **10 control** rows and **40 non-control** rows.
- Every `repo_name` in `block_assignment.csv` appears exactly once here.
- For every non-control row, `access_key_id` **and** `canarytoken_id` are
  non-empty before deploy — this is the guard `validate_deploy.py` enforces.

## Example (illustrative — not real tokens)

```csv
repo_name,block_id,wave,condition,placement,is_control,access_key_id,canarytoken_id,alert_channel,created_utc
feature-store-sync,1,1,env,.env,False,AKIAEXAMPLELIVE00001,exampletokenid0000000001a,aroaxinping@gmail.com,2026-09-14
churn-model-service,1,1,control,.env,True,AKIAEXAMPLEFAKE00000,,,2026-09-14
etl-warehouse-loader,1,1,terraform_tfvars,terraform.tfvars,False,AKIAEXAMPLELIVE00002,exampletokenid0000000002b,aroaxinping@gmail.com,2026-09-14
```

All `AKIA…` and canarytoken values shown here are fabricated for documentation.
Real values are filled in only on the deployment machine at mint time.
