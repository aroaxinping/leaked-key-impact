# Experiment: does credential *placement* causally change how attackers hit leaked AWS keys?

A randomized, matched-block field experiment on deliberately-leaked AWS canary
tokens. This document specifies the causal question, the design, the outcomes,
and the statistical plan. The repos it studies live on a **separate, dedicated
GitHub account**; this analysis repository stays on the main account.

> **Safety note.** No real secret is ever committed. Live conditions carry the
> placeholders `__CANARY_ACCESS_KEY_ID__` / `__CANARY_SECRET_ACCESS_KEY__`,
> which are swapped for genuine canary tokens by a downstream, out-of-band step.
> The control condition carries **obviously fake, non-live** placeholder values.

---

## 1. The causal question and the confound it fixes

The observational phase of this project leaked one AWS key per *file placement*
(a key in `.env`, a key in `config.ini`, a key in Terraform vars, a key in a CI
workflow) and watched how fast and how hard each was attacked. The pattern was
suggestive — keys that "look like infrastructure" seemed to draw faster, deeper
attacks — but it is **not identified**.

The problem is a one-repo-per-placement confound. With a single repository per
placement, "placement" is perfectly entangled with *that specific repository*:
its exact leak time, which crawler happened to see it first, and — critically —
**which shared credential-abuse feed the key landed in**. Once a scanner posts a
key to a common feed, a swarm of downstream actors hits it; two keys that reach
different feeds can differ by orders of magnitude for reasons that have nothing
to do with the file they sat in. We cannot tell the effect of the *placement*
apart from the luck of the *feed*.

**Causal estimand.** The effect we want is the average causal effect of
placement on attacker behavior, holding everything else fixed:

> If the *same* project had leaked its key in file *A* versus file *B*, how
> would time-to-first-hit, hit volume, and kill-chain depth differ?

To identify it we need placement to be assigned **at random**, independently of
which repo, which day, and which feed — so that, in expectation, everything
except the credential-bearing file is balanced across conditions. That is what
this experiment does: 50 repositories, placement assigned by a fixed-seed
randomizer, replicated across matched blocks and two time waves.

---

## 2. The factor: an ordered gradient (5 conditions)

The single manipulated factor is **placement**, and its levels are deliberately
arranged as an *ordered* gradient of how infrastructure/production-flavored the
key looks:

| Order | Condition key      | File (placement)                 | Reads as… |
|:-----:|--------------------|----------------------------------|-----------|
| 1     | `env`              | `.env`                           | Generic app secret (baseline) |
| 2     | `config_ini`       | `config.ini`                     | Service / cloud config |
| 3     | `terraform_tfvars` | `terraform.tfvars`               | Infrastructure-as-code |
| 4     | `ci_deploy`        | `.github/workflows/deploy.yml`   | CI/CD deploy credentials |
| 5     | `control`          | `.env` (obviously **fake** key)  | Baseline scanning noise |

The four live conditions (1–4) form a monotone ladder in perceived
"production-ness": a secret in a CI deploy workflow implies a live pipeline and
real blast radius; a generic `.env` could be a toy project. **Why order them?**
Ordering buys statistical power. Instead of testing five unstructured groups, we
can ask a sharper, lower-degree-of-freedom question — *does attacker aggression
increase monotonically along the infra gradient?* — with a **trend test**
(Section 6). A trend that tracks the ordering is also more mechanistically
interesting than a bare "the groups differ": it suggests attackers (or their
tooling) triage on *what the placement signals*, not merely on file name
strings.

The control (5) is described in Section 4.

---

## 3. Matched-block design and why

The 50 repos are organized into **10 matched blocks × 5 conditions**. A block is
a set of five repositories **created together and made as alike as possible** —
same creation day, same generation recipe, comparable repo size, comparable fake
commit history, comparable README and directory scaffolding — differing **only
in the credential-bearing file**. Within each block the five conditions are
assigned at random (fixed seed).

This is a randomized complete block design. Its purpose is **variance
reduction**. Attack intensity on GitHub is enormously noisy across calendar time
and across the idiosyncrasies of individual repos: a key leaked the day a big
scanning campaign runs gets hammered; the same key a week later might sit
untouched. If we compared conditions across *unmatched* repos, that nuisance
variation would inflate our error bars and could bias us if it happened to line
up with condition. Blocking sweeps the shared, block-level nuisance (the day, the
feed climate, the generation batch) **out of the placement contrast**: every
condition appears once inside every block, so within-block comparisons difference
that nuisance away. The result is a more precise, less confounded estimate of the
placement effect for the same 50 repos.

Concretely, the analysis treats **block as a random effect** (Section 6), which
is the model-based expression of the same idea: partition the variance into
between-block and within-block, and read the placement effect off the
within-block part.

---

## 4. The control group

Condition 5 is a **negative control**: a `.env` file whose AWS key is an
*obviously fake, non-live placeholder* (e.g. `AKIAAAAAAAAAAAAAAAAA` /
`0000...EXAMPLE`), not a real canary token. It sits in the same repo scaffolding
as everything else.

The control measures **baseline scanning noise** — the floor of automated
activity that any plausible-looking `.env` attracts regardless of whether the key
is real: indiscriminate crawlers, GitHub secret-scanning, string-matchers that
grep for `AKIA` and log a "hit" without ever validating the key. A real
canary-token "hit" is only meaningful *above* this floor. If a live condition
does not clear the control's noise band, we should not claim attackers acted on
it. The control also validates our instrumentation end to end (does a repo of
this shape even get discovered?) and calibrates our false-positive rate for
"validation attempts vs. blind grep hits."

Because the fake key never authenticates against AWS, the control can register
*discovery/scanning* signals but, by construction, **cannot register
authenticated token activations** — which is exactly what makes it a clean
zero-point for the live conditions.

---

## 5. Temporal replication: two waves

The 10 blocks launch in **two waves of five blocks each**: blocks 1–5 in wave 1,
blocks 6–10 in wave 2, separated by a deliberate gap (e.g. two to three weeks).

Randomized-once-in-time experiments on live adversaries are fragile: the
credential-abuse ecosystem shifts week to week as feeds, campaigns, and tooling
come and go. A single launch could catch an unusual climate and masquerade as a
placement effect. Splitting into two temporally separated waves lets us **check
that the placement effect replicates** across two independent snapshots of the
ecosystem. Wave enters the models as a second random/blocking factor (Section 6);
a placement effect that holds in both waves is far more credible than one seen
once. Staggering also caps operational blast radius per launch and lets wave 1
inform any fixes before wave 2.

---

## 6. Outcome metrics

Each repo is observed from its leak timestamp forward. Primary and secondary
outcomes:

- **Time-to-first-hit** *(primary, survival outcome).* Elapsed time from leak to
  the first attacker interaction with the key. Repos never hit within the
  observation window are **right-censored** — survival methods handle this
  correctly; dropping them would bias results. For live conditions a "hit" is an
  authenticated canary activation; the control's "hits" are scanning/validation
  signals only (Section 4).
- **Hit count** *(count outcome).* Number of distinct attacker interactions over
  a fixed exposure window — total attack *volume*, not just first contact.
- **Proxy-pool-build appearance** *(binary/time-to-event).* Whether, and how
  quickly, the key shows up being exercised through a **rotating proxy pool**
  (e.g. M247 ranges seen in the observational phase) — a fingerprint that the key
  has been absorbed into an industrialized abuse pipeline rather than hit by a
  lone scanner. A strong signal that the credential "graduated" to a shared feed.
- **Kill-chain depth** *(ordinal outcome).* How far the attacker progressed:
  `0` none → `1` key validation only (`sts:GetCallerIdentity`) → `2`
  reconnaissance/enumeration → `3` resource creation / privilege actions /
  attempted persistence. Deeper chains mean the placement provoked *more
  committed* adversaries, not just more of them.

---

## 7. Statistical plan

The unit of analysis is the repository (n = 50), nested in blocks and waves.
Placement is the fixed factor of interest, modeled both as an unordered factor
(five levels, control as reference) and as an ordered score 1→4 over the live
conditions for the trend test.

**Time-to-first-hit.**
- *Descriptive:* **Kaplan–Meier** survival curves per condition, with
  right-censoring for never-hit repos; median time-to-hit and 95% CIs where
  estimable.
- *Ordered inference:* an **ordered / trend log-rank test** (log-rank with linear
  scores across the four live conditions, i.e. the Tarone–Ware / trend variant)
  to test the *a priori* monotone gradient hypothesis with a single degree of
  freedom, rather than an omnibus "curves differ" test.
- *Model:* a **Cox proportional-hazards mixed model** (frailty model) with
  placement as fixed effect and **random intercepts for block and wave**. The
  block frailty is the model-based counterpart of the matched-block design; the
  wave frailty captures temporal replication. Report hazard ratios vs. control
  and vs. `.env`, and a linear-trend hazard ratio per gradient step. Check the
  proportional-hazards assumption (Schoenfeld residuals); fall back to an
  accelerated-failure-time model if it fails.

**Hit count.**
- **Poisson regression**, with placement fixed and block + wave random effects
  (a GLMM), `log(exposure time)` as offset. Attack counts are near-certain to be
  **over-dispersed**, so the primary count model is **negative-binomial** (or a
  Poisson with an observation-level random effect); report the dispersion and
  prefer NB by likelihood-ratio / information criteria. Include the same ordered
  linear contrast for the trend.

**Proxy-pool appearance** — treat as time-to-event (same Cox-frailty machinery)
or, if timing is coarse, as a **mixed-effects logistic** model on the binary
"appeared in a proxy pool" outcome.

**Kill-chain depth** — **ordinal (cumulative-link) mixed model** (proportional
odds) with placement fixed and block + wave random, giving an odds ratio for
reaching a deeper stage per gradient step.

**Control handling.** The control anchors the zero-point. Live-vs-control
contrasts test *"did anything above baseline scanning happen at all?"*; the
ordered trend across the four live conditions tests *"does aggression scale with
infra-flavor?"*. The control is excluded from the ordered trend score (it is a
different construct — fake key) and used only as a reference level and noise
floor.

**Multiplicity.** The gradient trend test on time-to-first-hit is the single
pre-registered primary hypothesis. Everything else (per-condition contrasts,
secondary outcomes) is secondary and reported with Benjamini–Hochberg FDR
control; effect sizes with CIs are emphasized over p-values throughout.

**A note on power.** With 50 repos in 10 blocks this is a **small experiment**,
and we are honest about it. Blocking and the low-df ordered trend test are the
main levers we pull *for* power — matched blocks strip out the biggest noise
source, and a 1-df trend test spends far less power than a 4-df omnibus. Even so,
we are powered to detect **large, monotone** placement effects (roughly a
doubling-scale hazard ratio across the gradient) far better than subtle ones;
small differences between adjacent conditions (e.g. `config.ini` vs.
`terraform.tfvars`) may be underpowered. Time-to-first-hit typically carries more
information per repo than the rarer deep-kill-chain events, so the survival
analyses are our best-powered readouts and the ordinal/proxy analyses are
treated as exploratory. A formal power calculation (simulation-based, over the
frailty Cox model) should be run before launch to set the observation window and
confirm the two-wave split; if it shows we are badly underpowered, the honest
response is to add blocks/waves rather than over-interpret nulls.

---

## 8. Honest limitations

- **Small n.** 50 repos, 10 per condition. Underpowered for subtle or
  non-monotone effects; a null is weak evidence of no effect (see power note).
- **One account, one platform.** All repos live on a single dedicated GitHub
  account. Account-level reputation, or GitHub's own scanning, could apply
  uniformly and does not generalize to GitLab, pastebins, or npm leaks.
- **Non-independence via shared feeds.** Randomization balances feed exposure in
  *expectation*, but if scanners cluster our repos (same account, similar names)
  and dump them into one feed together, outcomes within a wave may be correlated
  beyond what block/wave random effects absorb. The two-wave design mitigates but
  does not eliminate this.
- **Observation/measurement.** "Hit," "kill-chain depth," and "proxy-pool
  appearance" are operational definitions built on our telemetry (CloudTrail,
  IP/proxy fingerprints) and inherit its blind spots; the control calibrates but
  does not fully remove classification error.
- **Construct validity of the gradient.** The 1→4 ordering is our hypothesis
  about how *attackers* read these files. If they in fact triage on cues we did
  not vary (surrounding code, repo stars, README claims), the "placement" effect
  is really an effect of a correlated bundle. Blocks hold scaffolding constant,
  which narrows this, but the manipulated signal is still "file + minimal
  context," not file in isolation.
- **Ethics/ecosystem effect.** We are placing live canary tokens into the abuse
  ecosystem. Tokens are honeypots with no real blast radius, activity is only
  observed, and volumes are tiny — but the design is deliberately low-footprint
  for this reason, and this constrains how large the experiment can grow.
- **Detectability.** A determined adversary who notices 50 near-identical repos
  on one account could behave differently (ignore or poison them). Repo-name
  diversity and blocking-not-cloning reduce, but cannot rule out, this reactivity.

---

## 9. How results feed back into the main analysis

- **De-confounding.** A significant ordered trend (esp. replicated across waves)
  turns the observational "infra-flavored keys get hit harder" correlation into a
  **causal** claim about placement, and quantifies it (hazard ratio per gradient
  step). A null trend tells the main analysis that the observed differences were
  most likely **feed luck**, not placement — a genuinely useful correction.
- **Re-weighting the observational estimates.** The experimental placement
  effect becomes a calibration factor: the observational dataset can be
  re-interpreted with placement's causal contribution partialled out, sharpening
  the other (non-randomized) findings.
- **Baseline subtraction everywhere.** The control's scanning-noise floor
  becomes a reusable baseline the main analysis subtracts before calling any
  observational "hit" an attacker action.
- **Proxy-pool linkage.** Confirming (or not) that placement drives entry into
  the M247-style proxy pipeline connects this experiment to the observational
  proxy-pool findings and tells us whether placement affects *discovery* or
  *escalation* (or both).
- **Design template.** The block/wave machinery and the analysis code become the
  reusable scaffold for the next factor (leak *channel*, repo *reputation*,
  key *permissions*), so the project can move from one-off leaks to a program of
  small, clean causal experiments.
