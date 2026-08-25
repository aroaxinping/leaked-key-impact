# Fleet placement analysis & the proxy-pool finding

On 2026-08-28 the fleet was hit hard all day. The traffic is **not** spread
evenly across the tokens — it piles onto one placement, and unpacking why
reveals a single coordinated actor.

| Placement | Token | Events | Distinct IPs | Countries | hosting/proxy IPs |
|---|---|---:|---:|---:|---:|
| `terraform.tfvars` | 5 | 59 | 55 | many | 49 / 55 |
| `.env` | 1 | 15 | 11 | few | 4 / 11 (6 mobile) |
| `config.ini` | 3 | 8 | 2 | — | 0 / 2 |
| `settings.yaml` | 4 | 6 | 1 | 1 | 0 / 1 |

The obvious reading — *"attackers prefer `terraform.tfvars`"* — is **not
supported by this data** (see the confound below). What the data *does* support
is far more interesting.

## Three behaviourally distinct signatures

**`terraform.tfvars` — a proxy-pool fan-out.** 55 of its 59 events carry an
*identical* software fingerprint: kernel `linux#6.12.43+deb13-amd64`,
`boto3 1.43.80`, `retry-mode legacy` — the same Debian 13 build. Those events
come from **53 different IPs across 23 countries**, each firing roughly once,
spread over ~12 hours, each performing a *different* step of the kill-chain
(`GetCallerIdentity`, `ListFoundationModels`, `InvokeModel`, `ListBuckets`,
`ListSecrets`, `ListUserPolicies`, `GetSendQuota`, `ListUsers`, …).

53 "different" hosts running one very specific kernel build, each taking one
step, is not 53 independent attackers. It is **one operator behind a rotating
proxy pool**, spreading calls across egress IPs to dodge per-IP rate-limiting
and attribution. The OSINT corroborates this at scale:

- **48 of 53** fan-out IPs resolve to hosting/proxy providers (ip-api
  `proxy`/`hosting` flags); **zero** are mobile.
- The ASNs cluster on known commercial VPS/proxy networks — **M247** (a large
  VPN/proxy backbone), **HostRoyale**, **CDNEXT**, **ServerMania**, **SYN-UK**,
  **Leaseweb**, **Cogent** — spread thin (34 ASNs, ~1–6 IPs each), exactly the
  shape of a rented proxy pool.
- Spot checks of individual pool IPs against **GreyNoise** and **Shodan
  InternetDB** return little to nothing — no known-scanner classification, few
  or no open ports. These are **low-footprint ephemeral egress nodes**, not
  persistent internet-wide scanners, which again fits a rotating proxy pool
  rather than a botnet of compromised servers.

**`config.ini` — a hands-on operator attempting privilege escalation.** Two IPs,
worked as a deliberate sequence — and notably, this is the only placement where
someone tried to **change** the account, not just read it:

```
197.57.31.248  GetCallerIdentity → ListRoles          (validate, enumerate)
105.47.246.148 PutUserPolicy                           (privilege escalation!)
               GetCallerIdentity → ListStacks → GetAccount ×3
```

`PutUserPolicy` is an attempt to **attach an inline IAM policy to the user** —
i.e. grant itself durable permissions. It is the most aggressive single action
in the whole dataset, and it came from a hands-on operator, not the pool.

**`settings.yaml` — a single methodical operator.** All six events from **one**
IP (`197.57.31.248`, Telecom Egypt), a sequential checklist.

## The cross-placement link

`197.57.31.248` appears on **two placements** — `settings.yaml` *and*
`config.ini`. The same operator is working more than one leaked key, which is
direct evidence that behind the infrastructure sit actors handling multiple
credentials, not one scanner per key.

## What actually drives the concentration (the confound)

The `terraform.tfvars` concentration is best explained by **propagation, not
file type**: that key landed in a *widely-replayed shared credential feed* which
the proxy pool is now hammering, while the other keys were found by one or two
operators each. The fan-out is the direct evidence of that shared feed.

A tempting secondary hypothesis — that `terraform.tfvars` *itself* attracts more
attention because Infrastructure-as-Code implies real, broadly-permissioned
infra — **cannot be confirmed here**: with one repository per placement,
"placement" is perfectly confounded with "which key reached the shared feed."
Separating the two needs several repositories per file type, randomised — an A/B
design left to [future work](NEXT_STEPS.md).

## The honest takeaway

- **Strong, defensible:** the `terraform.tfvars` traffic is *one* proxy-pool
  actor — 53 IPs, one Debian-13 build, 48/53 hosting/proxy, M247-led ASNs, a
  coordinated LLMjacking-oriented kill-chain. The fingerprint + infrastructure
  evidence converge.
- **Strong, defensible:** the `config.ini` operator attempted **privilege
  escalation** (`PutUserPolicy`), and `197.57.31.248` links two placements —
  actors handle multiple keys.
- **Not established:** a genuine *placement preference*. The apparent
  `terraform.tfvars` bias is confounded with credential-feed propagation and is
  reported as an open question, not a conclusion.
