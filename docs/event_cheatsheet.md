# Event cheat sheet — what each API call means

A plain-language companion to [`aws_services_reference.md`](aws_services_reference.md).
That file is the precise technical reference; this one is the map you read to
*understand the story*: every event grouped by the attack phase it belongs to,
what it actually does, and why someone holding a stolen key bothers to run it.

Think of a stolen AWS key like a found keycard. The attacker doesn't know what
it opens, so they work a checklist: *does it work? → what's inside? → what's
worth stealing? → grab it → keep a way back in.* Each API call is one step of
that checklist.

## The kill-chain, in order

```
1. VALIDATION      "does this key even work, and whose is it?"
2. RECONNAISSANCE  "what's in this account — permissions, data, services?"
3. ABUSE-PREP      "how much of the expensive stuff can I use?"
4. RESOURCE-ABUSE  "use the expensive stuff and bill it to the victim"
5. PERSISTENCE     "leave myself a way back in after they revoke the key"
   ─────────────
   DEFENSE         (not the attacker — AWS's own automated leak response)
```

## 1. Validation — *"is the key live?"*

| Call | Service | What it is | Why they run it |
|---|---|---|---|
| `GetCallerIdentity` | STS | Returns the account ID and identity of whoever is calling | The universal first move: confirms the key works and reveals which account it belongs to. Free, needs no permissions, looks harmless. |

## 2. Reconnaissance — *"what's in here?"*

Looking around. None of these change anything — they *read* the account to plan
the next move.

| Call | Service | What it is | Why they run it |
|---|---|---|---|
| `GetUser` | IAM | Details about the current IAM user | Confirm who the key belongs to |
| `GetAccount*` | IAM (account summary) | Account-wide counts of users/roles/policies | Size up the account at a glance |
| `ListRoles` | IAM | Lists the account's roles | Find assumable roles → privilege-escalation paths |
| `ListUserPolicies` / `ListAttachedUserPolicies` | IAM | Lists the permissions attached to the user | Gauge *how much this key can actually do* before acting |
| `GetRegions` | Account Mgmt | Lists which AWS regions are enabled | Find where to launch abuse / dodge region guardrails |
| `ListBuckets` | S3 | Lists storage buckets | Hunt for data to read or steal |
| `ListSecrets` | Secrets Manager | Lists stored secrets | Hunt for *more* credentials to escalate with |
| `ListFunctions` | Lambda | Lists serverless functions | Enumerate compute available to hijack |
| `GetServiceQuota` | Service Quotas | A specific resource limit | Plan how much they can spin up |
| `DescribeSeverityLevels` | Support | Whether a paid Support plan exists | A Business/Enterprise plan signals a *valuable* account |

## 3. Abuse-prep — *"how much can I use?"*

Measuring the expensive resources before exploiting them.

| Call | Service | What it is | Why they run it |
|---|---|---|---|
| `GetSendQuota` | SES (email) | Your email-sending limit | Check capacity before blasting **spam/phishing** from your trusted AWS reputation |
| `ListFoundationModels` | Bedrock (AI) | Which AI models the account can reach | Enumerate what to hijack before **LLMjacking** |

## 4. Resource-abuse — *"use it, bill the victim"*

The actual money move. This is where a stolen key stops being curiosity and
starts costing the victim real money.

| Call | Service | What it is | Why they run it |
|---|---|---|---|
| `InvokeModel` | Bedrock (AI) | Runs an AI model — prompt in, answer out | **LLMjacking**: run paid AI on your bill, for their own use or to resell |
| `Converse` | Bedrock (AI) | Same, via the newer chat API | LLMjacking, chat-style variant |

> A stolen key is monetised across *different* businesses depending on what the
> account has: **Bedrock → sell/use AI** (`InvokeModel`), **SES → spam**
> (`GetSendQuota`), **S3 → steal data** (`ListBuckets`). The mix in this dataset
> shows opportunistic harvesting: grab the key, probe everything valuable, abuse
> whatever pays.

## 5. Persistence — *"keep a way back in"*

| Call | Service | What it is | Why they run it |
|---|---|---|---|
| `CreateUser` | IAM | Creates a brand-new IAM user | A user *they* control that survives even if the leaked key is revoked — a back door |

## Defense — *not the attacker: AWS itself*

These three are AWS's automated leak-response pipeline, not intrusion attempts.
They're in the data because the token records *everything* that touches the key.

| Call | What it is |
|---|---|
| `AWSFRAUDGITHUBKEYCLUTCHPROD` | AWS-internal flag: the key was found leaked on GitHub |
| `AttachUserPolicy` | AWS auto-quarantine attaching a restrictive policy to the dead key |
| `SNS` | AWS-side fraud/leak notification signal |

## What the distribution says (43 events)

Of the 40 attacker-issued events (the other 3 are AWS's defense):

| Phase | Events | Share |
|---|---:|---:|
| Validation | 11 | 28% |
| Reconnaissance | 15 | 38% |
| Abuse-prep | 7 | 18% |
| Resource-abuse | 6 | 15% |
| Persistence | 1 | 3% |

- **Two-thirds is "look, don't touch"** (validation + recon = 65%). Most actors
  never get past confirming the key and glancing around — because the key is
  already dead, but also because that's genuinely most of what automated
  credential-harvesting bots do.
- **The money moves cluster on Bedrock.** Resource-abuse is almost entirely
  `InvokeModel`/`Converse` — this dataset is disproportionately **LLMjacking**,
  which tracks with 2025-26 threat trends.
- **`GetCallerIdentity` is the single most common call** (11×), exactly as
  expected: it's the free, universal "does this work?" probe everyone runs first.

See [`fleet_placement_analysis.md`](fleet_placement_analysis.md) for how these
events distribute across attacker infrastructure.
