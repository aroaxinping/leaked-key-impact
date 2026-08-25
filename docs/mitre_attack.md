# MITRE ATT&CK mapping

Every observed AWS API action mapped to a MITRE ATT&CK (Enterprise/Cloud) tactic
and technique — the industry-standard vocabulary. Derived from the project's
intent taxonomy; see `src/canary_token_analytics/mitre.py`. Counts are over the
**985 attacker events** in the current dataset (AWS-side defensive events excluded).

## Techniques observed, by volume

| Tactic | Technique | ID | Events |
|---|---|---|---:|
| Discovery | Cloud Infrastructure Discovery | `T1580` | 460 |
| Impact | Resource Hijacking | `T1496` | 172 |
| Discovery | Valid Accounts: Cloud Accounts | `T1078.004` | 155 |
| Credential Access | Unsecured Credentials | `T1552` | 96 |
| Discovery | Account Discovery: Cloud Account | `T1087.004` | 34 |
| Credential Access | Unsecured Credentials: Cloud Instance Metadata / Secrets | `T1552.005` | 28 |
| Discovery | Permission Groups Discovery: Cloud Groups | `T1069.003` | 23 |
| Discovery | Cloud Storage Object Discovery | `T1619` | 12 |
| Persistence | Create Account: Cloud Account | `T1136.003` | 2 |
| Privilege Escalation | Account Manipulation | `T1098` | 2 |
| Discovery | Password Policy Discovery | `T1201` | 1 |

## Tactics summary

| Tactic | Events |
|---|---:|
| Discovery | 685 |
| Impact | 172 |
| Credential Access | 124 |
| Persistence | 2 |
| Privilege Escalation | 2 |

## Reading the kill-chain

- **Discovery dominates** — most attacker effort is enumerating the account (identity, permissions, infrastructure, data stores) before acting.
- **Impact = T1496 Resource Hijacking** is the money move: Bedrock LLMjacking (`InvokeModel`/`Converse` and their streaming variants).
- **Credential Access = T1552** — hunting Secrets Manager / SSM / KMS for further credentials to escalate with.
- **Persistence / Privilege Escalation** — `CreateUser` (T1136.003) and `PutUserPolicy` (T1098) attempts to keep or widen access.
- AWS-side quarantine (`AttachUserPolicy` from AWS Internal) is **defensive**, not an ATT&CK technique, and is excluded above.
