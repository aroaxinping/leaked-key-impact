# AWS Service / API Reference — Event Names in the Dataset

Every distinct `event_name` in `alerts_enriched.csv`, mapped to the AWS service behind it, what the call does, and why an attacker with a leaked key would issue it. Confidence is flagged; the two genuinely ambiguous calls are researched and marked, not guessed.

| event_name | AWS service | Confidence | What it does | Attacker rationale |
|---|---|---|---|---|
| GetCallerIdentity | STS (Security Token Service) | high | Returns account ID, user ID, ARN of the calling identity | Confirms the stolen key is live; reveals which account/principal it belongs to — the standard first move |
| ListAttachedUserPolicies | IAM | high | Lists managed policies attached to an IAM user | Gauge the user's privileges before acting |
| GetUser | IAM | high | Returns details about an IAM user | Recon: confirm username / account context of the key |
| CreateUser | IAM | high | Creates a new IAM user | Persistence — an attacker-controlled user that survives revocation of the leaked key |
| ListRoles | IAM | high | Lists IAM roles in the account | Find assumable roles / privilege-escalation paths |
| AttachUserPolicy | IAM | high | Attaches a managed policy to a user | In this dataset: AWS's **own automated quarantine** attaching a restrictive policy (defense). Attacker-issued it would be privilege escalation |
| DescribeSeverityLevels | AWS Support | high | Lists available support-case severity levels | Probes for a paid Support plan (Business/Enterprise) — signals account value / enables support abuse |
| GetSendQuota | SES (Simple Email Service) | high | Returns email sending limits and usage | Abuse prep — check SES capacity before sending spam/phishing from the account |
| GetServiceQuota | Service Quotas | high | Returns the value of a specific quota | Recon on resource limits to plan resource abuse |
| InvokeModel | Bedrock | high | Runs inference against a foundation model | Resource abuse / **LLMjacking** — run paid AI models on the victim's bill |
| Converse | Bedrock | high | Runs a chat-style conversation against a foundation model (the newer chat API) | Resource abuse / **LLMjacking** — chat-API variant of `InvokeModel` |
| ListFoundationModels | Bedrock | high | Lists the foundation models available to the account/region | Abuse prep — enumerate which models can be hijacked before LLMjacking |
| ListBuckets | S3 | high | Lists the account's S3 buckets | Recon — find data stores to read or exfiltrate |
| ListSecrets | Secrets Manager | high | Lists secrets stored in AWS Secrets Manager | Recon — hunt for further stored credentials to escalate with |
| ListUserPolicies | IAM | high | Lists the inline policies embedded in an IAM user | Gauge the user's privileges (inline policies) before acting |
| ListFunctions20150331 | Lambda | high | Lists the account's Lambda functions (`20150331` is the API version date) | Recon — enumerate serverless compute available to abuse |
| SNS | SNS (Simple Notification Service) | medium | Pub/sub messaging; here appears as an AWS-side safetynet signal, not a normal API name | Defense event (AWS fraud/leak flag) — no attacker rationale |
| **GetRegions** | **Account Management (`account:GetRegions`) — PROBABLE** | **medium** | Lists the enabled/available AWS regions for the account | Enumerate reachable regions to find where to launch abuse or evade region-scoped guardrails |
| **GetAccount** | **IAM `GetAccount*` family OR Account Management — AMBIGUOUS** | **low** | No service exposes a plain `GetAccount`; closest real actions below | Account-wide reconnaissance |
| AWSFRAUDGITHUBKEYCLUTCHPROD | AWS-internal fraud/leak detection (not a public API) | high | Internal label meaning the key was found leaked (e.g. on GitHub) | Not attacker-issued — AWS's own detection flagging the exposed key |

## Notes on the two ambiguous mappings

### GetRegions — confidence: MEDIUM (probable Account Management)
There is a documented **`account:GetRegions`** action in the **AWS Account Management** service that returns the list of regions and their opt-in/enabled status for an account. That is the best-supported owner of a call literally named `GetRegions`. It cannot be fully ruled out that the event label is a normalized/truncated form of a region-listing call from another surface (e.g. EC2 `DescribeRegions` is the more common region-enumeration API, but its event name is `DescribeRegions`, not `GetRegions`). Mapping to **Account Management** with medium confidence; flag for analyst confirmation against the raw CloudTrail `eventSource`.

### GetAccount — confidence: LOW (ambiguous)
**No AWS service exposes an action named exactly `GetAccount`.** The realistic candidates are:
- **IAM** — `iam:GetAccountSummary` (account-wide counts of users/roles/policies) or `iam:GetAccountAuthorizationDetails` (full account IAM dump). Either is strong account-wide recon and fits the observed `reconnaissance` intent.
- **AWS Account Management** — `account:GetAccountInformation` / `account:GetContactInformation` (account name, contact details).
`GetAccount` is most likely a **truncated or normalized label** for one of these. Do not treat the service attribution as settled — verify against the raw `eventSource`/`eventName` in CloudTrail before reporting. Marked low confidence.

### AWSFRAUDGITHUBKEYCLUTCHPROD
Not a customer-callable API. It is an **AWS-internal fraud/abuse-detection label** (the `safetynet` alert_type in the data) indicating AWS detected the access key as leaked — the "GITHUBKEY" fragment implies detection of the key exposed in a public GitHub repo. Paired with the `SNS` and `AttachUserPolicy` defense events, this is AWS's automated leak-response pipeline, not attacker activity.
