# How a stolen AWS key is monetised

The natural question when you first see this data is: *how does having an AWS
key let someone use AI for free, or send phishing?* What's the connection?

This doc answers that from the ground up. Once you understand what an AWS key
actually **is**, every event in the dataset explains itself.

## What an AWS key is

**AWS (Amazon Web Services)** rents out Amazon's computers and services over the
internet: servers, storage, databases, email delivery, AI models — anything.
You don't buy hardware; you rent Amazon's, and you **pay per use** — per server-
hour, per email sent, per AI response generated. At the end of the month, one
**bill** lands on the account owner's card.

An **AWS access key** is the credential a program uses to prove *which account*
a request belongs to. It is, literally, a machine username and password:

```
Access Key ID:     AKIA................    ← the "username"
Secret Access Key: ....................    ← the "password"
```

Anyone holding those two strings **can act as that account in AWS** — request
services, and have it all **charged to that account's bill**. No face, no SMS,
no second factor. The key *is* the identity.

> **This is why a leaked AWS key is gold.** Whoever steals it can spend the
> victim's money ordering Amazon services in their name. So the answer to "how
> do you use a key for free AI or phishing?" is: **it isn't free — the victim
> pays.** It's free *to the attacker* because the bill goes to someone else.

A stolen AWS key is best understood as **a credit card wired to an infinite
supermarket of servers and services.** The attacker isn't breaking sophisticated
cryptography — they're *shopping with someone else's card.* Every abuse below is
a different aisle of that supermarket.

---

## 🤖 "Free" AI — LLMjacking

**The service — Bedrock.** AWS Bedrock hands you ready-to-use AI models (Claude,
Llama, and others). You send text, it returns a response, and Amazon charges per
use — cents per thousand words, which adds up fast at scale.

**How the key is used.** The attacker points Bedrock at the stolen key and makes
requests *as the victim's account*:

```python
client = connect_to_bedrock(stolen_key)   # authenticates as the VICTIM
client.invoke_model("...prompt...")        # Amazon bills the VICTIM
```

- **The business:** unlimited AI for their own use, or a reselling operation —
  they stand up a service that resells access to premium models below the
  official price, and the real cost is absorbed by the victims. There are entire
  underground markets for this.
- **Impact on the victim:** thousands of dollars in hours. Documented cases have
  reached tens of thousands.
- **Dataset events:** `InvokeModel`, `Converse` (run a model), preceded by
  `ListFoundationModels` (see which models are reachable first).

---

## 📧 Phishing / spam

**The service — SES (Simple Email Service).** AWS's bulk-email service. You pay
per email sent.

**The connection people miss:** why steal an AWS account to send spam, when
anyone can send spam? **Reputation.** Amazon's mail servers are trusted by the
spam filters at Gmail, Outlook, etc. Mail sent through AWS **reaches the inbox**;
the same mail from a random server **goes straight to the spam folder.**

- **How the key is used:** the attacker runs their phishing campaign through the
  victim's SES → the mail goes out "clean", carrying Amazon's reputation, and the
  **victim pays for the sending.**
- **Dataset event:** `GetSendQuota` is the *setup* — "how many emails can this
  account send?" A high quota means a worthwhile target. It's measuring before
  firing.

---

## 💾 Data theft

**The service — S3.** AWS's file store. Companies keep databases, backups,
documents, and customer records there.

- **How the key is used:** `ListBuckets` lists the account's storage; if the key
  has permission, the attacker **downloads** whatever is there — customer data,
  credentials, intellectual property — to sell or to extort the victim with.
- **Dataset event:** `ListBuckets`.

---

## 🔑 Back door — persistence

**The attacker's problem:** the stolen key can be revoked at any moment (AWS
kills it, or the owner rotates it), and then they lose access.

- **How they solve it:** `CreateUser` creates a **new IAM user they control**,
  with its own fresh key. Even after the original stolen key is revoked, **they
  are still inside** via the user they created. It's hiding a spare key before
  the victim changes the locks.
- **Dataset event:** `CreateUser`.

---

## The whole picture

| AWS service | What it rents | How it's monetised | Dataset events |
|---|---|---|---|
| **Bedrock** | AI models | Free/resold AI — victim pays | `InvokeModel`, `Converse`, `ListFoundationModels` |
| **SES** | Email delivery | Phishing with trusted reputation — victim pays | `GetSendQuota` |
| **S3** | Storage | Steal and sell the victim's data | `ListBuckets` |
| **IAM** | Users & permissions | Create a back door | `CreateUser` |

**The single idea that explains all of it:** an AWS key is a payment method
attached to an infinite supermarket of compute. The attacker doesn't hack
anything clever — they *check out with the victim's card.* "Free for them"
always means the same thing: **the bill lands on the victim.**

## Why this makes the experiment matter

This is the context that makes the dataset worth collecting. It shows, with real
self-generated data, that the moment an AWS key touches a public repository, bots
begin testing it within minutes for exactly these four businesses — AI
hijacking, spam, data theft, and persistence. The
[event cheat sheet](event_cheatsheet.md) maps every observed call to its phase;
this doc explains the *economic motive* underneath those calls.
