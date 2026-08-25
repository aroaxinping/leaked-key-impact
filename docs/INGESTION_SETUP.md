# Automated ingestion setup (Gmail API)

One-time setup so `scripts/fetch_gmail.py` can pull canarytoken alerts from
Gmail and ingest them automatically. **~30–45 minutes, once.** You do the Google
Cloud clicks; the code is already written.

The alerts already arrive at your Gmail, so **no new email or account is
needed** — this reads from the inbox they land in, read-only.

## What you'll end up with

```
uv run --extra gmail python scripts/fetch_gmail.py   # pulls + ingests new alerts
uv run python scripts/build_dataset.py               # regenerates the analysis
```

## Step 1 — Create a Google Cloud project

1. Go to <https://console.cloud.google.com/>.
2. Top bar → project dropdown → **New Project**. Name it e.g. `canary-ingest`. Create.

## Step 2 — Enable the Gmail API

1. With the project selected: **APIs & Services → Library**.
2. Search **Gmail API** → open it → **Enable**.

## Step 3 — Configure the OAuth consent screen

1. **APIs & Services → OAuth consent screen**.
2. User type: **External** → Create.
3. Fill the required fields (app name `canary-ingest`, your email as support +
   developer contact). Save and continue.
4. **Scopes**: you can skip adding scopes here (the script requests the
   read-only scope itself). Save and continue.
5. **Test users**: add your own Gmail address. Save.
   *(Leaving the app in "Testing" is fine — it just means only your added test
   users can authorise it, which is exactly what we want.)*

## Step 4 — Create OAuth credentials

1. **APIs & Services → Credentials → Create Credentials → OAuth client ID**.
2. Application type: **Desktop app**. Name it anything. Create.
3. **Download JSON**. Save it into the repo root as **`credentials.json`**.
   *(It is git-ignored — never commit it.)*

## Step 5 — First run (one browser consent)

```bash
uv run --extra gmail python scripts/fetch_gmail.py
```

- A browser opens → pick your Google account → you'll see an
  **"unverified app"** warning (it's your own app): **Advanced → Go to
  canary-ingest (unsafe) → Allow**.
- The script writes **`token.json`** (also git-ignored) and never asks again.
- It then fetches every alert, caches the bodies under
  `data/raw/emails_cache/`, and merges new events into the raw CSV.

## From then on

Whenever you want to catch up:

```bash
uv run --extra gmail python scripts/fetch_gmail.py
uv run python scripts/build_dataset.py
uv run pytest -q
```

Re-running is safe — the ingester de-duplicates, so already-seen events are
skipped.

## Notes

- **Scope is `gmail.readonly`** — the script can only read mail, never send,
  delete, or modify.
- **Secrets** (`credentials.json`, `token.json`) and the raw email cache are
  git-ignored; they never enter the repo.
- If `token.json` ever expires or is deleted, the next run just re-does the
  one browser consent.
