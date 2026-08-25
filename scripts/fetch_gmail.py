"""Fetch canarytoken alert emails from Gmail and ingest them.

One-command update: authenticates against the Gmail API (read-only), pulls
every canarytoken alert, caches each body under ``data/raw/emails_cache/``,
and merges the new events into the raw dataset via the tested ingester.

    uv run --extra gmail python scripts/fetch_gmail.py

First run opens a browser once to authorise read-only access and writes
``token.json`` (reused afterwards). Both ``credentials.json`` and
``token.json`` are git-ignored — they are secrets. See
``docs/INGESTION_SETUP.md`` for the one-time Google Cloud setup.
"""

import base64
import sys
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from canary_token_analytics.ingest import (
    load_token_map,
    parse_alert_email,
    merge_new_events,
)

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw" / "canary_alerts_raw.csv"
REGISTRY = ROOT / "data" / "raw" / "fleet_registry.csv"
CACHE = ROOT / "data" / "raw" / "emails_cache"
CREDS = ROOT / "credentials.json"
TOKEN = ROOT / "token.json"

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
QUERY = "from:noreply@canarytokens.org"


def _service():
    creds = None
    if TOKEN.exists():
        creds = Credentials.from_authorized_user_file(str(TOKEN), SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not CREDS.exists():
                sys.exit(f"missing {CREDS.name} — see docs/INGESTION_SETUP.md")
            creds = InstalledAppFlow.from_client_secrets_file(
                str(CREDS), SCOPES).run_local_server(port=0)
        TOKEN.write_text(creds.to_json())
    return build("gmail", "v1", credentials=creds)


def _plain_body(payload):
    """Walk a Gmail message payload and return the decoded text/plain body."""
    if payload.get("mimeType") == "text/plain":
        data = payload.get("body", {}).get("data")
        if data:
            return base64.urlsafe_b64decode(data).decode("utf-8", "replace")
    for part in payload.get("parts", []) or []:
        body = _plain_body(part)
        if body:
            return body
    return ""


def main():
    svc = _service()
    CACHE.mkdir(parents=True, exist_ok=True)

    ids, page = [], None
    while True:
        resp = svc.users().messages().list(
            userId="me", q=QUERY, pageToken=page, maxResults=500).execute()
        ids += [m["id"] for m in resp.get("messages", [])]
        page = resp.get("nextPageToken")
        if not page:
            break
    print(f"{len(ids)} canarytoken emails match the query")

    fetched = 0
    for mid in ids:
        cached = CACHE / f"{mid}.txt"
        if cached.exists():
            continue
        msg = svc.users().messages().get(
            userId="me", id=mid, format="full").execute()
        body = _plain_body(msg.get("payload", {}))
        if body:
            cached.write_text(body)
            fetched += 1
    print(f"fetched {fetched} new bodies (rest already cached)")

    token_map = load_token_map(REGISTRY)
    records = [parse_alert_email(p.read_text(errors="replace"), token_map)
               for p in sorted(CACHE.iterdir()) if p.is_file()]
    combined, n_added = merge_new_events(records, RAW)
    combined.to_csv(RAW, index=False)
    print(f"parsed {sum(r is not None for r in records)} bodies, "
          f"added {n_added} new events -> {len(combined)} total")
    if n_added:
        print("now run: uv run python scripts/build_dataset.py")


if __name__ == "__main__":
    main()
