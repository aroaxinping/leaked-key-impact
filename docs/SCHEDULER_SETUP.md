# Scheduled ingestion (macOS launchd)

Runs the Gmail fetch + dataset rebuild automatically every 6 hours, so the
dataset stays current with no manual step. It **does not commit or push** — new
data is left in the working tree for you to review and commit yourself.

Prereq: the one-time Gmail OAuth setup is done (see
[`INGESTION_SETUP.md`](INGESTION_SETUP.md)) and `credentials.json` + `token.json`
exist in the repo root.

## Install

```bash
cp deploy/com.aroa.canary-ingest.plist ~/Library/LaunchAgents/
launchctl load -w ~/Library/LaunchAgents/com.aroa.canary-ingest.plist
```

Verify it's registered:

```bash
launchctl list | grep canary-ingest
```

## Trigger a run now (optional test)

```bash
launchctl start com.aroa.canary-ingest
tail -f logs/ingest.log        # watch it fetch + rebuild
```

## Logs

- `logs/ingest.log` — the fetch/build output of each run.
- `logs/launchd.out.log` / `logs/launchd.err.log` — launchd's own stdout/stderr.

(`logs/` is git-ignored.)

## Change the interval

Edit `StartInterval` in the plist (seconds; 21600 = 6 h), then reload:

```bash
launchctl unload ~/Library/LaunchAgents/com.aroa.canary-ingest.plist
cp deploy/com.aroa.canary-ingest.plist ~/Library/LaunchAgents/
launchctl load -w ~/Library/LaunchAgents/com.aroa.canary-ingest.plist
```

## Stop / uninstall

```bash
launchctl unload -w ~/Library/LaunchAgents/com.aroa.canary-ingest.plist
rm ~/Library/LaunchAgents/com.aroa.canary-ingest.plist
```

## Important caveat — the 7-day token

The OAuth app is in **Testing** mode, so Google expires the refresh token in
`token.json` after ~7 days. When that happens the scheduled run will start
failing (see `logs/ingest.log`); just re-run the fetch **once by hand** to
re-authorise:

```bash
uv run --extra gmail python scripts/fetch_gmail.py   # opens the browser again
```

The scheduler then resumes with the refreshed token. (Publishing the app would
remove the 7-day limit but requires Google verification for the Gmail scope,
which isn't worth it for a personal project.)
