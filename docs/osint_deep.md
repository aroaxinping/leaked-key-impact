# Deep per-IP OSINT layer

A second, deeper enrichment pass over the attacker IPs, on top of the base
geo/ASN/GreyNoise enrichment in `build_dataset.py`. It answers, for each IP:
*what does the wider internet already know about this host, and who is
responsible for the netblock?* — using only public OSINT databases.

## What it does

For every unique `source_ip` in `data/processed/ip_intel.csv`, three passive
lookups are run and flattened into `data/processed/ip_intel_deep.csv`:

| Column          | Source                | Meaning                                            |
| --------------- | --------------------- | -------------------------------------------------- |
| `source_ip`     | —                     | The attacker IP.                                   |
| `rdns`          | Reverse DNS (PTR)     | PTR hostname, if any.                              |
| `shodan_ports`  | Shodan InternetDB     | Open ports Shodan has already observed.            |
| `shodan_tags`   | Shodan InternetDB     | Shodan tags (e.g. `cloud`, `self-signed`).         |
| `shodan_vulns`  | Shodan InternetDB     | CVE ids Shodan associates with the host.           |
| `whois_netname` | `whois`               | Netblock name from the RIR.                        |
| `whois_org`     | `whois`               | Registered organisation / owner.                   |
| `whois_country` | `whois`               | Country of registration.                           |
| `whois_abuse`   | `whois`               | Abuse-reporting email for the netblock.            |

Empty cells are genuine gaps (no record / lookup failed), never invented.

## Passive-only ethics

This layer is **passive OSINT only**. It is non-negotiable and enforced by
how the code is written:

- We query **third-party databases about** the IP — never the IP itself.
  - **Shodan InternetDB** (`https://internetdb.shodan.io/<ip>`) serves
    Shodan's *already-collected* scan cache. We read that cache; we do not
    scan, and we never send a packet to the attacker host.
  - **`whois`** queries the responsible RIR/registry for the netblock's
    registration record. That is a query to the registry, not a connection
    to the host.
  - **Reverse DNS** resolves the PTR record via the standard public
    resolver — a DNS lookup, not a host connection.
- **No connection to attacker infrastructure**, ever — no curl/nc/openssl/
  ping/HTTP probe to the attacker IPs, and no visiting any hostname or
  domain discovered through them. Discovered hostnames are recorded as
  strings only.
- **Attribution stops at infrastructure.** We identify the provider
  responsible for a netblock, not the person behind it (GDPR). See
  `METHODOLOGY.md` §8 and `osint_tooling.md` §4.

## Tools used (all open-source / public)

- **Shodan InternetDB** — free, no API key, no account. Public endpoint.
- **`whois`** — the standard system client querying public RIR/registry
  WHOIS servers.
- **Reverse DNS** — Python's standard-library `socket` resolver against
  public DNS.

Code: `src/canary_token_analytics/enrich_deep.py` (pure stdlib + `requests`;
no secrets). Every function returns a dict and never raises — failures
degrade to empty fields.

## How to run it

From the repo root:

```bash
python scripts/build_deep_osint.py
```

The script:

1. Reads the unique attacker IPs from `data/processed/ip_intel.csv`.
2. Runs the three lookups per IP, **caching** each completed IP in
   `data/processed/deep_osint_cache.json` (git-ignored) so re-runs skip
   already-done IPs, and **throttling** with a short sleep between IPs to
   respect free-tier rate limits.
3. Writes `data/processed/ip_intel_deep.csv`.

Because of the cache, an interrupted run can simply be restarted — it picks
up where it left off. Delete the cache file to force a full refresh.
