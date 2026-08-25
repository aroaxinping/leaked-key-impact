"""Build the deep per-IP OSINT table for the current attacker IPs.

Reads the unique ``source_ip`` values from ``data/processed/ip_intel.csv``,
runs three passive OSINT lookups per IP (Shodan InternetDB + system whois +
reverse DNS), and writes ``data/processed/ip_intel_deep.csv``.

Two safeguards keep re-runs cheap and rate-limit-friendly:

* **Cache** — every completed IP is stored in
  ``data/processed/deep_osint_cache.json``. On a re-run, cached IPs are
  loaded from disk and their network lookups are skipped entirely.
* **Throttle** — a short sleep between IPs so we stay well within the
  free-tier limits of the services we query.

PASSIVE ONLY: we query third-party OSINT databases; we never connect to the
attacker IPs, hosts, or any discovered domain. See ``docs/osint_deep.md``.

Run from the repo root:

    python scripts/build_deep_osint.py
"""

import csv
import json
import sys
import time
from pathlib import Path

# Make ``src`` importable when run as a plain script.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from canary_token_analytics.enrich_deep import (  # noqa: E402
    reverse_dns,
    shodan_internetdb,
    whois_details,
)

IN_CSV = ROOT / "data" / "processed" / "ip_intel.csv"
OUT_CSV = ROOT / "data" / "processed" / "ip_intel_deep.csv"
CACHE = ROOT / "data" / "processed" / "deep_osint_cache.json"

# Seconds to pause between IPs that actually hit the network.
THROTTLE_SECONDS = 1.5

FIELDNAMES = [
    "source_ip",
    "rdns",
    "shodan_ports",
    "shodan_tags",
    "shodan_vulns",
    "whois_netname",
    "whois_org",
    "whois_country",
    "whois_abuse",
]

# Sources that are not real attacker IPs.
_SKIP = {"AWS Internal", "", None}


def load_cache():
    """Return the on-disk cache dict ({ip: row}), or empty on any problem."""
    if not CACHE.exists():
        return {}
    try:
        with CACHE.open(encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_cache(cache):
    """Write the cache to disk atomically-ish (temp file then replace)."""
    tmp = CACHE.with_suffix(".json.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, sort_keys=True)
    tmp.replace(CACHE)


def read_unique_ips():
    """Return the sorted unique attacker source IPs from ip_intel.csv."""
    with IN_CSV.open(encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    ips = {r["source_ip"].strip() for r in rows if r.get("source_ip")}
    return sorted(ip for ip in ips if ip not in _SKIP)


def lookup_ip(ip):
    """Run the three passive lookups for one IP and return a flat CSV row."""
    shodan = shodan_internetdb(ip)
    whois = whois_details(ip)
    rdns = reverse_dns(ip)
    return {
        "source_ip": ip,
        "rdns": rdns or "",
        "shodan_ports": ",".join(str(p) for p in shodan["ports"]),
        "shodan_tags": ",".join(shodan["tags"]),
        "shodan_vulns": ",".join(shodan["vulns"]),
        "whois_netname": whois["netname"] or "",
        "whois_org": whois["org"] or "",
        "whois_country": whois["country"] or "",
        "whois_abuse": whois["abuse_email"] or "",
    }


def main():
    ips = read_unique_ips()
    cache = load_cache()
    total = len(ips)
    print(f"[deep-osint] {total} unique attacker IPs; "
          f"{len(cache)} already in cache")

    rows = []
    for i, ip in enumerate(ips, 1):
        if ip in cache:
            print(f"[{i}/{total}] {ip} — cached, skipping lookups")
            rows.append(cache[ip])
            continue

        print(f"[{i}/{total}] {ip} — querying Shodan InternetDB + whois + rDNS")
        row = lookup_ip(ip)
        cache[ip] = row
        rows.append(row)
        # Persist after every new IP so an interrupted run loses nothing.
        save_cache(cache)
        time.sleep(THROTTLE_SECONDS)

    # Keep output row order aligned with the sorted IP list.
    rows.sort(key=lambda r: r["source_ip"])
    with OUT_CSV.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[deep-osint] wrote {len(rows)} rows -> {OUT_CSV}")


if __name__ == "__main__":
    main()
