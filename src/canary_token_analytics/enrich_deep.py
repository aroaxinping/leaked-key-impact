"""Deep, per-IP passive-OSINT enrichment for canary-token attacker IPs.

This module adds a second, deeper enrichment layer on top of :mod:`enrich`
(ipinfo / ip-api / GreyNoise). It queries **only** third-party OSINT
databases and never connects to the attacker infrastructure itself:

* **Shodan InternetDB** (``https://internetdb.shodan.io/<ip>``) — a free,
  key-less endpoint that returns Shodan's *already-collected* scan facts
  (open ports, tags, CVE ids, hostnames) for an IP. We read Shodan's cache;
  we do not scan.
* **whois** — the system ``whois`` command, which queries the responsible
  RIR / registry for the netblock's registration record (netname, CIDR,
  org, country, abuse contact).
* **Reverse DNS** — the PTR record for the IP, via the standard resolver
  (Python's :mod:`socket`).

ETHICS: passive only. None of these functions ever opens a connection to
the attacker IP, host, or any domain discovered through it. Attribution
stops at infrastructure — we never attempt to identify the person behind an
IP (GDPR). See ``docs/osint_deep.md``.

Every function returns a plain ``dict`` and **never raises**: on any
failure (network error, missing tool, unparseable output, no record) the
relevant fields come back as ``None`` or empty so the caller records a
genuine gap rather than a fabricated value. No secrets or API keys are used.
"""

import re
import socket
import subprocess

import requests

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"

# Sources that are not real attacker IPs; skip network work for them.
_NON_ATTACKER = {"AWS Internal", "", None}

_USER_AGENT = "canary-token-analytics (passive OSINT research)"


def shodan_internetdb(ip, timeout=15):
    """Return Shodan InternetDB facts for ``ip`` (passive; no scanning).

    InternetDB is a free, no-key endpoint serving Shodan's *cached* scan
    results. Returns a dict with keys ``ports`` (list[int]), ``tags``
    (list[str]), ``vulns`` (list[str] of CVE ids), ``hostnames``
    (list[str]). All empty on any failure or when the IP is unknown to
    Shodan (the endpoint answers 404 for never-seen IPs). Never raises.
    """
    result = {"ports": [], "tags": [], "vulns": [], "hostnames": []}
    if ip in _NON_ATTACKER:
        return result
    try:
        resp = requests.get(
            INTERNETDB_URL.format(ip=ip),
            headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
            timeout=timeout,
        )
    except requests.RequestException:
        return result
    if resp.status_code != 200:
        # 404 == "no information available" for this IP; anything else is a
        # transient error. Either way, record an empty (honest) result.
        return result
    try:
        data = resp.json()
    except ValueError:
        return result
    if not isinstance(data, dict):
        return result
    result["ports"] = [p for p in (data.get("ports") or []) if p is not None]
    result["tags"] = [t for t in (data.get("tags") or []) if t]
    result["vulns"] = [v for v in (data.get("vulns") or []) if v]
    result["hostnames"] = [h for h in (data.get("hostnames") or []) if h]
    return result


# whois field -> the canonical key we expose. Ordered candidates per key are
# tried in turn so we cope with ARIN / RIPE / APNIC / AFRINIC / LACNIC layouts.
_WHOIS_FIELDS = {
    "netname": ("netname", "NetName"),
    "cidr": ("CIDR", "inetnum", "NetRange", "route"),
    "org": ("OrgName", "org-name", "Organization", "owner", "descr", "netname"),
    "country": ("Country", "country"),
    "abuse_email": ("OrgAbuseEmail", "abuse-mailbox", "abuse-c", "e-mail"),
}

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def _first_field(text, keys):
    """Return the first value in ``text`` for any of ``keys`` (case-insensitive)."""
    for key in keys:
        m = re.search(rf"^\s*{re.escape(key)}\s*:\s*(.+?)\s*$",
                      text, re.IGNORECASE | re.MULTILINE)
        if m and m.group(1).strip():
            return m.group(1).strip()
    return None


def whois_details(ip, timeout=25):
    """Return registration details for ``ip`` from the system ``whois`` tool.

    Queries the responsible RIR/registry (not the host). Returns a dict with
    keys ``netname``, ``cidr``, ``org``, ``country``, ``abuse_email`` —
    each ``None`` when absent or on any failure (missing ``whois`` binary,
    timeout, no record). Never raises.
    """
    result = {"netname": None, "cidr": None, "org": None,
              "country": None, "abuse_email": None}
    if ip in _NON_ATTACKER:
        return result
    try:
        proc = subprocess.run(
            ["whois", ip],
            capture_output=True,
            text=True,
            # Some RIR whois servers reply in Latin-1; never let a stray
            # byte crash the run — replace undecodable bytes instead.
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return result
    out = proc.stdout or ""
    if not out.strip():
        return result

    for key, candidates in _WHOIS_FIELDS.items():
        result[key] = _first_field(out, candidates)

    # Abuse contact: prefer an explicit abuse field, else the first address
    # appearing on a line that mentions "abuse".
    if result["abuse_email"] and not _EMAIL_RE.fullmatch(result["abuse_email"] or ""):
        # abuse-c is often a handle, not an email; only keep real addresses.
        m = _EMAIL_RE.search(result["abuse_email"])
        result["abuse_email"] = m.group(0) if m else None
    if not result["abuse_email"]:
        for line in out.splitlines():
            if "abuse" in line.lower():
                m = _EMAIL_RE.search(line)
                if m:
                    result["abuse_email"] = m.group(0)
                    break

    # Normalise country to the code/name token only.
    if result["country"]:
        result["country"] = result["country"].split("#")[0].strip()

    return result


def reverse_dns(ip):
    """Return the PTR hostname for ``ip``, or ``None`` if none / on failure.

    Uses the standard resolver via :func:`socket.gethostbyaddr`. This is a
    reverse-DNS lookup against public DNS, not a connection to the host.
    Never raises.
    """
    if ip in _NON_ATTACKER:
        return None
    try:
        host, _aliases, _addrs = socket.gethostbyaddr(ip)
    except (OSError, socket.herror, socket.gaierror):
        return None
    return host or None
