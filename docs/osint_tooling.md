# OSINT tooling for IP infrastructure intelligence

This document is the reference for the **passive OSINT tooling** used to profile the
infrastructure behind the canary-token attacker IPs. It extends the per-field
enrichment recorded in [`METHODOLOGY.md`](METHODOLOGY.md): where METHODOLOGY covers
the primitives applied to build `ip_intel_deep.csv`, this file catalogues the wider
tool/source landscape, documents an automation framework (SpiderFoot), and records
the associated-infrastructure findings (reverse-IP, proxy flags, abuse contacts,
domain registration) captured in `data/processed/associated_infra.csv`.

- **Collection date:** 2026-08-27
- **Analyst posture:** passive OSINT only. Every technique below queries a
  third-party database/registry *about* an IP or reads what a host already exposes.
  No authentication, port scanning, exploitation, or credential submission against a
  target was performed. No malicious hostname was ever resolved-and-connected (see §4).

---

## 1. Tool / source catalogue, grouped by purpose

"Passive" = queries a third-party database or registry about the target, or reads
already-public metadata; the target is never touched. "Active" = sends packets to
the target itself. Only passive techniques were used in this project; active ones
are listed for completeness and explicitly marked.

### Geolocation
| Name | Open-source vs free-service | What it yields | Passive/Active |
|---|---|---|---|
| ip-api.com | Free service (no key) | Country, city, ISP, org, ASN + `proxy`/`hosting`/`mobile` booleans | Passive |
| ipinfo.io | Free service (no key) | City/region/country, ASN, org | Passive |
| MaxMind GeoLite2 | Open-source DB (offline) | Offline geo/ASN lookup, no network call | Passive |

### ASN / BGP / routing
| Name | Open-source vs free-service | What it yields | Passive/Active |
|---|---|---|---|
| RIPEstat `network-info` / `whois` | Free service (no key) | Announced prefix, origin ASN(s), RIR whois | Passive |
| `whois` (CLI, RIR: ARIN/RIPE/APNIC…) | Open-source CLI | Netname, OrgName, allocation, abuse contact | Passive |
| BGPView API | Free service (no key) | ASN details, prefixes, peers, upstreams | Passive |
| Robtex | Free service (no key) | AS/route summary, city/country, whois desc | Passive |
| Team Cymru IP-to-ASN | Free service (DNS/whois) | Fast bulk IP→ASN mapping | Passive |

### Reverse-IP & passive DNS
| Name | Open-source vs free-service | What it yields | Passive/Active |
|---|---|---|---|
| HackerTarget reverse-IP | Free service (rate-limited) | Other domains sharing an IP (co-hosting) | Passive |
| `dig -x` / PTR (CLI) | Open-source CLI | Reverse-DNS / PTR hostname | Passive |
| FarSight DNSDB / SecurityTrails | Free service (API key) | Historical/passive DNS (A/PTR over time) | Passive |

### Vulnerability / CVE enrichment
| Name | Open-source vs free-service | What it yields | Passive/Active |
|---|---|---|---|
| Shodan InternetDB | Free service (no key) | The list of CVE IDs a host is exposed to (from Shodan's prior scans) | Passive |
| Shodan CVEDB (`cvedb.shodan.io`) | Free service (no key) | Per-CVE **CVSS** (severity 0–10), **EPSS** (exploitation probability), **KEV** flag (CISA Known-Exploited), and summary | Passive |
| CISA KEV catalog | Open data | Which CVEs are confirmed exploited in the wild | Passive |
| FIRST EPSS | Open data | Probability a CVE will be exploited | Passive |

*Method:* the CVE IDs from InternetDB are enriched via CVEDB to rank each host's
exposure by severity and flag remote-code-execution (RCE) and actively-exploited
(KEV) vulnerabilities. Feeds [`pool_cve_inventory.md`](pool_cve_inventory.md) (full
205-CVE table), [`attacker_ip_cve_report.txt`](attacker_ip_cve_report.txt) (per-IP
CVE/RCE report), and the finding in
[`pool_infrastructure.md`](pool_infrastructure.md) — that several proxy-pool egress
nodes run end-of-life Squid/Apache with heavy CVE loads, i.e. likely-compromised
boxes recycled as proxies.

### Reputation / threat
| Name | Open-source vs free-service | What it yields | Passive/Active |
|---|---|---|---|
| GreyNoise Community | Free service (no key) | Whether IP is seen mass-scanning the internet | Passive |
| Shodan InternetDB | Free service (no key) | Open ports, products/OS, tags, known CVEs (from prior Shodan scans, not a live scan) | Passive |
| AbuseIPDB | Free service (API key) | Community abuse-report score | Passive |
| Spamhaus / abuse.ch feeds | Free service / open feeds | Blocklist + known-malware-infra membership | Passive |

### Proxy / VPN / hosting detection
| Name | Open-source vs free-service | What it yields | Passive/Active |
|---|---|---|---|
| ip-api.com `proxy`/`hosting`/`mobile` | Free service (no key) | Boolean flags per IP | Passive |
| ASN/org heuristic (datacenter vs carrier) | Method (over whois/ipinfo) | Infra type inferred from network owner | Passive |
| TLS-fallback / camouflage probe (`curl`+`openssl`) | Open-source CLI | Detects proxy masquerade (e.g. Xray/VLESS serving a decoy cert / Google redirect) | **Active** (touches target:443) |

### Certificate pivot
| Name | Open-source vs free-service | What it yields | Passive/Active |
|---|---|---|---|
| crt.sh (Certificate Transparency) | Free service (no key) | Certs + subject-alt-names issued for a domain/IP; pivot to related hosts | Passive |
| Censys certificates | Free service (API key) | Cert search + host cert history | Passive |
| `openssl s_client` | Open-source CLI | Live cert subject/issuer/chain from the host | **Active** (touches target:443) |

---

## 2. SpiderFoot — OSINT automation framework

[SpiderFoot](https://github.com/smicallef/spiderfoot) automates OSINT collection by
chaining ~200 modules: you give it a seed (here, an IP), and each module consumes
event types produced by others (IP → netblock → ASN → co-hosted domain → cert → …),
fanning out the collection and correlating results. It replaces running `whois`,
RIPEstat, BGPView, robtex, reverse-DNS, GreyNoise, etc. by hand, and de-duplicates
and links the findings. It has both a web UI and a CLI; only the **passive** modules
were enabled here (no port scanning, no active probing of the target).

### Install (throwaway venv)

`pip install spiderfoot` only fetches a reserved-name placeholder package (no
functionality), so install from source:

```bash
python3 -m venv sfvenv
git clone --depth 1 https://github.com/smicallef/spiderfoot
# SpiderFoot's pinned requirements assume an older Python; on Python 3.14 the
# pinned lxml<5 / PyPDF2 fail to build, so install current wheels of the deps:
sfvenv/bin/pip install "lxml>=5" cherrypy cherrypy-cors PyPDF2 adblockparser \
  dnspython ExifRead Mako beautifulsoup4 netaddr pysocks requests ipwhois ipaddr \
  phonenumbers pygexf python-whois secure pyOpenSSL python-docx python-pptx \
  networkx cryptography publicsuffixlist openpyxl pyyaml
```

### Passive run (CLI, CSV out)

```bash
cd spiderfoot
# Whole passive use case (auto-selects all passive modules; slow, some modules
# need API keys or hang on network):
../sfvenv/bin/python sf.py -s <ip> -u passive -o csv -q

# Focused fast passive set actually used here (registry/BGP/robtex/reverse-DNS,
# all no-key and quick):
../sfvenv/bin/python sf.py -s <ip> -m sfp_dnsresolve,sfp_ripe,sfp_bgpview,sfp_robtex -o csv -q
```

`-u passive` = passive use case, `-m` = explicit module list, `-s` = target,
`-o csv` = CSV output, `-q` = quiet. Passive no-key modules include `sfp_whois`,
`sfp_dnsresolve`, `sfp_ripe`, `sfp_bgpview`, `sfp_robtex`, `sfp_arin`,
`sfp_greynoise_community`; key-gated ones (`sfp_shodan`, `sfp_abuseipdb`,
`sfp_dnsdb`) were left disabled.

### SpiderFoot run — status: **completed**

SpiderFoot 4.0.0 was installed and run in this environment against the three
representative IPs. Real findings (verbatim):

- **146.103.40.12** (camouflaged proxy) — `sfp_ripe`: Netblock `146.103.40.0/22`,
  BGP AS `215311`. `sfp_robtex`: `{as: 215311, asname: "REGXA-CLOUD", country:
  "BE", bgproute: "146.103.40.0/22"}` — confirms the Regxa/REGXA-CLOUD leased VPS
  space from an independent source.
- **202.179.188.22** (exposed MikroTik) — `sfp_ripe`: Netblock `202.179.188.0/24`,
  BGP AS `38750`. `sfp_robtex`: `{as: 38750, asname: "TDS-AS-ID", city: "Bogor",
  country: "ID", whoisdesc: "Telemedia Dinamika Sarana, PT"}`.
- **34.173.24.24** (GCP node) — `sfp_dnsresolve`: Internet Name
  `24.24.173.34.bc.googleusercontent.com`, parent `googleusercontent.com`.
  `sfp_robtex`: `{as: 396982, asname: "Google", asdesc: "GOOGLE-CLOUD-PLATFORM",
  city: "Council Bluffs"}`. **Discrepancy worth recording:** SpiderFoot's
  `sfp_ripe` attributes the covering `34.173.0.0/17` prefix to **AS15169** (Google's
  main network AS), whereas ip-api/robtex report the more specific
  **AS396982 GOOGLE-CLOUD-PLATFORM**. Both are Google; the /17 is registered to the
  parent AS while the announced route is delegated to the Cloud AS. Consistent with
  METHODOLOGY's practice of surfacing rather than smoothing such disagreements.

The broad `-u passive` use case was also launched but is slow (some modules block on
network / expect API keys); the focused module set above returned the same
registry/BGP facts quickly and was used for the recorded results.

---

## 3. Findings — associated infrastructure (Tasks 2–3)

Full per-IP data: [`data/processed/associated_infra.csv`](../data/processed/associated_infra.csv).
Sources: `ip-api.com` (proxy/hosting/mobile flags, ISP), RIPEstat `network-info`
(prefix + origin ASN), HackerTarget reverse-IP (co-hosted domains), `whois` (abuse
contacts), and `whois <domain>` for registrable domains.

### Proxy / hosting / mobile flags (ip-api.com)
| IP | proxy | hosting | mobile | ISP | Reading |
|---|---|---|---|---|---|
| 146.103.40.12 | false | **true** | false | Regxa (REGXA-CLOUD) | Datacenter/VPS — leased space, matches camouflaged-proxy finding |
| 34.173.24.24 | false | **true** | false | Google LLC | Cloud (GCP us-central1) |
| 99.89.81.59 | false | false | **true** | AT&T | Mobile carrier (CGNAT) |
| 172.56.14.182 | false | false | **true** | T-Mobile | Mobile carrier (CGNAT) |
| 172.56.198.175 | false | false | **true** | T-Mobile | Mobile carrier (CGNAT) |
| 99.63.197.17 | false | false | **true** | AT&T | Mobile carrier (CGNAT) |
| 172.58.243.229 | false | false | **true** | T-Mobile | Mobile carrier (CGNAT) |
| 182.4.101.162 | false | **true** | **true** | Telkomsel | Mobile carrier; `hosting=true` likely reflects mixed carrier/hosting ranges |
| 202.179.188.22 | false | false | false | Telemedia Dinamika Sarana | Fixed-line ISP (exposed MikroTik CPE) |

None of the nine set the `proxy` boolean. Note that ip-api's `proxy` flag catches
known commercial VPN/proxy exit-node lists, **not** a self-hosted TLS-camouflaged
proxy — 146.103.40.12 shows `hosting=true, proxy=false` yet is the confirmed
Xray/VLESS masquerade from `ip_intel_deep.csv`. The flag is a weak signal; the
camouflage evidence is stronger.

### Reverse-IP (co-hosted domains) — flagged for C2
Only **146.103.40.12** returned co-hosted domains; the other eight returned "No DNS
A records found" (expected for CGNAT/mobile and single-tenant cloud IPs). No
reverse-IP query was rate-limited during this run.

146.103.40.12 reverse-IP set (**RECORDED, NOT CONNECTED TO — see §4**):
```
akdikdy.cayeuxvinc.com
faranate.duckdns.org
lrar24comin.dtdns.org
paramanoman.duckdns.org
ureagozonoun.duckdns.org
usfiscanoon.duckdns.org
```
`reverse_ip_looks_like_c2 = yes`. Rationale: random-looking subdomains on
dynamic-DNS parents (`duckdns.org`, `dtdns.org`) co-located on a camouflaged VPS is
a classic malware C2 / redirector fingerprint.

### Domain registration (Task 3) — registrable domains only
Passive `whois` (registry only) was run for the one registrable domain in the set,
`cayeuxvinc.com`. The dynamic-DNS parents (`duckdns.org`, `dtdns.org`) are shared
infrastructure, not attacker-registered, and were **not** queried or visited.

| Domain | Registrar | Creation date | Registrant |
|---|---|---|---|
| cayeuxvinc.com | IONOS SE | 2026-05-27 | REDACTED FOR PRIVACY (registrant country: FR) |

The **2026-05-27** creation date (≈3 months before the collection date, and within
the alert window) is consistent with throwaway attacker infrastructure. The
registrant is GDPR/privacy-redacted; per §4 attribution stops here.

### Who to report to (abuse contacts — network owners, not attacker identity)
These are the **network-owner abuse desks to notify** for traffic sourced from each
IP. They identify the responsible provider, never the individual behind the IP.

| IP | Org (netname) | Abuse email | Abuse phone |
|---|---|---|---|
| 146.103.40.12 | REGXA LLC (NET-146-103-40-0-22) | report@abuseradar.com | +31205354444 (RIPE NCC) |
| 34.173.24.24 | Google LLC (GOOGL-2) | google-cloud-compliance@google.com | +1-650-253-0000 |
| 99.89.81.59 | AT&T Enterprises, LLC (SBCIS-SBIS) | abuse@att.net | +1-919-319-8167 |
| 172.56.14.182 | T-Mobile USA, Inc. (TMO9) | abuse@t-mobile.com | +1-888-662-4662 |
| 172.56.198.175 | T-Mobile USA, Inc. (TMO9) | abuse@t-mobile.com | +1-888-662-4662 |
| 99.63.197.17 | AT&T Enterprises, LLC (SBCIS-SBIS) | abuse@att.net | +1-919-319-8167 |
| 172.58.243.229 | T-Mobile USA, Inc. (TMO9) | abuse@t-mobile.com | +1-888-662-4662 |
| 182.4.101.162 | PT Telekomunikasi Selular (TELKOMSEL-ID) | abuse@idnic.net | +62-21-5240811 |
| 202.179.188.22 | Telemedia Dinamika Sarana, PT (TDS-JKT-08) | abuse@tds.net.id | +62-21-4507447 |

For 146.103.40.12 the maximally-specific RIPE object gives `report@abuseradar.com`
(the reseller's abuse handler); the RIPE NCC desk (`abuse@ripe.net`, +31205354444)
is the registry-level fallback.

---

## 4. Attribution stops at infrastructure

Consistent with [`METHODOLOGY.md` §8](METHODOLOGY.md), this investigation identifies
**where** traffic originated and **which provider is responsible for reporting** — a
hosting provider, cloud tenant, mobile carrier, or camouflaged VPS — and stops there.
It does **not** attempt to identify or deanonymize the human behind any IP or domain.

- **GDPR-redacted registrants.** The one registrable attacker domain
  (`cayeuxvinc.com`) has its registrant name/org/address/phone withheld as "REDACTED
  FOR PRIVACY". That redaction is recorded as-is and treated as a full stop, not a
  puzzle to solve.
- **Legal process required.** Linking an IP or a redacted domain to a person needs
  the provider's or registrar's private subscriber records, obtainable only through
  a lawful request (subpoena / court order / abuse-report follow-up) by an authorized
  party — out of scope for this passive study.
- **Do not connect to discovered malicious hosts.** The C2-style hostnames surfaced
  by reverse-IP (`*.duckdns.org`, `*.dtdns.org`, `*.cayeuxvinc.com`) were recorded as
  strings only. None was resolved-and-connected, curl'd, pinged, or HTTP-probed.
  `whois` on the *registrable* domain hits the registry (safe); it is never a
  connection to the host. This boundary is absolute.

> **Deep per-IP OSINT layer:** a scripted passive pass (Shodan InternetDB + `whois` + reverse DNS) per attacker IP lives in [`osint_deep.md`](osint_deep.md) — run via `scripts/build_deep_osint.py`, output in `data/processed/ip_intel_deep.csv`.
