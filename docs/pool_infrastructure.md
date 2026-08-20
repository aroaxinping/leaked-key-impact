# The proxy pool runs on vulnerable — likely compromised — servers

A passive-OSINT look at the egress nodes behind the coordinated fan-out (see
[`fleet_placement_analysis.md`](fleet_placement_analysis.md)) turns up a
consistent picture: several of them are **neglected, badly out-of-date proxy
servers riddled with known vulnerabilities** — the classic profile of a machine
that was hijacked and repurposed as a proxy, rather than clean infrastructure an
operator rented.

All facts below come from Shodan InternetDB, the Shodan CVEDB, and `whois`
(passive; nothing was ever connected to these hosts). The full per-CVE list is in
[`pool_cve_inventory.md`](pool_cve_inventory.md).

## What we found

Five attacker IPs expose services with catalogued vulnerabilities — **205 unique
CVEs** in total (35 rated *Critical*, 92 *High*, and **9 on CISA's
Known-Exploited list** — i.e. confirmed exploited in real-world attacks).

| IP | Host / country | Open ports | Shodan tags | CVEs | KEV | In fan-out pool? |
|---|---|---|---|---:|---:|:--:|
| `103.130.61.61` | PT. Fiqran (ID) | 53, 80, 8081, 10000 | `proxy` | **186** | 3 | ✅ **yes** |
| `45.66.249.187` | RIPE-range (NL) | 443, 554, **3128**, 8181 | `eol-product`, `open-dir` | 65 | 2 | ✅ **yes** |
| `88.150.154.27` | iomart (GB) | **1080**, **1194**, 992, 5555 | `proxy`, `vpn` | 61 | 0 | no (other actor) |
| `2.26.160.172` | NetGrid (EU) | 80 | `eol-product` | 2 | 1 | no |
| `31.76.31.55` | PowerRDP (FI) | 22, 80, 443, 3389 | `eol-product` | 2 | 1 | no |

## Why this reads as "compromised, recycled infrastructure"

Three independent signals point the same way:

1. **They run proxy software on proxy ports.** `3128` is Squid's default port;
   `1080` is SOCKS; `1194` is OpenVPN. These boxes *are* proxies/VPNs — which is
   exactly what an egress node is.
2. **The software is dangerously old.** Shodan tags two of them `eol-product`
   (end-of-life software) and one `open-dir` (an exposed, listable directory —
   a hallmark of a poorly-maintained host). The CVE load is enormous: 186 on one
   box, 65 on another.
3. **Known-Exploited (KEV) vulnerabilities are present** — the very flaws
   attackers use to take over a server:
   - `CVE-2019-0211` — Apache HTTP Server local privilege escalation (root a box).
   - `CVE-2021-40438` — Apache `mod_proxy` SSRF.
   - `CVE-2024-38475` — Apache path handling.
   - `CVE-2023-44487` — HTTP/2 "Rapid Reset".
   A machine this exposed, running software with actively-exploited holes, is a
   prime candidate to have been broken into and quietly turned into a proxy.

**The strongest part:** two of these vulnerable proxies (`103.130.61.61` and
`45.66.249.187`) are **confirmed members of the coordinated fan-out pool** — same
Debian-13 / boto3-1.43.80 build, both firing `InvokeModel` (LLMjacking). So this
isn't a side observation about unrelated IPs; the pool that hammered
`terraform.tfvars` is **partly built out of hijacked, vulnerable boxes**.

## The honest caveats

- **CVE detection is version-based.** Shodan infers vulnerabilities from the
  detected software version — it is strong evidence the host is unpatched, not
  proof any specific flaw was exploited *here*.
- **"Compromised" is an inference, not a proven fact.** The convergence
  (proxy role + EOL software + KEV vulns + open directories) makes hijack the
  most likely explanation, but a sloppily-run *legitimate* cheap proxy service
  would look similar. We stop at "vulnerable proxy infrastructure, likely
  compromised."
- **Passive only.** We never connected to these hosts; everything is third-party
  database lookups. Attribution stops at the infrastructure.

## Where this could go next

- Cross-reference the abuse contacts / ASNs to see whether the pool concentrates
  on a few neglected hosters.
- Check whether these IPs also appear as internet-wide *scanners* (compromised
  boxes often scan) in GreyNoise.
- Track over time whether the same vulnerable IPs recur or rotate — a stable set
  suggests a curated pool; constant churn suggests a rented/botnet feed.
