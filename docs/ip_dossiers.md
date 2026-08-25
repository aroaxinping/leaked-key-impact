# IP Dossiers — Deep Passive OSINT

Passive OSINT only (whois, dig/reverse-DNS, ipinfo.io, Shodan InternetDB, GreyNoise community, and read-only curl/openssl TLS banner reads). No authentication, scanning, or intrusive probing was performed. Values recorded are exactly what a command returned; unknowns are marked and explained.

Collection date: 2026-08-27 (UTC). GreyNoise community API imposed a weekly rate limit after 5 lookups; the remaining 4 are marked "unknown (rate limit)".

---

## 146.103.40.12 — CAMOUFLAGE CONFIRMED (Xray/VLESS masquerading as Google)

- **whois (RIPE):** netname `NET-146-103-40-0-22`, org `ORG-RL619-RIPE` / **REGXA LLC**, ASN **AS215311** (Regxa Company for Information Technology Ltd). Status `LEGACY`, remark **"End User Organization"**, org country listed **US** while geolocation is **DE** (Frankfurt). Created 2024-04-01. The `descr:` field carries a `-----BEGIN TOKEN-----...-----END TOKEN-----` blob — a hallmark of **leased / resold IP space** (the block is delegated to an end user via a token-authenticated object).
- **abuse contact:** `report@abuseradar.com` (a third-party abuse-handling service, again consistent with leased/reseller space rather than a first-party hoster).
- **reverse DNS:** none.
- **Shodan InternetDB:** ports **22, 443**; products **Google web_server**, **OpenSSH 9.2p1**, Linux kernel / Debian; tag **`self-signed`**; no known vulns.
- **Direct probe (`curl -k -sI https://146.103.40.12`):** `HTTP/2 301` → `location: http://www.google.com/`, `server: gws`, Google CSP-report headers. Without `-k`, curl exits **60** (cert validation failure).
- **TLS (openssl, no SNI):** `subject=OU=No SNI provided - please fix your client., CN=invalid2.invalid`, identical issuer, `verify return code: 18 (self-signed certificate)`.
- **GreyNoise:** noise=false, riot=false, "not observed scanning."

**Interpretation:** This is the classic **Xray/VLESS "Fallback" camouflage**. The proxy accepts a real client only when the correct SNI/handshake is presented; anything else (a bare probe, wrong SNI) is transparently proxied to Google's real front end — hence the `301 → google.com`, the `server: gws` header, and the Google-style "No SNI provided" placeholder certificate. It presents itself as innocuous Google traffic to any scanner. Provider type: **hosting/datacenter VPS on leased space** — the only true datacenter/proxy node in the set. Frankfurt VPS + Windows-2022 boto3 UA (event 3) = an operator hiding behind a disguised relay.

---

## 34.173.24.24 — Google Cloud Platform compute

- **whois:** NetName `GOOGL-2`, Org **Google LLC (GOOGL-2)**, **AS396982**, US. Abuse `google-cloud-compliance@google.com`.
- **reverse DNS:** `24.24.173.34.bc.googleusercontent.com` — a Google Cloud **compute VM** hostname (`bc.googleusercontent.com`).
- **Shodan InternetDB:** "No information available" (no open services observed).
- **Direct probe:** no HTTPS response.
- **GreyNoise:** noise=false, riot=false, "not observed scanning."

**Interpretation:** A **cloud (GCP) compute instance**, AS396982 being Google Cloud's customer-facing ASN. Not consumer/residential — an attacker-rented VM. Council Bluffs, Iowa is Google's `us-central1` region. This IP did the live-key validation + SES quota + region recon burst (events 4–6) and carried the `DeepAWSAnalyzer/Pro` tool signature.

---

## 99.89.81.59 — AT&T residential/mobile

- **whois:** NetName `SBCIS-SBIS`, **AT&T Enterprises, LLC (AEL-360)**, **AS7018**, US. Abuse `abuse@att.net`.
- **reverse DNS:** none. **Shodan:** no data. **GreyNoise:** noise=false, riot=false.

**Interpretation:** AS7018 is a **known US consumer carrier (AT&T)**. Residential/mobile broadband IP, no exposed services — a real end-user access line (or device behind it), not hosting. Lansing, MI.

---

## 172.56.14.182 — T-Mobile mobile (CGNAT)

- **whois:** NetName `TMO9`, **T-Mobile USA, Inc. (TMOBI)**, **AS21928**, US. Abuse `abuse@t-mobile.com`.
- **reverse DNS:** none. **Shodan:** no data. **GreyNoise:** noise=false, riot=false.

**Interpretation:** AS21928 is a **known US consumer mobile carrier (T-Mobile)**. The 172.32.0.0/11 block is T-Mobile carrier-grade-NAT mobile space — IPs rotate across subscribers, so geolocation (Sacramento) is approximate. Part of the coordinated `iam_masscek/2.0` burst (event 9).

---

## 172.56.198.175 — T-Mobile mobile (CGNAT)

- **whois:** NetName `TMO9`, **T-Mobile USA, Inc. (TMOBI)**, **AS21928**, US. Abuse `abuse@t-mobile.com`.
- **reverse DNS:** none. **Shodan:** no data. **GreyNoise:** unknown (rate limit).

**Interpretation:** Same T-Mobile CGNAT space as above; geolocated Boston. Issued the `CreateUser` persistence call (event 10) under the `iam_masscek/2.0` signature — but the IP itself is throwaway mobile space.

---

## 99.63.197.17 — AT&T residential/mobile

- **whois:** NetName `SBCIS-SBIS`, **AT&T Enterprises, LLC (AEL-360)**, **AS7018**, US. Abuse `abuse@att.net`.
- **reverse DNS:** none. **Shodan:** no data. **GreyNoise:** unknown (rate limit).

**Interpretation:** AT&T consumer carrier (AS7018), Reston VA. Residential/mobile, no services. Part of the `iam_masscek/2.0` burst (event 11, `GetAccount`).

---

## 172.58.243.229 — T-Mobile mobile (CGNAT)

- **whois:** NetName `TMO9`, **T-Mobile USA, Inc. (TMOBI)**, **AS21928**, US. Abuse `abuse@t-mobile.com`.
- **reverse DNS:** none. **Shodan:** no data. **GreyNoise:** unknown (rate limit).

**Interpretation:** T-Mobile CGNAT mobile space, Baltimore MD. This IP issued the Bedrock `InvokeModel` LLMjacking attempt (event 12).

---

## 182.4.101.162 — Telkomsel cellular (Indonesia)

- **whois (APNIC):** netname `TELKOMSEL-ID`, **PT. Telekomunikasi Selular (Telkomsel)**, "Cellular Network Provider", **AS23693**, ID. Abuse `abuse@telkomsel.co.id` / `abuse@idnic.net`.
- **reverse DNS:** none. **Shodan:** no data. **GreyNoise:** unknown (rate limit).

**Interpretation:** AS23693 is a **known consumer mobile carrier (Telkomsel, Indonesia)**. Residential/mobile cellular IP, Yogyakarta. Did validation + GetUser recon (events 13–14).

---

## 202.179.188.22 — Exposed MikroTik router (Indonesian ISP)

- **whois (APNIC):** netname `TDS-JKT-08`, **PT Telemedia Dinamika Sarana (TDS)**, **AS38750**, ID (Jakarta). Abuse `abuse@tds.net.id`.
- **reverse DNS:** none.
- **Shodan InternetDB:** ports **22, 8291, 8728** (no product string, no vulns, no tags). Ports **8291 (Winbox)** + **8728 (RouterOS API)** are the signature of a **MikroTik RouterOS** device; 22 is SSH.
- **Direct probe:** no HTTPS/443 service. **GreyNoise:** unknown (rate limit).

**Interpretation:** A fixed-line **ISP** address (TDS, AS38750) fronting an **exposed MikroTik CPE router** (Winbox + API management ports reachable from the internet). No camouflage, but internet-exposed MikroTik routers are a well-known population that gets compromised and repurposed as **proxy/relay nodes** in botnets (e.g. Mēris-class). Issued `GetServiceQuota` + `ListRoles` recon (events 15–16). Worth flagging as a possible **compromised-router relay** rather than a genuine end user.

---

## Cross-cutting notes

- **One disguised datacenter node** (146.103.40.12, Xray/VLESS-as-Google, leased Regxa space) is the only true hosting/proxy in the set; **one exposed MikroTik router** (202.179.188.22) is a plausible relay.
- **Everything else is consumer-carrier space**: AT&T (AS7018), T-Mobile (AS21928), Telkomsel (AS23693) — mobile/residential IPs that rotate and geolocate loosely. This pattern (many short-lived carrier IPs sharing the same `iam_masscek/2.0` / boto3 tool fingerprints within minutes on 2026-08-25) points to a single operator behind mobile/proxy egress rather than many distinct actors.
- **34.173.24.24 is rented cloud (GCP)** — the middle ground: not disguised, but not a real person's line either.
- No IP in the set was flagged by GreyNoise as an internet-wide scanner; 5 explicitly returned "not observed scanning," 4 unknown due to the community rate limit.

### Could not fully resolve
- GreyNoise for **99.63.197.17, 172.58.243.229, 182.4.101.162, 202.179.188.22** — weekly community rate limit hit; retries kept returning HTTP 429-equivalent. Marked "unknown."
- TLS/cert detail beyond the self-signed placeholder for **146.103.40.12** — the Xray fallback only serves a real cert on a valid SNI handshake, which a passive probe won't trigger; the placeholder + `301→google.com` + `server: gws` is sufficient to confirm camouflage.
- Open-port/OS data for the 6 consumer-carrier IPs — Shodan InternetDB had "No information available" (no indexed services), consistent with NAT'd end-user lines.
