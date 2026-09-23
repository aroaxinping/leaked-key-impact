"""Live enrichment helpers for canary-token events.

Functions here perform real network lookups (ipinfo.io, GreyNoise community
API, and ``whois`` as a fallback) and parse boto3 user-agent strings. No
value is ever invented: when a lookup fails, the corresponding field is
returned as ``None`` so the caller can record a genuine gap.
"""

import json
import re
import subprocess
import urllib.request
import urllib.error

IPINFO_URL = "https://ipinfo.io/{ip}/json"
GREYNOISE_URL = "https://api.greynoise.io/v3/community/{ip}"
IPAPI_BATCH_URL = "http://ip-api.com/batch"

# IPs that are AWS's own detections, not attacker infrastructure.
NON_ATTACKER_IPS = {"AWS Internal", "", None}


def _http_get_json(url, timeout=15):
    """GET a URL and return parsed JSON, or ``None`` on any failure."""
    req = urllib.request.Request(url, headers={"User-Agent": "canary-token-analytics"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, OSError):
        return None


def _whois_org(ip, timeout=20):
    """Fallback: best-effort org/netname from the system ``whois`` tool."""
    try:
        out = subprocess.run(
            ["whois", ip],
            capture_output=True,
            text=True,
            timeout=timeout,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for key in ("OrgName", "org-name", "netname", "descr", "owner"):
        m = re.search(rf"^{key}:\s*(.+)$", out, re.IGNORECASE | re.MULTILINE)
        if m:
            return m.group(1).strip()
    return None


def lookup_ip(ip):
    """Return geo + ASN/org for ``ip`` via ipinfo.io, ``whois`` as backup.

    Returns a dict with keys: city, region, country, asn, org. Any field
    that could not be resolved is ``None``. AWS-internal / blank sources
    are skipped entirely (all fields ``None``).
    """
    result = {"city": None, "region": None, "country": None, "asn": None, "org": None}
    if ip in NON_ATTACKER_IPS:
        return result

    data = _http_get_json(IPINFO_URL.format(ip=ip))
    if data and not data.get("bogon"):
        result["city"] = data.get("city") or None
        result["region"] = data.get("region") or None
        result["country"] = data.get("country") or None
        org = data.get("org")  # e.g. "AS7018 AT&T Services, Inc."
        if org:
            m = re.match(r"(AS\d+)\s+(.*)", org)
            if m:
                result["asn"], result["org"] = m.group(1), m.group(2).strip()
            else:
                result["org"] = org.strip()

    if not result["org"]:
        result["org"] = _whois_org(ip)

    return result


def ip_api_batch(ips, timeout=30):
    """Batch-classify IPs' network type via ip-api.com.

    Returns ``{ip: {"proxy": bool|None, "hosting": bool|None,
    "mobile": bool|None, "asname": str|None}}``. ip-api's ``proxy`` /
    ``hosting`` / ``mobile`` booleans are a reliable signal for whether an IP
    is a proxy/VPN, a datacenter, or a mobile carrier — used to fill the gaps
    the keyword classifier leaves. On any failure the IP maps to all-``None``.

    The batch endpoint accepts up to 100 queries per call; larger inputs are
    chunked. Non-attacker sources are skipped.
    """
    targets = [ip for ip in ips if ip not in NON_ATTACKER_IPS]
    out = {ip: {"proxy": None, "hosting": None, "mobile": None, "asname": None}
           for ip in targets}
    fields = "query,proxy,hosting,mobile,asname,status"
    for start in range(0, len(targets), 100):
        chunk = targets[start:start + 100]
        body = json.dumps([{"query": ip, "fields": fields} for ip in chunk])
        req = urllib.request.Request(
            IPAPI_BATCH_URL,
            data=body.encode("utf-8"),
            headers={"Content-Type": "application/json",
                     "User-Agent": "canary-token-analytics"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError, OSError):
            continue
        for r in data or []:
            ip = r.get("query")
            if ip in out and r.get("status") == "success":
                out[ip] = {
                    "proxy": bool(r.get("proxy")),
                    "hosting": bool(r.get("hosting")),
                    "mobile": bool(r.get("mobile")),
                    "asname": r.get("asname") or None,
                }
    return out


def infra_from_flags(flags):
    """Fallback infra_type from ip-api boolean flags, when keywords fail.

    ``flags`` is one value dict from :func:`ip_api_batch`. Returns a label or
    ``None``. Mobile takes precedence (a mobile carrier can also read as
    hosting); then hosting/proxy -> 'datacenter/hosting'.
    """
    if flags.get("mobile"):
        return "residential/mobile"
    if flags.get("hosting") or flags.get("proxy"):
        return "datacenter/hosting"
    return None


# Keyword -> infra_type, ordered from most to least specific.
_INFRA_RULES = [
    (("t-mobile", "at&t", "att ", "cellco", "verizon wireless", "sprint",
      "selular", "seluler", "telkomsel", "mobile"),
     "residential/mobile"),
    (("google cloud", "google llc", "amazon", "aws", "microsoft azure",
      "azure", "digitalocean", "linode", "vultr", "ovh", "hetzner"),
     "cloud"),
    (("regxa", "brander", "hosting", "datacenter", "data center", "server",
      "vps", "colo", "leaseweb", "contabo"),
     "datacenter VPS"),
    (("telkom", "biznet", "indosat", "first media", "comcast", "spectrum",
      "cox", "telemedia", "dinamika", "sarana", "telecom", "broadband",
      "communications", "isp"),
     "residential/ISP"),
]


def classify_infra_type(org, asn=None):
    """Classify infrastructure type from the ASN/org string.

    Returns one of: 'cloud', 'datacenter VPS', 'residential/mobile',
    'residential/ISP', or None when there is nothing to classify.
    """
    if not org:
        return None
    hay = f"{org} {asn or ''}".lower()
    for keywords, label in _INFRA_RULES:
        if any(k in hay for k in keywords):
            return label
    return None


# boto3 user-agent tokens, e.g.:
# Boto3/1.43.68 md/Botocore#1.43.68 ua/2.1 os/windows#2022Server
# md/arch#amd64 lang/python#3.11.2 md/pyimpl#CPython
# cfg/retry-mode#legacy Botocore/1.43.68 DeepAWSAnalyzer/Pro
_BOTO3_RE = re.compile(r"Boto3/([\d.]+)")
_PYTHON_RE = re.compile(r"lang/python#([\d.]+)")
_OS_RE = re.compile(r"os/([^\s#]+)(?:#([^\s]+))?")
_RETRY_RE = re.compile(r"cfg/retry-mode#(\S+)")

# Named attacker tools appended to the UA.
_KNOWN_TOOLS = ("DeepAWSAnalyzer/Pro", "iam_masscek/2.0", "TruffleHog")


def parse_boto3_user_agent(ua):
    """Parse a boto3/botocore user-agent into structured fields.

    Returns a dict: os, python_version, boto3_version, retry_mode,
    tool_signature. Missing pieces are ``None``.
    """
    result = {
        "os": None,
        "python_version": None,
        "boto3_version": None,
        "retry_mode": None,
        "tool_signature": None,
    }
    if not ua:
        return result

    m = _BOTO3_RE.search(ua)
    if m:
        result["boto3_version"] = m.group(1)

    m = _PYTHON_RE.search(ua)
    if m:
        result["python_version"] = m.group(1)

    m = _OS_RE.search(ua)
    if m:
        result["os"] = f"{m.group(1)}#{m.group(2)}" if m.group(2) else m.group(1)

    m = _RETRY_RE.search(ua)
    if m:
        result["retry_mode"] = m.group(1)

    for tool in _KNOWN_TOOLS:
        if tool in ua:
            result["tool_signature"] = tool
            break

    return result


def greynoise_community(ip):
    """Query the GreyNoise community API (no key required) for ``ip``.

    Returns a dict with keys: noise, riot, classification, name. Returns
    all-``None`` on any failure or for non-attacker sources.
    """
    result = {"noise": None, "riot": None, "classification": None, "name": None}
    if ip in NON_ATTACKER_IPS:
        return result
    data = _http_get_json(GREYNOISE_URL.format(ip=ip))
    if not data:
        return result
    # A "not observed" 404 body still parses as JSON with a message field.
    result["noise"] = data.get("noise")
    result["riot"] = data.get("riot")
    result["classification"] = data.get("classification")
    result["name"] = data.get("name")
    return result
