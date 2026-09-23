"""Pipeline: raw canary alerts -> enriched analytical dataset.

Orchestrates reading the raw CSV, enriching each unique IP once (geo,
ASN/org, infra type, GreyNoise signal), parsing every user agent, mapping
each event to its intent, and writing the processed CSVs. Every enriched
value comes from a real lookup or the raw data; gaps stay ``None``.
"""

from pathlib import Path

import pandas as pd

from .enrich import (
    lookup_ip,
    parse_boto3_user_agent,
    classify_infra_type,
    greynoise_community,
    ip_api_batch,
    infra_from_flags,
    NON_ATTACKER_IPS,
)
from .taxonomy import classify_intent

RAW_COLUMNS = [
    "seq", "datetime_utc", "date_utc", "time_utc",
    "source_ip", "event_name", "user_agent", "alert_type",
    "token_id", "placement", "channel",
]


def _read_raw(raw_path):
    """Read the raw alerts CSV.

    The ``user_agent`` field can contain commas (e.g. ``m/D,Z,b,e``); the file
    is written with standard CSV quoting, so pandas parses it directly. Every
    field is kept as a string and empty cells stay as ``""`` (not ``NaN``) so
    that blank ``source_ip`` / ``user_agent`` on AWS-side rows read as empty.
    """
    df = pd.read_csv(raw_path, dtype=str, keep_default_na=False)
    assert list(df.columns) == RAW_COLUMNS, f"unexpected header: {list(df.columns)}"
    return df


def _is_attacker_ip(ip):
    return ip not in NON_ATTACKER_IPS and str(ip).strip() != ""


def build_ip_intel(unique_ips, log=print):
    """Look up each unique attacker IP once. Returns {ip: intel_dict}."""
    log(f"  batch network-type lookup for {len(unique_ips)} IPs (ip-api) ...")
    net = ip_api_batch(unique_ips)

    intel = {}
    for ip in unique_ips:
        log(f"  looking up {ip} ...")
        geo = lookup_ip(ip)
        gn = greynoise_community(ip)
        flags = net.get(ip, {"proxy": None, "hosting": None, "mobile": None, "asname": None})
        # Keyword classifier first; fall back to the ip-api flags rather than
        # leaving the type blank when the org string is ambiguous.
        infra = classify_infra_type(geo["org"], geo["asn"]) or infra_from_flags(flags)
        intel[ip] = {
            **geo,
            "infra_type": infra,
            "asname": flags["asname"],
            "is_proxy": flags["proxy"],
            "is_hosting": flags["hosting"],
            "is_mobile": flags["mobile"],
            "gn_noise": gn["noise"],
            "gn_riot": gn["riot"],
            "gn_classification": gn["classification"],
            "gn_name": gn["name"],
        }
        if geo["org"] is None:
            log(f"    ! no geo/org resolved for {ip}")
    return intel


def run_pipeline(raw_path, processed_dir, log=print):
    """Run the full enrichment pipeline and write processed outputs.

    Returns ``(enriched_df, ip_intel_df)``.
    """
    raw_path = Path(raw_path)
    processed_dir = Path(processed_dir)
    processed_dir.mkdir(parents=True, exist_ok=True)

    df = _read_raw(raw_path)
    log(f"read {len(df)} raw rows from {raw_path}")

    unique_ips = sorted({ip for ip in df["source_ip"] if _is_attacker_ip(ip)})
    log(f"{len(unique_ips)} unique attacker IPs to resolve")
    intel = build_ip_intel(unique_ips, log=log)

    enriched_rows = []
    for _, row in df.iterrows():
        ip = row["source_ip"]
        geo = intel.get(ip, {})
        ua = parse_boto3_user_agent(row["user_agent"])
        phase, desc = classify_intent(row["event_name"], ip)
        enriched_rows.append({
            **{c: row[c] for c in RAW_COLUMNS},
            "city": geo.get("city"),
            "region": geo.get("region"),
            "country": geo.get("country"),
            "asn": geo.get("asn"),
            "org": geo.get("org"),
            "infra_type": geo.get("infra_type"),
            "asname": geo.get("asname"),
            "is_proxy": geo.get("is_proxy"),
            "is_hosting": geo.get("is_hosting"),
            "is_mobile": geo.get("is_mobile"),
            "ua_os": ua["os"],
            "ua_python": ua["python_version"],
            "ua_boto3": ua["boto3_version"],
            "ua_retry_mode": ua["retry_mode"],
            "tool_signature": ua["tool_signature"],
            "intent_phase": phase,
            "intent_description": desc,
        })

    enriched_df = pd.DataFrame(enriched_rows)

    ip_intel_rows = []
    for ip in unique_ips:
        d = intel[ip]
        ip_intel_rows.append({
            "source_ip": ip,
            "city": d["city"],
            "region": d["region"],
            "country": d["country"],
            "asn": d["asn"],
            "org": d["org"],
            "infra_type": d["infra_type"],
            "asname": d["asname"],
            "is_proxy": d["is_proxy"],
            "is_hosting": d["is_hosting"],
            "is_mobile": d["is_mobile"],
            "gn_noise": d["gn_noise"],
            "gn_riot": d["gn_riot"],
            "gn_classification": d["gn_classification"],
            "gn_name": d["gn_name"],
        })
    ip_intel_df = pd.DataFrame(ip_intel_rows)

    enriched_out = processed_dir / "alerts_enriched.csv"
    ip_intel_out = processed_dir / "ip_intel.csv"
    enriched_df.to_csv(enriched_out, index=False)
    ip_intel_df.to_csv(ip_intel_out, index=False)
    log(f"wrote {enriched_out} ({len(enriched_df)} rows)")
    log(f"wrote {ip_intel_out} ({len(ip_intel_df)} rows)")

    return enriched_df, ip_intel_df
