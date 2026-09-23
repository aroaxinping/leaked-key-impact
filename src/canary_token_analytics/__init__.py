"""Canary token analytics: enrich real AWS canary-token security events.

This package turns a raw CSV of canary-token alerts into an analytical
dataset by adding geolocation, ASN/organization, infrastructure type,
parsed boto3 user-agent details and an intent taxonomy for each event.
"""

from .taxonomy import INTENT_TAXONOMY, classify_intent
from .enrich import (
    lookup_ip,
    parse_boto3_user_agent,
    classify_infra_type,
    greynoise_community,
)

__all__ = [
    "INTENT_TAXONOMY",
    "classify_intent",
    "lookup_ip",
    "parse_boto3_user_agent",
    "classify_infra_type",
    "greynoise_community",
]
