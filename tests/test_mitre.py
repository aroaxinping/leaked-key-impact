"""Unit tests for the MITRE ATT&CK mapping (pure, deterministic)."""

import pytest

from canary_token_analytics.mitre import MITRE_MAP, classify_mitre

ALLOWED_TACTICS = {
    "Discovery",
    "Credential Access",
    "Privilege Escalation",
    "Persistence",
    "Impact",
    None,  # AWS-side defensive events
}


@pytest.mark.parametrize("event_name,expected", MITRE_MAP.items())
def test_every_mapping_is_wellformed(event_name, expected):
    tactic, technique_id, technique_name = expected
    assert tactic in ALLOWED_TACTICS
    assert technique_name  # never empty
    # Attacker techniques carry a Txxxx id; defensive events carry None.
    if tactic is None:
        assert technique_id is None
    else:
        assert technique_id and technique_id.startswith("T")


def test_llmjacking_is_resource_hijacking():
    for ev in ("InvokeModel", "Converse", "InvokeModelWithResponseStream", "ConverseStream"):
        assert classify_mitre(ev) == ("Impact", "T1496", "Resource Hijacking")


def test_unknown_event_is_unmapped():
    assert classify_mitre("SomeBrandNewApiCall") == (None, None, "unmapped")
