"""Unit tests for the intent taxonomy (pure, deterministic)."""

import pytest

from canary_token_analytics.taxonomy import (
    INTENT_TAXONOMY,
    classify_intent,
)

ALLOWED_PHASES = {
    "validation",
    "reconnaissance",
    "abuse-prep",
    "persistence",
    "resource-abuse",
    "defense",
}


@pytest.mark.parametrize(
    "event_name, expected_phase",
    [
        ("GetCallerIdentity", "validation"),
        ("ListRoles", "reconnaissance"),
        ("ListAttachedUserPolicies", "reconnaissance"),
        ("GetSendQuota", "abuse-prep"),
        ("CreateUser", "persistence"),
        ("InvokeModel", "resource-abuse"),
        ("AttachUserPolicy", "defense"),
        ("AWSFRAUDGITHUBKEYCLUTCHPROD", "defense"),
    ],
)
def test_known_events_map_to_expected_phase(event_name, expected_phase):
    phase, description = classify_intent(event_name)
    assert phase == expected_phase
    assert isinstance(description, str) and description


def test_unknown_event_returns_unknown():
    phase, description = classify_intent("SomeEventThatDoesNotExist")
    assert phase == "unknown"
    assert isinstance(description, str) and description


def test_every_taxonomy_phase_is_in_the_allowed_set():
    for event_name, (phase, description) in INTENT_TAXONOMY.items():
        assert phase in ALLOWED_PHASES, f"{event_name} has invalid phase {phase!r}"
        assert isinstance(description, str) and description
