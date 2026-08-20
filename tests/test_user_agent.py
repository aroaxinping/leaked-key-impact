"""Unit tests for boto3 user-agent parsing (pure, deterministic)."""

from canary_token_analytics.enrich import parse_boto3_user_agent

# Real user agents observed in the dataset.
UA_IAM_MASSCEK = (
    "Boto3/1.43.74 md/Botocore#1.43.74 ua/2.1 os/linux#5.15.0-46-generic "
    "md/arch#x86_64 lang/python#3.10.12 md/pyimpl#CPython m/E,b,Z,e "
    "cfg/retry-mode#standard Botocore/1.43.74 iam_masscek/2.0"
)
UA_DEEPAWS = (
    "Boto3/1.43.65 md/Botocore#1.43.65 ua/2.1 os/windows#2022Server "
    "md/arch#amd64 lang/python#3.14.2 md/pyimpl#CPython m/Z,e,b,F "
    "cfg/retry-mode#adaptive Botocore/1.43.65 DeepAWSAnalyzer/Pro"
)
UA_PLAIN = (
    "Boto3/1.43.81 md/Botocore#1.43.81 ua/2.1 os/windows#10 md/arch#amd64 "
    "lang/python#3.11.2 md/pyimpl#CPython m/D,e,C,b,Z cfg/retry-mode#legacy "
    "Botocore/1.43.81"
)


def test_parses_named_attacker_tool_signature():
    parsed = parse_boto3_user_agent(UA_IAM_MASSCEK)
    assert parsed["tool_signature"] == "iam_masscek/2.0"
    assert parsed["boto3_version"] == "1.43.74"
    assert parsed["python_version"] == "3.10.12"
    assert parsed["os"] == "linux#5.15.0-46-generic"
    assert parsed["retry_mode"] == "standard"


def test_parses_second_named_tool():
    parsed = parse_boto3_user_agent(UA_DEEPAWS)
    assert parsed["tool_signature"] == "DeepAWSAnalyzer/Pro"
    assert parsed["os"] == "windows#2022Server"
    assert parsed["python_version"] == "3.14.2"


def test_plain_ua_has_no_tool_signature_but_parses_fields():
    # The 'm/D,e,C,b,Z' segment has unquoted commas; parsing must not break.
    parsed = parse_boto3_user_agent(UA_PLAIN)
    assert parsed["tool_signature"] is None
    assert parsed["os"] == "windows#10"
    assert parsed["python_version"] == "3.11.2"
    assert parsed["boto3_version"] == "1.43.81"
    assert parsed["retry_mode"] == "legacy"


def test_empty_user_agent_returns_all_none():
    for empty in ("", None):
        parsed = parse_boto3_user_agent(empty)
        assert parsed == {
            "os": None,
            "python_version": None,
            "boto3_version": None,
            "retry_mode": None,
            "tool_signature": None,
        }
