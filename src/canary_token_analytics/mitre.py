"""MITRE ATT&CK mapping for the observed AWS canary-token events.

Maps each ``event_name`` to a MITRE ATT&CK (Enterprise / Cloud) tactic and
technique. This puts the project's home-grown intent taxonomy (see
``taxonomy.py``) into the industry-standard vocabulary analysts and detection
engineers actually use.

Each entry is ``(tactic, technique_id, technique_name)``. AWS-side defensive
events (quarantine / fraud flags) are not attacker techniques and map to
``None``.
"""

# event_name -> (tactic, technique_id, technique_name)
MITRE_MAP = {
    # --- Credential validation / account discovery ---
    "GetCallerIdentity": ("Discovery", "T1078.004", "Valid Accounts: Cloud Accounts"),
    "GetUser": ("Discovery", "T1087.004", "Account Discovery: Cloud Account"),
    "GetAccount": ("Discovery", "T1087.004", "Account Discovery: Cloud Account"),
    "GetAccountPasswordPolicy": ("Discovery", "T1201", "Password Policy Discovery"),
    "ListAccountAliases": ("Discovery", "T1087.004", "Account Discovery: Cloud Account"),
    "ListUsers": ("Discovery", "T1087.004", "Account Discovery: Cloud Account"),

    # --- Permissions / policy enumeration (privilege mapping) ---
    "ListRoles": ("Discovery", "T1069.003", "Permission Groups Discovery: Cloud Groups"),
    "ListPolicies": ("Discovery", "T1069.003", "Permission Groups Discovery: Cloud Groups"),
    "ListUserPolicies": ("Discovery", "T1069.003", "Permission Groups Discovery: Cloud Groups"),
    "ListAttachedUserPolicies": ("Discovery", "T1069.003", "Permission Groups Discovery: Cloud Groups"),
    "GetServiceQuota": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "GetRegions": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "DescribeSeverityLevels": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),

    # --- Infrastructure / compute enumeration ---
    "DescribeInstances": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "ListFunctions20150331": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "ListNotebookInstances": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "ListStacks": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "ListTaskDefinitionFamilies": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "GetContainerServices": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "ListApps": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "GetApis": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "ListRules": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "GetConnections": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "ListConnections": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "ListProjects": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),

    # --- Data-store discovery ---
    "ListBuckets": ("Discovery", "T1619", "Cloud Storage Object Discovery"),
    "ListTables": ("Discovery", "T1619", "Cloud Storage Object Discovery"),

    # --- Credential hunting (secrets stores) ---
    "ListSecrets": ("Credential Access", "T1552.005", "Unsecured Credentials: Cloud Instance Metadata / Secrets"),
    "DescribeParameters": ("Credential Access", "T1552", "Unsecured Credentials"),
    "ListKeys": ("Credential Access", "T1552", "Unsecured Credentials"),

    # --- Messaging / email abuse prep (spam / phishing) ---
    "GetSendQuota": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "ListEmailIdentities": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "GetSMSAttributes": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "ListTopics": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "ListFoundationModels": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "ListInferenceProfiles": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),

    # --- Resource hijacking (LLMjacking — Bedrock compute abuse) ---
    "InvokeModel": ("Impact", "T1496", "Resource Hijacking"),
    "Converse": ("Impact", "T1496", "Resource Hijacking"),
    "InvokeModelWithResponseStream": ("Impact", "T1496", "Resource Hijacking"),
    "ConverseStream": ("Impact", "T1496", "Resource Hijacking"),

    # --- Persistence / privilege escalation ---
    "CreateUser": ("Persistence", "T1136.003", "Create Account: Cloud Account"),
    "PutUserPolicy": ("Privilege Escalation", "T1098", "Account Manipulation"),

    # --- More infrastructure / data-store / account discovery ---
    "ListAliases": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "ListServices": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "GetRestApis": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "DescribeEnvironments": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "ListJobs": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "ListClusters": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "ListDevEndpoints": ("Discovery", "T1580", "Cloud Infrastructure Discovery"),
    "ListUserPools": ("Discovery", "T1087.004", "Account Discovery: Cloud Account"),
    "ListIdentityPools": ("Discovery", "T1087.004", "Account Discovery: Cloud Account"),
    "GetRole": ("Discovery", "T1069.003", "Permission Groups Discovery: Cloud Groups"),
    "ListGroups": ("Discovery", "T1069.003", "Permission Groups Discovery: Cloud Groups"),
    "ListGroupsForUser": ("Discovery", "T1069.003", "Permission Groups Discovery: Cloud Groups"),
    "HeadBucket": ("Discovery", "T1619", "Cloud Storage Object Discovery"),
    "GetParameter": ("Credential Access", "T1552.005", "Unsecured Credentials: Cloud Instance Metadata / Secrets"),

    # --- Resource hijacking (compute) ---
    "RunInstances": ("Impact", "T1496", "Resource Hijacking"),
    "RunTask": ("Impact", "T1496", "Resource Hijacking"),

    # --- Persistence / privilege escalation (more) ---
    "CreateFunction20150331": ("Persistence", "T1648", "Serverless Execution"),
    "CreateStateMachine": ("Persistence", "T1648", "Serverless Execution"),
    "AddUserToGroup": ("Privilege Escalation", "T1098", "Account Manipulation"),
    "CreateInstanceProfile": ("Privilege Escalation", "T1098", "Account Manipulation"),

    # --- AWS-side defense (not attacker techniques) ---
    "AttachUserPolicy": (None, None, "AWS auto-quarantine (defensive, not an ATT&CK technique)"),
    "SNS": (None, None, "AWS-side fraud/leak flag (defensive)"),
    "AWSFRAUDGITHUBKEYCLUTCHPROD": (None, None, "AWS-side fraud/leak flag (defensive)"),
}

_UNKNOWN = (None, None, "unmapped")


def classify_mitre(event_name):
    """Return ``(tactic, technique_id, technique_name)`` for an event name."""
    return MITRE_MAP.get(event_name, _UNKNOWN)
