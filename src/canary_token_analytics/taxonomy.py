"""Intent taxonomy for canary-token AWS API events.

Maps each observed ``event_name`` to an attack-lifecycle ``phase`` and a
human-readable description. This mapping is authoritative for the project:
it is derived from what each AWS API call reveals about the operator's
intent, not from any external framework.
"""

# event_name -> (phase, description)
INTENT_TAXONOMY = {
    "GetCallerIdentity": (
        "validation",
        "Confirms the stolen key is live and reveals which account/identity "
        "it belongs to",
    ),
    "GetUser": (
        "reconnaissance",
        "Enumerates the account's identity, permissions, roles, regions or "
        "limits",
    ),
    "GetAccount": (
        "reconnaissance",
        "Enumerates the account's identity, permissions, roles, regions or "
        "limits",
    ),
    "ListRoles": (
        "reconnaissance",
        "Enumerates the account's identity, permissions, roles, regions or "
        "limits",
    ),
    "ListAttachedUserPolicies": (
        "reconnaissance",
        "Enumerates the account's identity, permissions, roles, regions or "
        "limits",
    ),
    "GetRegions": (
        "reconnaissance",
        "Enumerates the account's identity, permissions, roles, regions or "
        "limits",
    ),
    "DescribeSeverityLevels": (
        "reconnaissance",
        "Enumerates the account's identity, permissions, roles, regions or "
        "limits",
    ),
    "GetServiceQuota": (
        "reconnaissance",
        "Enumerates the account's identity, permissions, roles, regions or "
        "limits",
    ),
    "GetSendQuota": (
        "abuse-prep",
        "Checks the SES email sending quota - precursor to spam/phishing "
        "from the account",
    ),
    "ListUserPolicies": (
        "reconnaissance",
        "Enumerates the account's identity, permissions, roles, regions or "
        "limits",
    ),
    "ListSecrets": (
        "reconnaissance",
        "Enumerates AWS Secrets Manager entries, hunting for further stored "
        "credentials to escalate with",
    ),
    "ListBuckets": (
        "reconnaissance",
        "Enumerates the account's S3 buckets, hunting for accessible or "
        "exfiltratable data stores",
    ),
    "ListUsers": (
        "reconnaissance",
        "Enumerates the account's IAM users, mapping identities and escalation "
        "targets",
    ),
    "ListStacks": (
        "reconnaissance",
        "Enumerates CloudFormation stacks, hunting for infrastructure "
        "definitions and embedded parameters",
    ),
    "ListTopics": (
        "reconnaissance",
        "Enumerates SNS topics — messaging infrastructure that can be abused "
        "for spam or pivoting",
    ),
    "ListAccountAliases": (
        "reconnaissance",
        "Enumerates the account's IAM alias — cheap account fingerprinting",
    ),
    "DescribeInstances": (
        "reconnaissance",
        "Enumerates EC2 instances, mapping running compute to hijack or abuse",
    ),
    "PutUserPolicy": (
        "persistence",
        "Attaches an inline policy to an IAM user - privilege escalation, an "
        "attempt to grant itself durable permissions",
    ),
    "ListFunctions20150331": (
        "reconnaissance",
        "Enumerates the account's Lambda functions (the 20150331 API version "
        "of ListFunctions)",
    ),
    "ListFoundationModels": (
        "abuse-prep",
        "Enumerates which Bedrock foundation models the account can reach - "
        "precursor to LLMjacking",
    ),
    "ListInferenceProfiles": (
        "abuse-prep",
        "Enumerates Bedrock inference profiles - Bedrock recon that precedes "
        "LLMjacking",
    ),
    "GetSMSAttributes": (
        "abuse-prep",
        "Checks the SNS SMS sending settings - precursor to SMS spam/smishing "
        "from the account",
    ),
    "ListEmailIdentities": (
        "abuse-prep",
        "Enumerates SES verified email identities - precursor to phishing from "
        "the account",
    ),
    "GetAccountPasswordPolicy": (
        "reconnaissance",
        "Reads the account's IAM password policy - account-wide fingerprinting",
    ),
    "ListNotebookInstances": (
        "reconnaissance",
        "Enumerates SageMaker notebook instances - hunting for compute to hijack",
    ),
    "ListPolicies": (
        "reconnaissance",
        "Enumerates IAM policies to map permissions and escalation paths",
    ),
    "Converse": (
        "resource-abuse",
        "Attempts to run AI models on AWS Bedrock at the victim's expense "
        "(LLMjacking), via the Bedrock Converse chat API",
    ),
    "CreateUser": (
        "persistence",
        "Attempts to create a new IAM user to retain access even if the "
        "leaked key is revoked",
    ),
    "InvokeModel": (
        "resource-abuse",
        "Attempts to run AI models on AWS Bedrock at the victim's expense "
        "(LLMjacking)",
    ),
    "InvokeModelWithResponseStream": (
        "resource-abuse",
        "Attempts to run AI models on AWS Bedrock at the victim's expense "
        "(LLMjacking), via the streaming InvokeModel API",
    ),
    "ConverseStream": (
        "resource-abuse",
        "Attempts to run AI models on AWS Bedrock at the victim's expense "
        "(LLMjacking), via the streaming Bedrock Converse chat API",
    ),
    "ListKeys": (
        "reconnaissance",
        "Enumerates KMS keys, mapping the account's encryption material",
    ),
    "DescribeParameters": (
        "reconnaissance",
        "Enumerates SSM Parameter Store entries, hunting for stored config and "
        "secrets to escalate with",
    ),
    "ListTables": (
        "reconnaissance",
        "Enumerates DynamoDB tables, hunting for accessible or exfiltratable "
        "data stores",
    ),
    "ListTaskDefinitionFamilies": (
        "reconnaissance",
        "Enumerates ECS task-definition families, mapping containerised "
        "workloads to hijack or abuse",
    ),
    "ListProjects": (
        "reconnaissance",
        "Enumerates CodeBuild projects, hunting for build pipelines and "
        "embedded credentials",
    ),
    "ListApps": (
        "reconnaissance",
        "Enumerates deployed applications, mapping the account's hosted "
        "workloads",
    ),
    "GetConnections": (
        "reconnaissance",
        "Enumerates service connections, mapping integrations and pivot paths",
    ),
    "ListConnections": (
        "reconnaissance",
        "Enumerates service connections, mapping integrations and pivot paths",
    ),
    "GetContainerServices": (
        "reconnaissance",
        "Enumerates Lightsail container services, mapping running compute to "
        "hijack or abuse",
    ),
    "GetApis": (
        "reconnaissance",
        "Enumerates API Gateway APIs, mapping exposed endpoints to abuse or "
        "pivot through",
    ),
    "ListRules": (
        "reconnaissance",
        "Enumerates EventBridge rules, mapping the account's automation and "
        "event wiring",
    ),
    "ListAliases": (
        "reconnaissance",
        "Enumerates KMS key aliases, mapping the account's encryption keys",
    ),
    "DescribeVpcs": (
        "reconnaissance",
        "Enumerates VPCs, mapping the account's network topology",
    ),
    "ListServices": (
        "reconnaissance",
        "Enumerates ECS services, mapping running container workloads to "
        "hijack or abuse",
    ),
    "GetRestApis": (
        "reconnaissance",
        "Enumerates API Gateway REST APIs, mapping exposed endpoints to abuse "
        "or pivot through",
    ),
    "DescribeEnvironments": (
        "reconnaissance",
        "Enumerates Elastic Beanstalk environments, mapping deployed apps",
    ),
    "ListUserPools": (
        "reconnaissance",
        "Enumerates Cognito user pools, mapping the account's identity stores",
    ),
    "ListIdentityPools": (
        "reconnaissance",
        "Enumerates Cognito identity pools, mapping the account's identity "
        "stores",
    ),
    "GetParameter": (
        "reconnaissance",
        "Reads an SSM Parameter Store value, hunting for stored secrets or "
        "config",
    ),
    "HeadBucket": (
        "reconnaissance",
        "Probes an S3 bucket's existence and access, mapping reachable storage",
    ),
    "GetRole": (
        "reconnaissance",
        "Reads an IAM role, mapping assumable roles and their permissions",
    ),
    "ListGroups": (
        "reconnaissance",
        "Enumerates IAM groups, mapping the account's permission structure",
    ),
    "ListGroupsForUser": (
        "reconnaissance",
        "Enumerates the IAM groups a user belongs to, mapping permission "
        "inheritance paths",
    ),
    "ListJobs": (
        "reconnaissance",
        "Enumerates Glue jobs, mapping data pipelines in the account",
    ),
    "ListClusters": (
        "reconnaissance",
        "Enumerates ECS/EKS clusters, mapping container compute to hijack or "
        "abuse",
    ),
    "ListDevEndpoints": (
        "reconnaissance",
        "Enumerates Glue development endpoints, mapping accessible compute",
    ),
    "RunInstances": (
        "resource-abuse",
        "Launches EC2 instances on the victim's account - compute hijacking "
        "for cryptomining or other abuse",
    ),
    "RunTask": (
        "resource-abuse",
        "Runs an ECS task on the victim's account - compute hijacking for "
        "abuse",
    ),
    "CreateFunction20150331": (
        "persistence",
        "Creates a Lambda function - a foothold to run code and retain access",
    ),
    "CreateStateMachine": (
        "persistence",
        "Creates a Step Functions state machine - a foothold to orchestrate "
        "code execution",
    ),
    "AddUserToGroup": (
        "persistence",
        "Adds an IAM user to a group - privilege escalation to retain or "
        "widen access",
    ),
    "CreateInstanceProfile": (
        "persistence",
        "Creates an IAM instance profile - scaffolding for privilege "
        "escalation or persistence",
    ),
    "AttachUserPolicy": (
        "defense",
        "AWS's own automated quarantine attaching a restrictive policy to "
        "the leaked key",
    ),
    "SNS": (
        "defense",
        "AWS-side fraud/leak detection flagging the key",
    ),
    "AWSFRAUDGITHUBKEYCLUTCHPROD": (
        "defense",
        "AWS-side fraud/leak detection flagging the key",
    ),
}

_UNKNOWN = ("unknown", "No intent mapping defined for this event")


def classify_intent(event_name, source_ip=None):
    """Return ``(phase, description)`` for an ``event_name``.

    ``source_ip`` is accepted for the special ``AttachUserPolicy`` case,
    which is only classified as AWS's own defensive quarantine when the
    source is AWS-internal (which is the only way it appears in this data).
    """
    if event_name not in INTENT_TAXONOMY:
        return _UNKNOWN
    return INTENT_TAXONOMY[event_name]
