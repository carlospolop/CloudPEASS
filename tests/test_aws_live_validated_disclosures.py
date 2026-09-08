from CloudPEASS.permission_risk_classifier import classify_permission
from sensitive_permissions.aws import (
    live_validated_disclosure_documentation,
    sensitive_combinations,
    very_sensitive_combinations,
)


LIVE_VALIDATED_HIGH_ACTIONS = {
    "account:GetContactInformation",
    "amplify:GetApp",
    "amplify:GetJob",
    "apigateway:GET",
    "athena:GetQueryExecution",
    "appstream:CreateStreamingURL",
    "appconfig:GetHostedConfigurationVersion",
    "appsync:GraphQL",
    "appsync:ListApiKeys",
    "autoscaling:DescribeLaunchConfigurations",
    "batch:DescribeJobDefinitions",
    "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
    "cloudformation:DescribeStacks",
    "cloudformation:DescribeChangeSet",
    "cloudformation:GetTemplate",
    "cloudformation:GetTemplateSummary",
    "cloudformation:ListExports",
    "cloudfront:GetDistribution",
    "cloudfront:GetDistributionConfig",
    "cloudfront:GetFunction",
    "cloudfront:ListDistributions",
    "cloudtrail:LookupEvents",
    "ce:GetCostAndUsage",
    "codebuild:BatchGetBuilds",
    "codebuild:BatchGetProjects",
    "codeartifact:GetPackageVersionAsset",
    "codecommit:GetBlob",
    "codecommit:GetCommit",
    "codecommit:GetFile",
    "codecommit:GitPull",
    "codepipeline:PollForJobs",
    "connect:GetFederationToken",
    "cognito-idp:AdminGetUser",
    "cognito-idp:DescribeUserPoolClient",
    "cognito-idp:DescribeIdentityProvider",
    "cognito-idp:ListUsers",
    "cognito-idp:ListUsersInGroup",
    "dynamodb:BatchGetItem",
    "dynamodb:GetItem",
    "dynamodb:Query",
    "dynamodb:Scan",
    "dynamodb:TransactGetItems",
    "deadline:AssumeQueueRoleForRead",
    "deadline:AssumeQueueRoleForUser",
    "ec2:DescribeLaunchTemplateVersions",
    "ec2:DescribeInstanceAttribute",
    "ebs:GetSnapshotBlock",
    "ecr:GetDownloadUrlForLayer",
    "ecs:DescribeTaskDefinition",
    "ecs:DescribeTasks",
    "emr-serverless:GetApplication",
    "emr-serverless:GetJobRun",
    "events:ListTargetsByRule",
    "execute-api:Invoke",
    "glue:GetConnection",
    "glue:GetJob",
    "glue:GetWorkflowRunProperties",
    "greengrass:GetComponentVersionArtifact",
    "imagebuilder:GetComponent",
    "iot:GetThingShadow",
    "iotwireless:GetWirelessDevice",
    "kinesis:GetRecords",
    "kinesisanalytics:DescribeApplication",
    "lambda:GetFunctionConfiguration",
    "lambda:GetLayerVersion",
    "logs:FilterLogEvents",
    "logs:GetLogRecord",
    "logs:GetLogEvents",
    "logs:GetQueryResults",
    "invoicing:BatchGetInvoiceProfile",
    "invoicing:GetInvoicePDF",
    "invoicing:ListInvoiceSummaries",
    "sagemaker:DescribeModel",
    "sagemaker:DescribeTrainingJob",
    "s3:GetDataAccess",
    "s3express:CreateSession",
    "scheduler:GetSchedule",
    "pipes:DescribePipe",
    "profile:SearchProfiles",
    "ses:GetSuppressedDestination",
    "ses:GetEmailTemplate",
    "ses:ListSuppressedDestinations",
    "sns:ListSubscriptions",
    "sns:ListSubscriptionsByTopic",
    "sqs:ReceiveMessage",
    "ssm:GetParameterHistory",
    "ssm:GetDocument",
    "ssm:GetOpsItem",
    "states:DescribeStateMachine",
    "states:DescribeExecution",
    "states:GetActivityTask",
    "states:GetExecutionHistory",
    "tax:GetTaxRegistration",
    "tax:ListTaxRegistrations",
    "transcribe:GetTranscriptionJob",
    "wisdom:GetContent",
}


def test_live_validated_disclosures_are_high():
    for action in LIVE_VALIDATED_HIGH_ACTIONS:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"


def test_live_validated_disclosures_have_single_action_findings():
    combinations = {tuple(combination) for combination in sensitive_combinations}
    for action in LIVE_VALIDATED_HIGH_ACTIONS:
        assert (action,) in combinations


def test_live_validated_disclosures_have_service_specific_evidence():
    for action in LIVE_VALIDATED_HIGH_ACTIONS:
        document = live_validated_disclosure_documentation[action]
        assert document.endswith(".md")
        assert document.startswith(
            (
                "aws-post-exploitation/",
                "aws-privilege-escalation/",
                "aws-services/",
            )
        )


def test_live_validated_appconfig_data_disclosure_requires_both_actions():
    combination = (
        "appconfig:StartConfigurationSession",
        "appconfig:GetLatestConfiguration",
    )
    combinations = {tuple(candidate) for candidate in sensitive_combinations}
    assert combination in combinations
    assert (combination[0],) not in combinations
    assert (combination[1],) not in combinations
    for action in combination:
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-appconfig-enum.md"
        )


def test_live_validated_lex_export_disclosure_requires_export_workflow():
    combination = ("lex:CreateExport", "lex:DescribeExport")
    combinations = {tuple(candidate) for candidate in sensitive_combinations}
    assert combination in combinations
    for action in combination:
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-lex-v2-enum.md"
        )


def test_live_validated_agentcore_api_key_disclosure_requires_full_chain():
    combination = (
        "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
        "bedrock-agentcore:GetResourceApiKey",
        "secretsmanager:GetSecretValue",
    )
    combinations = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert combination in combinations
    assert live_validated_disclosure_documentation[combination[0]] == (
        "aws-services/aws-bedrock-enum.md"
    )
    assert live_validated_disclosure_documentation[combination[1]] == (
        "aws-services/aws-bedrock-enum.md"
    )
    assert live_validated_disclosure_documentation[combination[2]] == (
        "aws-services/aws-secrets-manager-enum.md"
    )
