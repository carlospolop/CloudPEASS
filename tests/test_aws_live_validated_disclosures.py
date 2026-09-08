from CloudPEASS.permission_risk_classifier import classify_permission
from sensitive_permissions.aws import (
    live_validated_disclosure_documentation,
    sensitive_combinations,
    very_sensitive_combinations,
)


LIVE_VALIDATED_HIGH_ACTIONS = {
    "account:GetContactInformation",
    "amplify:GetApp",
    "amplify:GetArtifactUrl",
    "amplify:GetJob",
    "apigateway:GET",
    "athena:GetQueryExecution",
    "appstream:CreateStreamingURL",
    "appconfig:GetHostedConfigurationVersion",
    "appsync:GraphQL",
    "appsync:ListApiKeys",
    "autoscaling:DescribeLaunchConfigurations",
    "batch:DescribeJobDefinitions",
    "bedrock:Retrieve",
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
    "connect:GetAttachedFile",
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
    "ivschat:CreateChatToken",
    "kinesis:GetRecords",
    "kinesisanalytics:DescribeApplication",
    "lambda:GetFunctionConfiguration",
    "lambda:GetLayerVersion",
    "logs:FilterLogEvents",
    "logs:GetLogRecord",
    "logs:GetLogEvents",
    "logs:GetQueryResults",
    "medical-imaging:GetImageFrame",
    "medical-imaging:GetImageSetMetadata",
    "omics:GetReadSet",
    "invoicing:BatchGetInvoiceProfile",
    "invoicing:GetInvoicePDF",
    "invoicing:ListInvoiceSummaries",
    "sagemaker:DescribeModel",
    "sagemaker:DescribeTrainingJob",
    "s3:GetDataAccess",
    "s3vectors:GetVectors",
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


def test_live_validated_iot_mqtt_read_requires_full_broker_path():
    combination = ("iot:Connect", "iot:Subscribe", "iot:Receive")
    combinations = {tuple(candidate) for candidate in sensitive_combinations}
    assert combination in combinations
    for action in combination:
        assert (action,) not in combinations
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-iot-core-enum.md"
        )


def test_live_validated_backup_restore_requires_passrole():
    combination = ("backup:StartRestoreJob", "iam:PassRole")
    combinations = {tuple(candidate) for candidate in sensitive_combinations}
    assert combination in combinations
    assert (combination[0],) not in combinations
    assert classify_permission(
        "aws", combination[0], unknown_default="medium"
    ) == "medium"
    assert classify_permission(
        "aws", combination[1], unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[combination[0]] == (
        "aws-post-exploitation/aws-backup-post-exploitation/README.md"
    )


def test_live_validated_backup_vault_policy_self_grant_and_deletion():
    policy_action = "backup:PutBackupVaultAccessPolicy"
    deletion_action = "backup:DeleteRecoveryPoint"
    assert [policy_action] in very_sensitive_combinations
    assert [deletion_action] in sensitive_combinations
    assert classify_permission(
        "aws", policy_action, unknown_default="medium"
    ) == "critical"
    assert classify_permission(
        "aws", deletion_action, unknown_default="medium"
    ) == "high"


def test_live_validated_backup_access_point_requires_full_policy_chain():
    combination = (
        "backup:CreateBackupAccessPoint",
        "backup:DescribeBackupAccessPoint",
        "s3:CreateAccessPoint",
        "s3:GetAccessPoint",
        "s3:PutAccessPointPolicy",
    )
    sensitive = {tuple(candidate) for candidate in sensitive_combinations}
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert combination in sensitive
    assert ("s3:PutAccessPointPolicy",) in critical
    assert ("backup:CreateBackupAccessPoint",) not in sensitive
    assert ("backup:DescribeBackupAccessPoint",) not in sensitive
    assert classify_permission(
        "aws", "backup:CreateBackupAccessPoint", unknown_default="medium"
    ) == "medium"
    assert classify_permission(
        "aws", "backup:DescribeBackupAccessPoint", unknown_default="medium"
    ) == "low"
    assert classify_permission(
        "aws", "s3:PutAccessPointPolicy", unknown_default="medium"
    ) == "critical"
    for action in combination:
        assert live_validated_disclosure_documentation[action] == (
            "aws-post-exploitation/aws-backup-post-exploitation/README.md"
        )


def test_live_validated_service_catalog_launch_role_escalation_requires_pair():
    combination = (
        "servicecatalog:CreateProvisioningArtifact",
        "servicecatalog:ProvisionProduct",
    )
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert combination in critical
    assert (combination[0],) not in critical
    assert (combination[1],) not in critical
    for action in combination:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "medium"
        assert live_validated_disclosure_documentation[action] == (
            "aws-privilege-escalation/aws-service-catalog-privesc/README.md"
        )


def test_live_validated_image_builder_wildcard_component_escalation_requires_pair():
    combination = (
        "imagebuilder:CreateComponent",
        "imagebuilder:StartImagePipelineExecution",
    )
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert combination in critical
    assert (combination[0],) not in critical
    assert (combination[1],) not in critical
    for action in combination:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "medium"
        assert live_validated_disclosure_documentation[action] == (
            "aws-privilege-escalation/aws-ec2-image-builder-privesc/README.md"
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


def test_live_validated_s3_vectors_plaintext_disclosure_paths():
    combinations = {tuple(candidate) for candidate in sensitive_combinations}
    assert ("s3vectors:GetVectors",) in combinations
    assert ("s3vectors:ListVectors", "s3vectors:GetVectors") in combinations
    assert ("s3vectors:QueryVectors", "s3vectors:GetVectors") in combinations
    for action in (
        "s3vectors:GetVectors",
        "s3vectors:ListVectors",
        "s3vectors:QueryVectors",
    ):
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-bedrock-enum.md"
        )
