from CloudPEASS.permission_risk_classifier import classify_permission
from sensitive_permissions.aws import (
    live_validated_disclosure_documentation,
    sensitive_combinations,
    tested_risk_documentation,
    very_sensitive_combinations,
)


LIVE_VALIDATED_HIGH_ACTIONS = {
    "account:GetContactInformation",
    "amplify:GetApp",
    "amplify:GetArtifactUrl",
    "amplify:GetJob",
    "apigateway:GET",
    "apigateway:PATCH",
    "athena:GetQueryExecution",
    "appstream:CreateStreamingURL",
    "appconfig:GetHostedConfigurationVersion",
    "appsync:GraphQL",
    "appsync:ListApiKeys",
    "autoscaling:DescribeLaunchConfigurations",
    "batch:DescribeJobDefinitions",
    "bedrock:Retrieve",
    "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
    "b2bi:GetProfile",
    "b2bi:GetTransformer",
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
    "budgets:ViewBudget",
    "aws-portal:ViewBilling",
    "aws-marketplace:SearchAgreements",
    "aws-marketplace:DescribeAgreement",
    "aws-marketplace:GetAgreementTerms",
    "codebuild:BatchGetBuilds",
    "codebuild:BatchGetProjects",
    "codeartifact:GetPackageVersionAsset",
    "codecommit:GetBlob",
    "codecommit:GetCommit",
    "codecommit:GetFile",
    "codecommit:GitPull",
    "codepipeline:PollForJobs",
    "chime:GetChannelMessage",
    "chime:ListChannelMessages",
    "connect:BatchDescribeDataTableValue",
    "connect:EvaluateDataTableValues",
    "connect:GetAttachedFile",
    "connect:GetContactAttributes",
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
    "datazone:GetEnvironmentCredentials",
    "ec2:DescribeLaunchTemplateVersions",
    "ec2:DescribeInstanceAttribute",
    "elasticloadbalancing:ModifyListener",
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
    "geo:GetDevicePosition",
    "geo:GetDevicePositionHistory",
    "greengrass:GetComponentVersionArtifact",
    "healthlake:ReadResource",
    "healthlake:SearchEverything",
    "healthlake:SearchWithGet",
    "healthlake:SearchWithPost",
    "imagebuilder:GetComponent",
    "iot:GetThingShadow",
    "iotwireless:GetWirelessDevice",
    "iotsitewise:BatchGetAssetPropertyAggregates",
    "iotsitewise:BatchGetAssetPropertyValue",
    "iotsitewise:BatchGetAssetPropertyValueHistory",
    "iotsitewise:GetAssetPropertyAggregates",
    "iotsitewise:GetAssetPropertyValue",
    "iotsitewise:GetAssetPropertyValueHistory",
    "iotsitewise:GetInterpolatedAssetPropertyValues",
    "ivschat:CreateChatToken",
    "kinesis:GetRecords",
    "kinesisanalytics:DescribeApplication",
    "kinesisvideo:GetClip",
    "kinesisvideo:GetDASHStreamingSessionURL",
    "kinesisvideo:GetHLSStreamingSessionURL",
    "kinesisvideo:GetImages",
    "kinesisvideo:GetMedia",
    "kinesisvideo:GetMediaForFragmentList",
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
    "rum:GetAppMonitorData",
    "route53domains:GetDomainDetail",
    "sdb:GetAttributes",
    "sdb:Select",
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
    "sts:GetFederationToken",
    "tax:GetTaxRegistration",
    "tax:ListTaxRegistrations",
    "transcribe:GetTranscriptionJob",
    "translate:GetParallelData",
    "translate:GetTerminology",
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


def test_live_validated_chime_message_disclosures():
    actions = ("chime:GetChannelMessage", "chime:ListChannelMessages")
    for action in actions:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-chime-sdk-enum.md"
        )


def test_live_validated_b2bi_disclosures():
    actions = ("b2bi:GetProfile", "b2bi:GetTransformer")
    for action in actions:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-b2b-data-interchange-enum.md"
        )


def test_live_validated_connect_data_disclosures():
    actions = (
        "connect:BatchDescribeDataTableValue",
        "connect:EvaluateDataTableValues",
        "connect:GetContactAttributes",
    )
    for action in actions:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-connect-enum.md"
        )


def test_live_validated_kinesis_video_disclosures():
    actions = (
        "kinesisvideo:GetClip",
        "kinesisvideo:GetDASHStreamingSessionURL",
        "kinesisvideo:GetHLSStreamingSessionURL",
        "kinesisvideo:GetImages",
        "kinesisvideo:GetMedia",
        "kinesisvideo:GetMediaForFragmentList",
    )
    for action in actions:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-kinesis-video-streams-enum.md"
        )


def test_live_validated_healthlake_fhir_disclosures():
    actions = (
        "healthlake:ReadResource",
        "healthlake:SearchEverything",
        "healthlake:SearchWithGet",
        "healthlake:SearchWithPost",
    )
    for action in actions:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-healthlake-enum.md"
        )


def test_live_validated_iot_sitewise_disclosures():
    actions = (
        "iotsitewise:BatchGetAssetPropertyAggregates",
        "iotsitewise:BatchGetAssetPropertyValue",
        "iotsitewise:BatchGetAssetPropertyValueHistory",
        "iotsitewise:GetAssetPropertyAggregates",
        "iotsitewise:GetAssetPropertyValue",
        "iotsitewise:GetAssetPropertyValueHistory",
        "iotsitewise:GetInterpolatedAssetPropertyValues",
    )
    for action in actions:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-iot-sitewise-enum.md"
        )


def test_live_validated_iot_twinmaker_read_requires_metadata_prerequisites():
    combination = (
        "iottwinmaker:GetWorkspace",
        "iottwinmaker:GetComponentType",
        "iottwinmaker:GetPropertyValue",
    )
    combinations = {tuple(candidate) for candidate in sensitive_combinations}
    assert combination in combinations
    for action in combination:
        assert (action,) not in combinations
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "low"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-iot-twinmaker-enum.md"
        )


def test_live_validated_simpledb_disclosures():
    actions = ("sdb:GetAttributes", "sdb:Select")
    for action in actions:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-simpledb-enum.md"
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


def test_live_validated_codedeploy_instance_profile_escalation_requires_chain():
    combination = (
        "codedeploy:CreateDeployment",
        "codedeploy:GetDeploymentConfig",
        "codedeploy:RegisterApplicationRevision",
    )
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert combination in critical
    for action in combination:
        assert (action,) not in critical
        assert live_validated_disclosure_documentation[action] == (
            "aws-privilege-escalation/aws-codedeploy-privesc/README.md"
        )
    assert classify_permission(
        "aws", combination[0], unknown_default="medium"
    ) == "medium"
    assert classify_permission(
        "aws", combination[1], unknown_default="medium"
    ) == "low"
    assert classify_permission(
        "aws", combination[2], unknown_default="medium"
    ) == "medium"


def test_live_validated_ssm_stored_automation_role_escalation():
    action = "ssm:StartAutomationExecution"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert tested_risk_documentation[action] == (
        "aws-privilege-escalation/aws-ssm-privesc/README.md"
    )
    assert live_validated_disclosure_documentation[action] == (
        "aws-privilege-escalation/aws-ssm-privesc/README.md"
    )


def test_live_validated_signer_lambda_code_signing_bypass():
    action = "signer:StartSigningJob"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert tested_risk_documentation[action] == (
        "aws-privilege-escalation/aws-lambda-privesc/README.md"
    )
    assert live_validated_disclosure_documentation[action] == (
        "aws-privilege-escalation/aws-lambda-privesc/README.md"
    )


def test_live_validated_eventbridge_target_attachment_escalation_requires_pair():
    combination = ("events:PutTargets", "events:PutEvents")
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert combination in critical
    for action in combination:
        assert (action,) not in critical
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "medium"
        assert live_validated_disclosure_documentation[action] == (
            "aws-privilege-escalation/aws-eventbridge-privesc/README.md"
        )


def test_live_validated_roles_anywhere_trust_anchor_replacement():
    action = "rolesanywhere:UpdateTrustAnchor"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-privilege-escalation/aws-sts-privesc/README.md"
    )


def test_live_validated_sagemaker_lifecycle_takeover():
    action = "sagemaker:UpdateNotebookInstanceLifecycleConfig"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-persistence/aws-sagemaker-persistence/README.md"
    )


def test_live_validated_secrets_manager_resource_policy_self_grant():
    action = "secretsmanager:PutResourcePolicy"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-privilege-escalation/aws-secrets-manager-privesc/README.md"
    )


def test_live_validated_dynamodb_resource_policy_self_grant():
    action = "dynamodb:PutResourcePolicy"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-privilege-escalation/aws-dynamodb-privesc/README.md"
    )


def test_live_validated_sqs_queue_policy_self_grant():
    action = "sqs:SetQueueAttributes"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-post-exploitation/aws-sqs-post-exploitation/README.md"
    )


def test_live_validated_sns_topic_policy_subscription_self_grant():
    action = "sns:SetTopicAttributes"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-post-exploitation/aws-sns-post-exploitation/README.md"
    )


def test_live_validated_iam_cross_user_access_key_takeover():
    action = "iam:CreateAccessKey"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-privilege-escalation/aws-iam-privesc/README.md"
    )


def test_live_validated_route53_existing_zone_record_takeover():
    action = "route53:ChangeResourceRecordSets"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-route53-enum.md"
    )


def test_live_validated_elbv2_listener_redirect_takeover():
    action = "elasticloadbalancing:ModifyListener"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-ec2-ebs-elb-ssm-vpc-and-vpn-enum/README.md"
    )


def test_live_validated_cognito_identity_public_role_credentials():
    action = "cognito-identity:UpdateIdentityPool"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-cognito-enum/cognito-identity-pools.md"
    )


def test_live_validated_ec2_security_group_replacement():
    action = "ec2:ModifyInstanceAttribute"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-privilege-escalation/aws-ec2-privesc/README.md"
    )


def test_live_validated_route53_domain_registration_disclosure():
    action = "route53domains:GetDomainDetail"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-privilege-escalation/aws-route53-domains-privesc/README.md"
    )


def test_live_validated_acm_private_key_export():
    action = "acm:ExportCertificate"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-certificate-manager-acm-and-private-certificate-authority-pca.md"
    )


def test_live_validated_eks_access_entry_cluster_admin_pair():
    combination = ("eks:CreateAccessEntry", "eks:AssociateAccessPolicy")
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert combination in critical
    for action in combination:
        assert live_validated_disclosure_documentation[action] == (
            "aws-post-exploitation/aws-eks-post-exploitation/README.md"
        )


def test_live_validated_opensearch_domain_policy_takeover():
    action = "es:UpdateDomainConfig"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-opensearch-enum.md"
    )


def test_live_validated_eks_pod_identity_token_exchange():
    action = "eks-auth:AssumeRoleForPodIdentity"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-post-exploitation/aws-eks-post-exploitation/README.md"
    )


def test_live_validated_redshift_single_action_database_credentials():
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    for action in (
        "redshift:GetClusterCredentials",
        "redshift:GetClusterCredentialsWithIAM",
    ):
        assert (action,) in critical
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "critical"
        assert live_validated_disclosure_documentation[action] == (
            "aws-privilege-escalation/aws-redshift-privesc/README.md"
        )


def test_live_validated_rds_password_takeover_and_iam_database_access():
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    high = {tuple(candidate) for candidate in sensitive_combinations}

    modify_action = "rds:ModifyDBInstance"
    assert (modify_action,) in critical
    assert classify_permission(
        "aws", modify_action, unknown_default="medium"
    ) == "critical"

    connect_action = "rds-db:connect"
    assert (connect_action,) in high
    assert classify_permission(
        "aws", connect_action, unknown_default="medium"
    ) == "high"

    for action in (modify_action, connect_action):
        assert live_validated_disclosure_documentation[action] == (
            "aws-privilege-escalation/aws-rds-privesc/README.md"
        )


def test_live_validated_amp_workspace_policy_self_grant():
    action = "aps:PutResourcePolicy"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-managed-prometheus-enum.md"
    )


def test_live_validated_cloudwatch_dashboard_disclosure():
    action = "cloudwatch:GetDashboard"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-security-and-detection-services/aws-cloudwatch-enum.md"
    )


def test_live_validated_budget_disclosure_uses_view_budget_iam_action():
    action = "budgets:ViewBudget"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-security-and-detection-services/aws-cost-explorer-enum.md"
    )


def test_live_validated_legacy_billing_console_permission_discloses_credits():
    action = "aws-portal:ViewBilling"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-security-and-detection-services/aws-cost-explorer-enum.md"
    )


def test_live_validated_marketplace_agreement_disclosures_are_independent():
    actions = (
        "aws-marketplace:SearchAgreements",
        "aws-marketplace:DescribeAgreement",
        "aws-marketplace:GetAgreementTerms",
    )
    high = {tuple(candidate) for candidate in sensitive_combinations}
    for action in actions:
        assert (action,) in high
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-marketplace-enum.md"
        )


def test_live_validated_ecr_public_repository_policy_self_grant():
    action = "ecr-public:SetRepositoryPolicy"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-privilege-escalation/aws-ecr-privesc/README.md"
    )


def test_live_validated_datasync_delegated_copy_requires_destination_access():
    action = "datasync:StartTaskExecution"
    combination = (action, "s3:GetObject")
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert combination in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-datasync-enum.md"
    )


def test_live_validated_grafana_admin_token_minting():
    actions = (
        "grafana:CreateWorkspaceApiKey",
        "grafana:CreateWorkspaceServiceAccountToken",
    )
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    for action in actions:
        assert (action,) in critical
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "critical"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-managed-grafana-enum.md"
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
