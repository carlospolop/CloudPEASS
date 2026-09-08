from CloudPEASS.permission_risk_classifier import classify_permission
from sensitive_permissions.aws import (
    live_validated_disclosure_documentation,
    sensitive_combinations,
)


LIVE_VALIDATED_HIGH_ACTIONS = {
    "account:GetContactInformation",
    "amplify:GetApp",
    "amplify:GetJob",
    "apigateway:GET",
    "appstream:CreateStreamingURL",
    "appconfig:GetHostedConfigurationVersion",
    "appsync:ListApiKeys",
    "autoscaling:DescribeLaunchConfigurations",
    "batch:DescribeJobDefinitions",
    "cloudformation:DescribeStacks",
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
    "codecommit:GetBlob",
    "codecommit:GetCommit",
    "codecommit:GetFile",
    "codecommit:GitPull",
    "cognito-idp:AdminGetUser",
    "cognito-idp:DescribeIdentityProvider",
    "cognito-idp:ListUsers",
    "cognito-idp:ListUsersInGroup",
    "dynamodb:BatchGetItem",
    "dynamodb:GetItem",
    "dynamodb:Query",
    "dynamodb:Scan",
    "dynamodb:TransactGetItems",
    "ec2:DescribeLaunchTemplateVersions",
    "ecr:GetDownloadUrlForLayer",
    "ecs:DescribeTaskDefinition",
    "emr-serverless:GetApplication",
    "events:ListTargetsByRule",
    "glue:GetConnection",
    "glue:GetJob",
    "glue:GetWorkflowRunProperties",
    "imagebuilder:GetComponent",
    "kinesisanalytics:DescribeApplication",
    "lambda:GetFunctionConfiguration",
    "lambda:GetLayerVersion",
    "logs:FilterLogEvents",
    "logs:GetLogEvents",
    "invoicing:BatchGetInvoiceProfile",
    "invoicing:GetInvoicePDF",
    "invoicing:ListInvoiceSummaries",
    "sagemaker:DescribeModel",
    "sagemaker:DescribeTrainingJob",
    "scheduler:GetSchedule",
    "pipes:DescribePipe",
    "ses:GetSuppressedDestination",
    "ses:ListSuppressedDestinations",
    "sns:ListSubscriptions",
    "sns:ListSubscriptionsByTopic",
    "ssm:GetParameterHistory",
    "ssm:GetDocument",
    "states:DescribeStateMachine",
    "tax:GetTaxRegistration",
    "tax:ListTaxRegistrations",
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
