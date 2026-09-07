from CloudPEASS.permission_risk_classifier import classify_permission
from sensitive_permissions.aws import (
    live_validated_disclosure_documentation,
    sensitive_combinations,
)


LIVE_VALIDATED_HIGH_ACTIONS = {
    "apigateway:GET",
    "cloudfront:GetDistribution",
    "cloudfront:GetDistributionConfig",
    "cloudfront:ListDistributions",
    "codebuild:BatchGetBuilds",
    "codebuild:BatchGetProjects",
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
    "lambda:GetFunctionConfiguration",
    "lambda:GetLayerVersion",
    "logs:FilterLogEvents",
    "logs:GetLogEvents",
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
