import json
from datetime import date, timedelta
from types import SimpleNamespace
from urllib.parse import quote

import AWSPEAS as awspeas_module
from botocore.exceptions import ClientError

from AWSPEAS import AWSPEASS, UNKNOWN_RESOURCE_SCOPE, build_parser
from src.CloudPEASS.cloudpeass import CloudPEASS, CloudResource
from src.aws.awsbruteforce import AWSBruteForce
from src.aws.awsmanagedpoliciesguesser import AWSManagedPoliciesGuesser


def bare_awspeass():
    instance = object.__new__(AWSPEASS)
    instance.action_catalog = {
        "iam": ["GetUser", "DeleteUser"],
        "s3": ["GetObject", "PutObject"],
    }
    instance.action_catalog_source = "test"
    instance.policy_conditions = set()
    instance.policy_notes = []
    instance.permissions_boundary_arns = set()
    return instance


def test_parse_principal_variants_and_paths():
    parse = AWSPEASS.parse_principal
    assert parse("arn:aws:iam::123456789012:user/team/alice") == ("user", "alice")
    assert parse("arn:aws:iam::123456789012:role/team/app-role") == ("role", "app-role")
    assert parse("arn:aws:sts::123456789012:assumed-role/app-role/session") == ("role", "app-role")
    assert parse("arn:aws:sts::123456789012:federated-user/red/team") == (
        "federated-user",
        "red/team",
    )
    assert parse("arn:aws:iam::123456789012:root") == ("root", "root")


def test_admin_detection_requires_unrestricted_global_wildcard():
    detect = AWSPEASS._is_admin_aws
    assert detect(["*"], [], unrestricted=True)
    assert detect(["*:*"], [], unrestricted=True)
    assert not detect(["iam:*"], [], unrestricted=True)
    assert not detect(["s3:Get*"], [], unrestricted=True)
    assert not detect(["*"], ["ec2:RunInstances"], unrestricted=True)
    assert not detect(["*"], [], unrestricted=False)


def test_policy_parser_preserves_resource_conditions_denies_and_notaction():
    instance = bare_awspeass()
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": ["arn:aws:s3:::example", "arn:aws:s3:::example/*"],
                "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
            },
            {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
            {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
        ],
    }

    scopes, _, _, unrestricted = instance._parse_policy_documents([("inline", policy, False)])

    assert scopes["arn:aws:s3:::example"]["allow"] == {"s3:GetObject", "s3:ListBucket"}
    assert "s3:DeleteObject" in scopes["arn:aws:s3:::example"]["deny"]
    assert "StringEquals" in instance.policy_conditions
    assert "s3:GetObject" in scopes["*"]["allow"]
    assert "iam:GetUser" not in scopes["*"]["allow"]
    assert not unrestricted


def test_policy_document_accepts_url_encoded_json():
    document = {"Statement": {"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}}
    encoded = quote(json.dumps(document))
    assert AWSPEASS._policy_document(encoded) == document


def test_permissions_boundary_prevents_admin_classification():
    instance = bare_awspeass()
    identity = {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
    boundary = {"Statement": {"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}}
    _, boundary_allow, _, unrestricted = instance._parse_policy_documents(
        [("admin", identity, False), ("boundary", boundary, True)]
    )
    assert boundary_allow == {"s3:Get*"}
    assert not unrestricted


def test_help_parser_handles_ascii_and_unicode_bullets():
    output = [
        "AVAILABLE COMMANDS",
        "o list-things",
        "* describe-things",
        "• get-thing",
        "+ create-thing",
        "SEE ALSO",
    ]
    assert AWSBruteForce._help_entries(output, "AVAILABLE COMMANDS") == [
        "list-things",
        "describe-things",
        "get-thing",
        "create-thing",
    ]
    overstruck = ["AVAILABLE COMMANDS", "o g\bge\bet\bt-t\bth\bhi\bin\bng\bg", "SEE ALSO"]
    assert AWSBruteForce._help_entries(overstruck, "AVAILABLE COMMANDS") == ["get-thing"]


def test_required_cli_options_handle_multiple_delimiters():
    unix = "aws: error: the following arguments are required: --bucket, --key"
    wrapped = "arguments are required: --role-name --policy-name\r\n"
    assert AWSBruteForce._required_options(unix) == ["--bucket", "--key"]
    assert AWSBruteForce._required_options(wrapped) == ["--role-name", "--policy-name"]


def test_sensitive_read_probes_use_valid_safe_placeholders():
    placeholder = AWSBruteForce._placeholder_for
    assert placeholder(
        "--selector", "invoicing", "list-invoice-summaries"
    ) == "ResourceType=INVOICE_ID,Value=CloudPEASSProbe"
    assert placeholder(
        "--email-address", "sesv2", "get-suppressed-destination"
    ) == "cloudpeass-probe@example.invalid"
    assert placeholder(
        "--granularity", "ce", "get-cost-and-usage"
    ) == "DAILY"
    assert placeholder("--metrics", "ce", "get-cost-and-usage") == "UnblendedCost"
    assert placeholder("--time-period", "ce", "get-cost-and-usage") == (
        f"Start={(date.today() - timedelta(days=1)).isoformat()},"
        f"End={date.today().isoformat()}"
    )
    assert placeholder(
        "--workspace-id", "workspaces", "describe-workspace-snapshots"
    ) == "ws-00000000"
    assert placeholder(
        "--portal-id", "workspaces-web", "list-sessions"
    ) == "00000000-0000-0000-0000-000000000000"
    assert placeholder(
        "--session-id", "workspaces-web", "get-session"
    ) == "00000000-0000-0000-0000-000000000000"
    assert placeholder(
        "--id", "workspaces-thin-client", "get-device"
    ) == "000000000000000000000000"
    assert placeholder(
        "--id", "workspaces-thin-client", "get-environment"
    ) == "000000000"
    assert placeholder(
        "--workspace-instance-id",
        "workspaces-instances",
        "get-workspace-instance",
    ) == "wsinst-00000000"
    assert placeholder(
        "--organization-id", "workmail", "list-users"
    ) == "m-00000000000000000000000000000000"
    # A fabricated pool ID returned AccessDenied even to the validation admin,
    # so it must not be treated as permission evidence.
    assert placeholder(
        "--pool-id", "workspaces", "describe-workspaces-pool-sessions"
    ) == "CloudPEASSProbe"


def test_caller_account_id_uses_safe_argv_and_validates_output(monkeypatch):
    instance = object.__new__(AWSBruteForce)
    instance.aws_cli = "/usr/bin/aws"
    instance.profile_uses_environment_credentials = False
    instance.access_key_id = None
    instance.secret_access_key = None
    instance.session_token = None
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        return SimpleNamespace(returncode=0, stdout=b"123456789012\n")

    monkeypatch.setattr("src.aws.awsbruteforce.subprocess.run", fake_run)

    assert instance._caller_account_id("profile name", "us-east-1") == "123456789012"
    assert seen["command"][-6:] == [
        "sts",
        "get-caller-identity",
        "--query",
        "Account",
        "--output",
        "text",
    ]


def test_token_minting_get_commands_are_never_probed(monkeypatch):
    instance = object.__new__(AWSBruteForce)
    instance._get_aws_help = lambda service: [
        "AVAILABLE COMMANDS",
        "o get-caller-identity",
        "o get-delegated-access-token",
        "o get-federation-token",
        "o get-session-token",
        "SEE ALSO",
    ]
    assert instance.get_commands_for_service("sts") == ["get-caller-identity"]


def test_cli_command_is_an_argv_list_not_a_shell_string():
    instance = object.__new__(AWSBruteForce)
    instance.aws_cli = "/usr/bin/aws"
    command = instance._build_command("profile; touch /tmp/pwned", "us-east-1", "s3api", "list-buckets", [])
    assert command == [
        "/usr/bin/aws",
        "--cli-connect-timeout",
        "5",
        "--cli-read-timeout",
        "10",
        "--profile",
        "profile; touch /tmp/pwned",
        "--region",
        "us-east-1",
        "s3api",
        "list-buckets",
    ]


def test_shared_grouping_retains_explicit_denies():
    resource = CloudResource(
        resource_id="arn:aws:iam::123456789012:root",
        name="account",
        resource_type="account",
        permissions=["s3:GetObject"],
        deny_perms=["s3:DeleteObject"],
    )
    grouped = CloudPEASS.group_resources_by_permissions([resource])
    permissions = next(iter(grouped))
    assert permissions == frozenset({"s3:GetObject", "-s3:DeleteObject"})


def test_parser_allows_default_credential_chain_and_optional_region():
    args = build_parser().parse_args([])
    assert args.profile is None
    assert args.access_key_id is None
    assert args.region is None


def test_parser_accepts_repeatable_resource_arns():
    args = build_parser().parse_args([
        "--resource-arn", "arn:aws:s3:::one",
        "--resource-arn", "arn:aws:s3:::two,arn:aws:s3:::three",
    ])
    assert args.resource_arn == [
        "arn:aws:s3:::one",
        "arn:aws:s3:::two,arn:aws:s3:::three",
    ]


def test_complete_catalog_simulation_is_compacted_to_admin_wildcard():
    instance = bare_awspeass()
    instance.principal_type = "user"
    instance.entity_arn = "arn:aws:iam::123456789012:user/alice"
    instance.num_threads = 2
    instance._paginate_iam = lambda *args, **kwargs: ([], True)
    instance._all_actions = lambda: {"iam:GetUser", "s3:GetObject"}
    instance.simulate_batch = lambda actions: (set(actions), True)

    permissions, complete = instance.simulate_permissions(batch_size=1)

    assert complete
    assert permissions == ["*"]
    assert instance.simulation_is_admin


def test_public_aws_managed_policy_fallback_is_permissionless_and_partial():
    instance = bare_awspeass()
    instance.public_managed_policy_actions = {
        "ReadOnlyAccess": ["s3:GetObject", "ec2:DescribeInstances"]
    }
    document = instance._public_managed_policy_document(
        "arn:aws:iam::aws:policy/ReadOnlyAccess"
    )
    assert document["Statement"][0]["Action"] == [
        "s3:GetObject",
        "ec2:DescribeInstances",
    ]
    assert document["Statement"][0]["Resource"] == UNKNOWN_RESOURCE_SCOPE
    assert instance._public_managed_policy_document(
        "arn:aws:iam::123456789012:policy/ReadOnlyAccess"
    ) == {}


def test_s3api_and_access_analyzer_permissions_are_normalized():
    instance = object.__new__(AWSBruteForce)
    assert instance.transform_command("s3api:ListBuckets") == "s3:ListAllMyBuckets"
    assert instance.transform_command("s3api:GetBucketAcl") == "s3:GetBucketAcl"
    assert instance.transform_command("accessanalyzer:ListAnalyzers") == (
        "access-analyzer:ListAnalyzers"
    )
    assert instance.transform_command("codedeploy:ListApplications") == (
        "codedeploy:ListApplications"
    )
    assert instance.transform_command("taxsettings:GetTaxRegistration") == (
        "tax:GetTaxRegistration"
    )
    assert instance.permission_for_command("s3api", "get-bucket-acl") == "s3:GetBucketAcl"
    assert instance.permission_for_command(
        "cloudfront", "list-distributions-by-web-acl-id"
    ) == "cloudfront:ListDistributionsByWebACLId"
    assert instance.permission_for_command("deploy", "list-applications") == (
        "codedeploy:ListApplications"
    )


def test_managed_policy_inference_is_case_insensitive_and_combines_policies():
    guesser = AWSManagedPoliciesGuesser({"S3:listallmybuckets", "EC2:describeinstances"})
    guesser.fetch_managed_policies = lambda url: [
        {"name": "StorageRead", "effective_action_names": ["s3:ListAllMyBuckets"]},
        {"name": "ComputeRead", "effective_action_names": ["ec2:DescribeInstances"]},
    ]
    result = guesser.guess_permissions()
    assert result[0]["policies"] == ["ComputeRead", "StorageRead"]


def test_managed_policy_inference_accepts_new_live_read_operations():
    guesser = AWSManagedPoliciesGuesser({"newservice:GetNewThing"})
    guesser.fetch_managed_policies = lambda url: [{
        "name": "NewReadPolicy", "effective_action_names": ["newservice:GetNewThing"]
    }]
    assert guesser.guess_permissions()[0]["policies"] == ["NewReadPolicy"]


def test_future_credential_and_token_getters_are_blocked():
    blocked = AWSBruteForce._is_blocked_command
    assert blocked("future-service", "get-project-credentials")
    assert blocked("future-service", "get-new-access-token")
    assert not blocked("future-service", "get-token-balance")
    assert not blocked("iam", "get-credential-report")


def test_profile_environment_is_sanitized_unless_profile_chain_requires_it(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "ambient")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/custom/config")
    instance = object.__new__(AWSBruteForce)
    instance.profile_uses_environment_credentials = False
    clean = instance._build_env("selected-profile")
    assert "AWS_ACCESS_KEY_ID" not in clean
    assert clean["AWS_CONFIG_FILE"] == "/custom/config"

    instance.profile_uses_environment_credentials = True
    preserved = instance._build_env("environment-source-profile")
    assert preserved["AWS_ACCESS_KEY_ID"] == "ambient"


def test_profile_environment_source_is_detected_through_source_chain():
    profiles = {
        "target": {"source_profile": "base"},
        "base": {"credential_source": "Environment"},
        "cycle-a": {"source_profile": "cycle-b"},
        "cycle-b": {"source_profile": "cycle-a"},
    }
    assert AWSPEASS._profile_chain_uses_environment(profiles, "target")
    assert not AWSPEASS._profile_chain_uses_environment(profiles, "cycle-a")


def test_malformed_inline_policy_marks_direct_enumeration_partial():
    instance = bare_awspeass()
    instance.principal_type = "role"
    instance.principal_name = "app"
    instance.principal_arn = "arn:aws:sts::123456789012:assumed-role/app/session"
    instance.identity = {"Account": "123456789012"}

    def call(operation, **kwargs):
        if operation == "get_role":
            return {"Role": {"Arn": "arn:aws:iam::123456789012:role/app"}}, True
        if operation == "get_role_policy":
            return {"PolicyDocument": None}, True
        raise AssertionError(operation)

    def paginate(operation, result_key, **kwargs):
        if operation == "list_role_policies":
            return ["broken"], True
        if operation == "list_attached_role_policies":
            return [], True
        raise AssertionError(operation)

    instance._call_iam = call
    instance._paginate_iam = paginate
    documents, complete = instance._collect_direct_policies()
    assert documents == []
    assert not complete
    assert any("malformed inline role policy" in note for note in instance.policy_notes)


def test_iam_user_self_lookup_omits_username_for_permission_friendly_access():
    instance = bare_awspeass()
    instance.principal_type = "user"
    instance.principal_name = "alice"
    instance.principal_arn = "arn:aws:iam::123456789012:user/alice"
    calls = []

    def call(operation, **kwargs):
        calls.append((operation, kwargs))
        assert operation == "get_user"
        return {"User": {"Arn": instance.principal_arn}}, True

    instance._call_iam = call
    instance._paginate_iam = lambda *args, **kwargs: ([], True)
    documents, complete = instance._collect_direct_policies()
    assert documents == []
    assert complete
    assert calls == [("get_user", {})]


def test_malformed_action_catalog_uses_offline_botocore_fallback(monkeypatch):
    class Response:
        text = "[]"

        @staticmethod
        def raise_for_status():
            return None

    instance = bare_awspeass()
    instance.action_catalog = None
    instance.debug = False
    instance._botocore_action_catalog = lambda: {"s3": ["ListAllMyBuckets"]}
    monkeypatch.setattr(awspeas_module.requests, "get", lambda *args, **kwargs: Response())

    assert instance.download_aws_permissions() == {"s3": ["ListAllMyBuckets"]}
    assert "offline fallback" in instance.action_catalog_source


def test_offline_catalog_keeps_normalized_iam_service_prefix():
    class Model:
        metadata = {"signingName": "monitoring"}
        endpoint_prefix = "monitoring"
        operation_names = ["ListMetrics"]

    class LowLevel:
        @staticmethod
        def get_service_model(service):
            assert service == "cloudwatch"
            return Model()

    class Session:
        _session = LowLevel()

        @staticmethod
        def get_available_services():
            return ["cloudwatch"]

    instance = bare_awspeass()
    instance.session = Session()
    instance.AWSBruteForce = object.__new__(AWSBruteForce)
    assert instance._botocore_action_catalog() == {"cloudwatch": ["ListMetrics"]}


def test_malformed_snapshot_inline_policy_is_partial():
    class Paginator:
        def paginate(self, **kwargs):
            yield {
                "RoleDetailList": [{
                    "RoleName": "app",
                    "Arn": "arn:aws:iam::123456789012:role/app",
                    "RolePolicyList": [{"PolicyName": "broken", "PolicyDocument": None}],
                }]
            }

    class IAM:
        def get_paginator(self, operation):
            return Paginator()

    instance = bare_awspeass()
    instance.iam_client = IAM()
    instance.principal_type = "role"
    instance.principal_name = "app"
    instance.entity_arn = None
    instance.iam_errors = []
    documents, complete = instance._collect_account_authorization_fallback()
    assert documents == []
    assert not complete


def test_evidence_sources_are_not_union_merged_for_the_same_resource():
    resources = [
        CloudResource("account", "account", "account", ["iam:GetUser"], evidence="static"),
        CloudResource("account", "account", "account", ["s3:GetObject"], evidence="live"),
    ]

    grouped = CloudPEASS.group_resources_by_permissions(resources)

    assert set(grouped) == {frozenset({"iam:GetUser"}), frozenset({"s3:GetObject"})}


def test_denies_are_reported_separately_and_not_risk_classified(monkeypatch):
    instance = CloudPEASS([], [], "AWS", 1)
    seen = []
    monkeypatch.setattr(instance, "analyze_sensitive_combinations", lambda perms: {
        "very_sensitive_perms": set(), "sensitive_perms": set()
    })

    def classify(perms):
        seen.append(set(perms))
        return {"critical": set(), "high": set(), "medium": set(), "low": set(perms)}

    monkeypatch.setattr(instance, "categorize_permissions_from_catalog", classify)
    result = instance.analyze_group(
        frozenset({"s3:GetObject", "-s3:DeleteObject"}),
        [CloudResource("account", "account", "account", ["s3:GetObject"], ["s3:DeleteObject"])],
    )

    assert seen == [{"s3:GetObject"}]
    assert result["deny_permissions"] == ["s3:DeleteObject"]
    assert "-s3:DeleteObject" not in result["permissions_cat"]["low"]


def test_account_snapshot_is_partial_when_attached_policy_document_is_missing():
    class Paginator:
        def paginate(self, **kwargs):
            assert "Role" in kwargs["Filter"]
            yield {
                "RoleDetailList": [{
                    "RoleName": "app",
                    "Arn": "arn:aws:iam::123456789012:role/team/app",
                    "AttachedManagedPolicies": [{
                        "PolicyArn": "arn:aws:iam::123456789012:policy/missing"
                    }],
                }],
                "Policies": [],
            }

    class IAM:
        def get_paginator(self, operation):
            assert operation == "get_account_authorization_details"
            return Paginator()

    instance = bare_awspeass()
    instance.iam_client = IAM()
    instance.principal_type = "role"
    instance.principal_name = "app"
    instance.entity_arn = None
    instance.iam_errors = []

    documents, complete = instance._collect_account_authorization_fallback()

    assert documents == []
    assert not complete
    assert instance.entity_arn.endswith("role/team/app")


def test_simulator_retries_throttling_and_follows_markers(monkeypatch):
    throttled = ClientError(
        {"Error": {"Code": "ThrottlingException", "Message": "slow down"}},
        "SimulatePrincipalPolicy",
    )

    class IAM:
        def __init__(self):
            self.calls = []

        def simulate_principal_policy(self, **kwargs):
            self.calls.append(kwargs)
            if len(self.calls) == 1:
                raise throttled
            if "Marker" not in kwargs:
                return {
                    "EvaluationResults": [{"EvalActionName": "s3:GetObject", "EvalDecision": "allowed"}],
                    "IsTruncated": True,
                    "Marker": "next",
                }
            return {
                "EvaluationResults": [{"EvalActionName": "iam:GetUser", "EvalDecision": "allowed"}],
                "IsTruncated": False,
            }

    instance = bare_awspeass()
    instance.iam_client = IAM()
    instance.entity_arn = "arn:aws:iam::123456789012:user/alice"
    instance.debug = False
    sleeps = []
    monkeypatch.setattr(awspeas_module.time, "sleep", sleeps.append)

    allowed, complete = instance.simulate_batch(["s3:GetObject", "iam:GetUser"])

    assert complete
    assert allowed == {"s3:GetObject", "iam:GetUser"}
    assert sleeps == [1]
    assert instance.iam_client.calls[-1]["Marker"] == "next"


def test_simulator_stops_repeated_pagination_marker_as_partial():
    class IAM:
        @staticmethod
        def simulate_principal_policy(**kwargs):
            return {
                "EvaluationResults": [{
                    "EvalActionName": "s3:GetObject", "EvalDecision": "allowed"
                }],
                "IsTruncated": True,
                "Marker": "same-marker",
            }

    instance = bare_awspeass()
    instance.iam_client = IAM()
    instance.entity_arn = "arn:aws:iam::123456789012:user/alice"
    instance.debug = False
    allowed, complete = instance.simulate_batch(["s3:GetObject"])
    assert allowed == {"s3:GetObject"}
    assert not complete


def test_secretsmanager_resources_are_discovered_for_scoped_simulation():
    class Paginator:
        @staticmethod
        def paginate():
            yield {"SecretList": [
                {"ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:flag-one"},
                {"ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:flag-two"},
            ]}

    class SecretsManager:
        @staticmethod
        def get_paginator(operation):
            assert operation == "list_secrets"
            return Paginator()

    class Session:
        @staticmethod
        def client(service, region_name=None):
            assert service == "secretsmanager"
            assert region_name == "us-east-1"
            return SecretsManager()

    instance = bare_awspeass()
    instance.session = Session()
    instance.region = "us-east-1"
    instance.debug = False
    instance.resource_arns = {"arn:aws:s3:::known-bucket"}

    resources = instance._discover_simulation_resources(["secretsmanager:ListSecrets"])

    assert resources == [
        "arn:aws:s3:::known-bucket",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:flag-one",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:flag-two",
    ]
    assert any("Discovered 2 Secrets Manager ARN" in note for note in instance.policy_notes)


def test_resource_specific_simulator_keeps_permissions_per_arn():
    first = "arn:aws:secretsmanager:us-east-1:123456789012:secret:flag-one"
    second = "arn:aws:secretsmanager:us-east-1:123456789012:secret:flag-two"

    class IAM:
        @staticmethod
        def simulate_principal_policy(**kwargs):
            assert kwargs["ResourceArns"] == [first, second]
            return {
                "EvaluationResults": [
                    {
                        "EvalActionName": "secretsmanager:GetSecretValue",
                        "EvalResourceName": first,
                        "EvalDecision": "allowed",
                    },
                    {
                        "EvalActionName": "secretsmanager:DescribeSecret",
                        "EvalResourceName": "*",
                        "EvalDecision": "implicitDeny",
                        "ResourceSpecificResults": [
                            {"EvalResourceName": first, "EvalResourceDecision": "implicitDeny"},
                            {"EvalResourceName": second, "EvalResourceDecision": "allowed"},
                        ],
                    },
                ],
                "IsTruncated": False,
            }

    instance = bare_awspeass()
    instance.iam_client = IAM()
    instance.entity_arn = "arn:aws:iam::123456789012:user/alice"
    instance.debug = False

    allowed, complete = instance.simulate_resource_batch(
        ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
        [first, second],
    )

    assert complete
    assert allowed == {
        first: {"secretsmanager:GetSecretValue"},
        second: {"secretsmanager:DescribeSecret"},
    }


def test_expired_cli_credentials_stop_remaining_probes(monkeypatch):
    instance = AWSBruteForce(
        False, "us-east-1", None, [], 1, "AKIAEXAMPLE", "secret"
    )
    instance.aws_cli = "/usr/bin/aws"
    calls = []

    class Result:
        returncode = 255
        stdout = b""
        stderr = b"ExpiredToken: the security token has expired"

    def run(*args, **kwargs):
        calls.append(args)
        return Result()

    monkeypatch.setattr("src.aws.awsbruteforce.subprocess.run", run)
    instance.run_command(None, "us-east-1", "sts", "get-caller-identity")
    instance.run_command(None, "us-east-1", "s3api", "list-buckets")
    assert len(calls) == 1
    assert instance.stop_event.is_set()
    assert instance.probe_stats["credential_errors"] == 1


def test_static_admin_is_validated_by_simulator_instead_of_ending_early():
    instance = bare_awspeass()
    instance.identity = {"Account": "123456789012"}
    instance.principal_arn = "arn:aws:iam::123456789012:user/alice"
    instance.principal_type = "user"
    instance.principal_name = "alice"
    instance.is_session_principal = False
    instance.get_caller_identity = lambda: instance.principal_arn
    instance.get_principal_permissions = lambda: {
        "allow": ["*"], "deny": [], "scopes": {}, "unrestricted_admin": True,
        "complete": True, "documents_found": 1,
    }
    calls = []

    def simulate():
        calls.append("simulate")
        instance.simulation_is_admin = True
        return ["*"], True

    instance.simulate_permissions = simulate
    instance.AWSBruteForce = type("BF", (), {
        "brute_force_permissions": lambda self: (_ for _ in ()).throw(AssertionError("unexpected probe"))
    })()
    instance.skip_iam_policies = False
    instance.skip_simulation = False
    instance.skip_bruteforce = False
    instance.bruteforce_always = False
    instance.skip_managed_policies_guess = True
    instance.iam_visibility = "complete"
    instance.iam_errors = []
    instance.principal_info = {}

    resources = instance.get_resources_and_permissions()

    assert calls == ["simulate"]
    assert any(resource.is_admin and resource.extra_fields["evidence"] == "IAM policy simulator" for resource in resources)


def test_assumed_role_session_uses_live_probe_even_after_base_role_simulation():
    instance = bare_awspeass()
    instance.identity = {"Account": "123456789012"}
    instance.principal_arn = "arn:aws:sts::123456789012:assumed-role/app/session"
    instance.principal_type = "role"
    instance.principal_name = "app"
    instance.is_session_principal = True
    instance.get_caller_identity = lambda: instance.principal_arn
    instance.get_principal_permissions = lambda: {
        "allow": ["s3:GetObject"], "deny": [], "scopes": {}, "unrestricted_admin": False,
        "complete": True, "documents_found": 1,
    }
    instance.simulate_permissions = lambda: (["s3:GetObject"], True)
    instance.simulation_is_admin = False
    instance.AWSBruteForce = type("BF", (), {
        "brute_force_permissions": lambda self: ["sts:GetCallerIdentity"]
    })()
    instance.skip_iam_policies = False
    instance.skip_simulation = False
    instance.skip_bruteforce = False
    instance.bruteforce_always = False
    instance.skip_managed_policies_guess = True
    instance.iam_visibility = "complete"
    instance.iam_errors = []
    instance.principal_info = {}

    resources = instance.get_resources_and_permissions()

    assert any(resource.extra_fields["evidence"] == "live read-only probes" for resource in resources)
    assert not any(resource.is_admin for resource in resources)


def test_root_metadata_is_complete_and_explicit_live_validation_is_honored():
    instance = bare_awspeass()
    instance.identity = {"Account": "123456789012"}
    instance.principal_arn = "arn:aws:iam::123456789012:root"
    instance.principal_type = "root"
    instance.principal_name = "root"
    instance.get_caller_identity = lambda: instance.principal_arn
    instance.AWSBruteForce = type("BF", (), {
        "brute_force_permissions": lambda self: ["sts:GetCallerIdentity"]
    })()
    instance.bruteforce_always = True
    instance.skip_bruteforce = False
    instance.principal_info = {}

    resources = instance.get_resources_and_permissions()

    assert [resource.extra_fields["evidence"] for resource in resources] == [
        "root principal", "live read-only probes"
    ]
    assert instance.principal_info["iam_visibility"] == "not applicable (root principal)"


def test_malformed_policy_and_condition_are_ignored_without_crashing():
    instance = bare_awspeass()
    scopes, _, _, unrestricted = instance._parse_policy_documents([
        ("broken document", None, False),
        ("broken condition", {
            "Statement": {"Effect": "Allow", "Action": "*", "Condition": "bad"}
        }, False),
        ("broken not-action", {
            "Statement": {"Effect": "Allow", "NotAction": 123, "Resource": "*"}
        }, False),
    ])

    assert scopes["*"]["allow"] == {"*"}
    assert not unrestricted
    assert "<malformed>" in instance.policy_conditions
    assert any("malformed policy document" in note for note in instance.policy_notes)
    assert any("malformed Condition" in note for note in instance.policy_notes)


def test_partition_is_preserved_for_account_and_assumed_role_fallback_arns():
    instance = bare_awspeass()
    instance.identity = {"Account": "123456789012"}
    instance.principal_arn = "arn:aws-us-gov:sts::123456789012:assumed-role/app/session"
    instance.principal_type = "role"
    instance.principal_name = "app"
    instance.entity_arn = None
    instance.num_threads = 1
    instance.debug = False
    instance._call_iam = lambda *args, **kwargs: ({}, False)
    instance._paginate_iam = lambda *args, **kwargs: ([], False)
    instance._all_actions = lambda: set()

    assert instance._account_resource(["s3:GetObject"]).id.startswith("arn:aws-us-gov:")
    assert instance.simulate_permissions() == ([], False)
    assert instance.entity_arn == "arn:aws-us-gov:iam::123456789012:role/app"


def test_missing_cli_and_os_errors_are_nonfatal():
    instance = object.__new__(AWSBruteForce)
    instance.aws_cli = None
    instance.debug = False
    instance.found_permissions = []
    assert instance.brute_force_permissions() == []

    instance.aws_cli = "/missing/aws"
    assert instance._get_aws_help() == []
