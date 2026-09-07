import json
from urllib.parse import quote

from AWSPEAS import AWSPEASS, build_parser
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


def test_token_minting_get_commands_are_never_probed(monkeypatch):
    instance = object.__new__(AWSBruteForce)
    instance._get_aws_help = lambda service: [
        "AVAILABLE COMMANDS",
        "o get-caller-identity",
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
        "19",
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


def test_managed_policy_inference_is_case_insensitive_and_combines_policies():
    guesser = AWSManagedPoliciesGuesser({"S3:listallmybuckets", "EC2:describeinstances"})
    guesser.fetch_managed_policies = lambda url: [
        {"name": "StorageRead", "effective_action_names": ["s3:ListAllMyBuckets"]},
        {"name": "ComputeRead", "effective_action_names": ["ec2:DescribeInstances"]},
    ]
    result = guesser.guess_permissions()
    assert result[0]["policies"] == ["ComputeRead", "StorageRead"]
