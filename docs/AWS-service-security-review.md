# AWS service security review tracker

This tracker keeps the AWS post-exploitation and privilege-escalation review
systematic. The companion CSV contains all 455 unique IAM service prefixes from
the 475 entries currently published by AWS's Policy Generator catalog. Entries
that share a prefix are combined because IAM cannot distinguish them by service
name. It is a work queue, not a claim that a queued service has no attack surface.

## Status meanings

- `queued`: not yet reviewed in this campaign.
- `in_progress`: documentation and API review or isolated live testing is in progress.
- `no_new_positive`: reviewed on the recorded date; no new reproducible technique was found.
- `validated`: at least one new technique passed the full evidence gate. A service remains
  eligible for later review because AWS adds APIs and changes behavior.
- `blocked`: a precise prerequisite prevented a conclusive test; the Notes field records it.

## Priority meanings

- `P0`: identity, credential, organization, compute, execution, deployment, backup, or broadly
  sensitive data control planes. Review these first.
- `P1`: services likely to contain secrets, customer data, invocation paths, resource-policy
  pivots, or service-role abuse.
- `P2`: all remaining services. P2 means later, not safe or uninteresting.

## Evidence gate

A technique can be added to HackTricks and CloudPEASS only when all of these are true:

1. The attack uses synthetic resources in an authorized account and a unique test prefix.
2. A least-privilege test identity succeeds with the candidate permission set.
3. A negative control with the candidate permission removed (or explicitly denied) fails.
4. The resulting security impact is observed, not inferred from an accepted API response.
5. Required companion permissions, resource policies, trust relationships, and ownership
   assumptions are recorded exactly.
6. Every test resource is deleted and the exact prefix is re-enumerated until empty.
7. The documentation includes reproduction and cleanup commands without overstating scope.

## Workflow

Review one service at a time. Start with API actions that can return credentials or sensitive
data, invoke code, pass or change identities, attach resources, alter policies, restore or clone
data, create signed URLs, or cause a more privileged service to act. Record failed hypotheses as
`no_new_positive` or `blocked` so they are not repeatedly rediscovered. Update the CSV in the same
commit as the evidence-backed implementation, then open a new HackTricks PR for documented true
positives.

The first completed service is AWS Backup (`backup`). The next service is selected from the P0
queue after the AWS Backup changes and cleanup verification are published.

Source catalog: <https://awspolicygen.s3.amazonaws.com/js/policies.js>

## Review log

### AWS Backup (`backup`) — 2026-09-08

Validated with synthetic resources and least-privilege STS sessions:

- `backup:StartRestoreJob` plus `iam:PassRole` restored both a native DynamoDB backup and a fully
  AWS Backup-managed recovery point. The actor was denied source-table reads but could read the
  restored table because only the target ARN was allowed.
- Removing `backup:StartRestoreJob` denied the restore. Granting it without `iam:PassRole` failed
  specifically on the pass-role authorization check.
- `backup:PutBackupVaultAccessPolicy` let a same-account role self-grant
  `backup:DeleteRecoveryPoint`. Deletion failed before the vault-policy change and succeeded after
  it; the temporary policy was then removed.
- `backup:DeleteRecoveryPoint` deleted the scoped synthetic recovery point and is therefore a
  direct recovery/destructive impact permission when vault lock or an applicable deny does not
  block it.
- A least-privilege role denied direct source-bucket reads and was also denied through a Backup
  Access Point created without a policy. With the full `backup:CreateBackupAccessPoint`,
  `backup:DescribeBackupAccessPoint`, `s3:CreateAccessPoint`, `s3:GetAccessPoint`, and
  `s3:PutAccessPointPolicy` chain, it embedded a policy granting itself `s3:GetObject` and read the
  exact canary directly from the S3 recovery point without an identity-based data permission.

Not promoted from this pass:

- `backup:GetRecoveryPointRestoreMetadata` returned infrastructure restore metadata for the
  synthetic DynamoDB point, not table data or a credential.
- Cross-account copy remains a separate, configuration-dependent path requiring organization,
  destination-vault, role, and encryption prerequisites; no cross-account impact is claimed.
- Compliance-mode vault lock was not activated because its minimum cooling-off period conflicts
  with the mandatory same-session cleanup requirement.

The S3 Backup Access Point API was introduced after the locally installed AWS CLI model. The live
check therefore used a disposable current AWS SDK environment; the HackTricks procedure records
upgrading the CLI or using a current SDK as the compatibility fallback.

Cleanup completed in dependency order. Exact-prefix inventories for Backup vaults/access points,
recovery points, DynamoDB tables/backups, S3 buckets/access points, IAM roles, EventBridge rules,
and tagged resources all returned empty. The account's AWS Backup service-linked role dates from
2022 and was deliberately left untouched.

### Account access manager (`account-access`) — 2026-09-08

The management-account lab is an all-features AWS Organization but has no IAM Identity Center
instance. Account access manager requires that identity source before an application or role
entitlement can be created. Enabling a new organization-wide identity system solely to exercise
`account-access:CreateEntitlement` would expand the test beyond a safely isolated fixture, so the
service is recorded as `blocked`, with no security claim and no infrastructure created.

### AWS Service Catalog (`servicecatalog`) — 2026-09-08

Live validation confirmed that `servicecatalog:CreateProvisioningArtifact` plus
`servicecatalog:ProvisionProduct` can turn an existing privileged launch constraint into a
privilege-escalation path. A synthetic end-user role controlled one private template object and
the exact product, but had no `iam:PassRole`, no CloudFormation create permission, and no direct
`organizations:DescribeOrganization`. It added an artifact whose template created a role trusting
the end user, provisioned it, assumed the created role, and successfully called
`organizations:DescribeOrganization`. The Service Catalog record identified the configured launch
role as the executor.

Independent controls removed each Service Catalog action in turn. Creating the artifact without
`CreateProvisioningArtifact` and provisioning it without `ProvisionProduct` both returned
`AccessDenied`, and neither control created a resource. A second end-to-end run used
`DisableTemplateValidation=true` and succeeded without caller `cloudformation:ValidateTemplate`,
so that permission is not part of the minimum chain. The caller still needs control of a template
source, access to a non-shared product associated with its portfolio, and a launch constraint whose
role can perform the template's actions. The pair is therefore recorded as a conditional critical
combination while each permission remains medium in isolation.

### Amazon EC2 Image Builder (`imagebuilder`) — 2026-09-08

Live validation confirmed a version-reference escalation. A benign recipe stored
`component/cloudpeass-ib-.../x.x.x` and an enabled pipeline used an infrastructure configuration
with a synthetic instance profile. A restricted role with only `imagebuilder:CreateComponent` on
that component name, `imagebuilder:StartImagePipelineExecution` on the existing pipeline, and read
access to a proof bucket published version `2.0.0` and started the unchanged pipeline. The resulting
image record resolved the wildcard to the new `2.0.0/1` component and launched a build instance
with the existing instance profile.

The caller had no `iam:PassRole`, no `imagebuilder:UpdateImagePipeline`, and was denied
`organizations:DescribeOrganization`. Its component used the build profile to write the caller
identity and organization response to the proof bucket. Reading those objects showed the exact
build-instance role ARN and organization metadata. Removing `StartImagePipelineExecution` denied a
second start and created no image; removing `CreateComponent` denied creation of version `3.0.0`.
The pair is conditional critical: the recipe must track a wildcard version beneath a component name
the caller can update, and the existing pipeline profile must expose a useful permission or data
path. Pinned component build ARNs prevent this particular technique.

The image was cancelled as soon as both proof objects arrived. Image Builder reported `CANCELLED`,
the EC2 instance reached `terminated`, and no AMI, snapshot, or active volume was produced. The
pipeline, image record, recipe, both component versions, infrastructure configuration, two log
groups, proof objects and bucket, test roles, and instance profile were deleted. Exact-prefix checks
returned no active Image Builder, IAM, S3, CloudWatch Logs, EC2, EBS, AMI, or snapshot resources.
The account's Image Builder service-linked role dates from 2020 and was deliberately left untouched.

### AWS CodeDeploy (`codedeploy`) — 2026-09-08

Live validation confirmed that a controlled S3 revision plus `codedeploy:CreateDeployment` can
execute lifecycle hooks as root on an existing EC2 deployment-group target and inherit its instance
profile. AWS enforced `codedeploy:GetDeploymentConfig` on the group's deployment configuration and
`codedeploy:RegisterApplicationRevision` on the application as dependent permissions of the create
request. The caller did not need to make a separate register call.

The synthetic caller could write one revision object and read three proof objects, but had no
`iam:PassRole`, EC2, SSM, or direct `organizations:DescribeOrganization`. The revision's
`AfterInstall` hook returned `uid=0(root)`, the exact assumed instance-role ARN, and organization
metadata. A policy containing only `CreateDeployment` failed on `GetDeploymentConfig`; adding that
failed on `RegisterApplicationRevision`; adding all three succeeded. A final control removed
`CreateDeployment` while retaining both dependencies and was denied without creating a second
deployment.

The chain is conditional critical: the application and EC2/on-premises deployment group must
already exist, the caller must control an accessible revision source, and at least one reachable
agent target must expose useful host or instance-profile privilege. The successful deployment was
deleted with its group/application; the only EC2 target was terminated, its volume and no-ingress
security group deleted, and all test IAM, instance-profile, S3, and local bundle resources removed.
Authoritative inventories returned no active prefix-matching resource; the Resource Groups Tagging
API temporarily retained tombstones for the terminated instance and deleted volume.

### AWS Systems Manager (`ssm`) — 2026-09-08

Live validation confirmed that `ssm:StartAutomationExecution` alone can invoke an
administrator-authored Automation runbook with a constant privileged `assumeRole`. The test role
had no `iam:PassRole` and was denied `organizations:DescribeOrganization`, but started the exact
document successfully. Its `aws:executeAwsApi` step assumed the stored role and returned the
organization ID.

`ssm:GetAutomationExecution` is not required for the action's impact. A second session containing
only `StartAutomationExecution` was denied the get call, while an independent administrator
observed that its execution reached `Success` with the same privileged output. Removing Start and
retaining only Get denied a third execution. This finding is scoped to a role ARN stored directly in
the runbook and preauthorized when the document was authored; passing an attacker-selected
`AutomationAssumeRole` parameter at runtime can invoke separate `iam:PassRole` checks.

The permission is classified critical because preauthorized runbooks are delegated-administration
entry points and may change infrastructure or expose role-only output. A useful document and any
required parameter values remain prerequisites. Both completed executions became immutable history;
the document and two test roles were deleted, and exact checks returned no active Automation, IAM,
or tagged fixture.
