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
