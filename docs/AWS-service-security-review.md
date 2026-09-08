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

On 2026-09-08 the tracker was reconciled with
`live_validated_disclosure_documentation` and its regression suite. Fifty-six previously queued
service prefixes already had an evidence-backed action, a dedicated automated assertion, and a
service-specific HackTricks document; those rows now record the exact actions and documents as
`validated`. This reconciliation created no infrastructure and made no new severity decision. A
tracker regression test prevents a prefix with registered live evidence from silently remaining
queued.

The same evidence gate was subsequently applied to B2BI and additional Amazon Connect data
surfaces. Exact-action sessions recovered randomized B2BI sample/mapping and partner-contact
canaries, Connect contact attributes, and two forms of Connect Data Table values. Neighboring-action
controls were denied, and every transformer, profile, contact, table, flow, instance, and test role
was removed before those actions were marked `validated`.

## Ranked P0 hypothesis queue

These are test plans, not findings. The order favors paths that might reuse an existing service
role, weaken a trust boundary, expose a credential, or clone protected data. Each row must still
pass the evidence gate before it can change a permission severity or appear in HackTricks.

| Rank | Service | Next isolated hypothesis |
| ---: | --- | --- |
| Q03 | AWS Config | Point remediation at a preauthorized SSM Automation path and call `StartRemediationExecution`; distinguish Config permissions from SSM and pass-role checks. |
| Q04 | CodeConnections | Use an installed connection through an existing or synthetic consumer to determine whether `UseConnection` exposes or executes otherwise inaccessible private repository content. |
| Q05 | IAM Roles Anywhere | Mutate a trust anchor used by an existing profile and role, then attempt a certificate-backed session; retain the exact role trust and profile prerequisites. |
| Q07 | AWS Batch | Register and submit attacker code against existing job and execution roles; remove each `iam:PassRole` and Batch dependency independently. |
| Q10 | EKS | Create an access entry and attach an EKS access policy, then prove Kubernetes authorization rather than treating accepted IAM APIs as impact. |
| Q11 | OpenSearch | Change a domain access policy or another authorization surface and prove new data-plane access with a denied-before control. |
| Q12 | RDS | Share, copy, or restore an unencrypted snapshot and read a canary without source-instance access; record customer-managed KMS blockers separately. |
| Q13 | FSx | Copy, share, or restore a backup and mount/read a canary without source-filesystem permission. |
| Q14 | EventBridge | Attach a target to an existing rule and attempt execution through an existing service role or target resource policy, with and without `iam:PassRole`. |
| Q16 | S3 Object Lambda | Test access-point policy self-grant and a known transformed-object path while the caller remains denied direct source-object access. |

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

### AWS Signer (`signer`) — 2026-09-08

Live validation confirmed a code-signing trust bypass when `signer:StartSigningJob` covers the exact
profile version trusted by an enforcing Lambda Code Signing Config. The restricted caller staged an
attacker-controlled ZIP, signed it with that trusted profile, and used
`lambda:UpdateFunctionCode` to deploy it to an existing function. The caller had no
`iam:PassRole` and was denied `organizations:DescribeOrganization`, but an independent invocation
returned the function execution-role ARN and organization ID.

The unsigned deployment was rejected with `CodeVerificationFailedException`. A role lacking
`StartSigningJob` could not sign, while a signing-only role produced a valid signed ZIP but was
denied `UpdateFunctionCode`. Lambda also enforced `lambda:GetCodeSigningConfig` during the update.
Minimization runs reduced the S3 prerequisites to `ListBucket`, `GetObjectVersion`, and `PutObject`
for signing, plus `GetObject` so Lambda could fetch the signed result. `GetBucketLocation` and
`GetBucketVersioning` were removed and the complete path still succeeded.

`StartSigningJob` is high because it is authority to produce artifacts accepted as a trusted
publisher; the end-to-end Lambda execution path is conditional critical and additionally requires
an enforcing configuration that trusts the profile, code-update access, controlled staging objects,
and a function role with useful access. List and describe permissions were absent from the attack
sessions. Known names and versions can instead come from SAM/CloudFormation templates, CI files,
artifact manifests, cached command output, errors, or shell history.

All functions, code-signing configurations, buckets and every object version, IAM roles, and inline
policies were deleted. Signer jobs remain immutable history, and each test signing profile was
canceled and revoked because Signer does not permit reusing or physically deleting its name after
cancellation. Exact checks returned no active compute, S3, Lambda, or IAM fixture.

### Amazon EventBridge (`events`) — 2026-09-08

Live validation confirmed that `events:PutTargets` plus `events:PutEvents` can invoke an existing
privileged Lambda without `lambda:InvokeFunction` or `iam:PassRole` when the Lambda resource policy
already trusts the targeted rule ARN. Three administrator-created rules on a synthetic custom bus
isolated the controls. A PutEvents-only role emitted before any target existed and no proof object
appeared; it was denied PutTargets. A PutTargets-only role attached the function but was denied
PutEvents. The full role attached the same function to a third rule, emitted an attacker-controlled
event, and read a proof containing the function execution-role ARN and organization ID.

The caller was independently denied direct Lambda invocation and
`organizations:DescribeOrganization`. No execution role was supplied to `PutTargets`; Lambda
authorized `events.amazonaws.com` through its own resource policy. This pair is conditional
critical because a controllable bus/rule, a useful target, and a matching target resource policy
are prerequisites. Each EventBridge action remains medium alone.

All three rules and targets, the custom bus, function, bucket and object versions, four IAM roles,
inline policies, and Lambda resource-policy statements were deleted. Exact prefix checks returned
no active EventBridge, Lambda, S3, or IAM fixture.

### IAM Roles Anywhere (`rolesanywhere`) — 2026-09-08

Live validation confirmed that `rolesanywhere:UpdateTrustAnchor` alone can replace the CA
certificate bundle behind an existing trust anchor. A client certificate issued by the synthetic
attacker CA was rejected before the update. A no-permission IAM user was denied the update, while a
restricted user with only `UpdateTrustAnchor` replaced the anchor. The unchanged certificate then
obtained temporary credentials for the existing profile's target role and returned organization
metadata unavailable to the restricted user directly. No `iam:PassRole` was used.

The permission is critical when the anchor is enabled, an enabled profile names a useful role, the
role trusts `rolesanywhere.amazonaws.com`, and its trust-policy conditions accept the certificate's
subject/issuer/SAN attributes and source anchor. Strong `aws:SourceArn`, `aws:SourceAccount`, and
principal-tag conditions can prevent a swapped CA from satisfying the role trust.

The trust anchor, profile, target role, two disposable IAM users and access keys, inline policies,
local CA/client keys, and the service-linked role created by the first anchor were deleted. Exact
Roles Anywhere and IAM inventories returned empty.

### Amazon EventBridge Pipes (`pipes`) — 2026-09-08

The tested same-role target-redirection hypothesis produced no new positive. An administrator
created a running SQS-to-SQS pipe whose existing execution role could receive from the source and
send to both the benign and synthetic attacker queues. A restricted IAM user had only
`pipes:UpdatePipe` on that exact pipe and receive access to the attacker queue; it was denied direct
reads from the source queue.

Changing the target still required the caller to submit the pipe's `RoleArn`. AWS denied the update
specifically because the caller lacked `iam:PassRole`, even though the ARN was unchanged and the
pipe was already running. A no-permission user was also denied. This rules out treating
`pipes:UpdatePipe` alone as a validated stored-role bypass for this configuration; attack paths
that genuinely include `iam:PassRole`, or a different independently tested authorization surface,
remain separate cases.

The pipe, all three queues, execution role and policy, both disposable IAM users, and both access
keys were deleted. Exact prefix queries returned no remaining Pipes, SQS, or IAM resources.

### Amazon SageMaker (`sagemaker`) — 2026-09-08

Live validation confirmed that `sagemaker:UpdateNotebookInstanceLifecycleConfig` alone can persist
attacker-controlled shell code into a lifecycle configuration already attached to a notebook. The
restricted user could not start or stop the notebook, lacked `iam:PassRole`, and was denied direct
`organizations:DescribeOrganization`. A no-permission user was denied the lifecycle update.

The notebook's original benign `OnStart` hook reached `InService` without creating a proof object.
After an administrator stopped it, the restricted user replaced only the lifecycle configuration's
`OnStart` content. The restricted user's own start request was denied. On the next administrator
start, the new script ran as root, wrote the unique canary, reported the notebook's exact assumed
execution-role ARN, and returned organization metadata that the updater could not access directly.

This single permission is critical when a target lifecycle configuration is attached to at least
one notebook that will later start and the notebook role or host exposes useful privilege or data.
The action does not attach the configuration to a different notebook; known configuration names
can still be recovered from IaC, CI files, cached output, errors, or shell history when list and
describe permissions are unavailable. Disabling notebook-user root access does not restrict the
lifecycle hook itself.

The notebook was stopped and deleted, followed by its lifecycle configuration, private proof
bucket and object, execution role and policy, two disposable IAM users, and both access keys.
Exact prefix inventories returned no remaining SageMaker notebook, lifecycle configuration, S3
bucket, IAM user, or IAM role.

### Amazon API Gateway Management (`apigateway`) — 2026-09-08

Live validation confirmed that `apigateway:PATCH` alone can redirect an existing HTTP API
integration and intercept requests when its stage has automatic deployment enabled. The synthetic
`$default` stage initially routed `POST /submit` to a benign Lambda and returned `benign`; no proof
object existed. A restricted user knew the API and integration IDs but had no API Gateway list/get
permissions, deployment permission, Lambda invocation, or `iam:PassRole`.

A no-permission user was denied `UpdateIntegration`, and the restricted user was denied direct
invocation of the collector Lambda. The restricted user then changed only the existing
integration's URI with `apigateway:PATCH`. The next request was received by the collector, whose
private proof object contained the exact JSON body, bearer `Authorization` header, and custom
sensitive header. No `apigateway:POST` deployment action was needed because auto-deploy published
the integration update.

The action is High based on the independently observed request and token disclosure. Whether it
becomes privilege escalation or Critical depends on the affected route, its authorization model,
the secrets carried by clients, and whether the replacement endpoint is accepted. Without list or
get permissions, IDs may still be recovered from invoke URLs, OpenAPI/IaC files, CI configuration,
SDK settings, logs, cached CLI output, errors, or shell history. Stages without auto-deploy require
a separate deployment path.

The HTTP API, stage, route and integration, both Lambda functions and their policies, private proof
bucket and object, execution role, two disposable IAM users, both access keys, and local deployment
ZIP were deleted. Exact prefix inventories returned no API Gateway, Lambda, S3, or IAM resource.

### Amazon EventBridge Scheduler (`scheduler`) — 2026-09-08

The tested stored-role target-redirection hypothesis produced no new positive. An administrator
created an enabled schedule whose execution role could send to both a benign queue and a synthetic
attacker queue. A restricted user had only `scheduler:UpdateSchedule` on that exact schedule and
receive access to the attacker queue; it was denied reads from the original target queue.

`UpdateSchedule` requires a complete target object including `RoleArn`. AWS denied the restricted
update specifically on `iam:PassRole` even though the request resubmitted the unchanged role already
stored on the schedule. A no-permission user was independently denied the update. Therefore
`scheduler:UpdateSchedule` alone is not classified as a stored-role bypass for this configuration;
attack chains that also include `iam:PassRole` remain separately relevant.

The schedule, both queues, execution role and policy, two disposable IAM users, and both access keys
were deleted. Exact prefix queries returned no remaining Scheduler, SQS, or IAM resources.

### AWS Secrets Manager (`secretsmanager`) — 2026-09-08

Live validation confirmed that `secretsmanager:PutResourcePolicy` alone can grant a same-account IAM
user access to a secret value. A synthetic user had an identity policy allowing only
`PutResourcePolicy` on one exact secret and was denied `GetSecretValue` before the change. A
no-permission user was independently denied the policy update.

The restricted user installed a policy naming its exact IAM-user ARN and allowing
`secretsmanager:GetSecretValue` on that secret. The same user then recovered the exact canary even
though its identity policy still contained no read action. This is classified Critical because it
directly turns resource-policy control into secret disclosure.

The proof is deliberately limited to a same-account IAM user and a secret encrypted with the
AWS-managed Secrets Manager key. Cross-account principals require both resource- and identity-based
allows, and customer-managed KMS keys introduce `kms:Decrypt` plus key-policy authorization.
`BlockPublicPolicy` protects against policies that Zelkova considers broad/public; fixed-principal
self-grants must still be prevented by restricting `PutResourcePolicy` itself. Known secret names or
ARNs may come from application configuration, IaC, CI files, environment variables, logs, errors,
or shell history when list/get metadata calls are denied.

The resource policy was removed, the secret was force-deleted and polled until absent, and both
disposable IAM users, access keys, and inline policy were deleted. Exact Secrets Manager and IAM
prefix inventories returned empty.

### Amazon DynamoDB (`dynamodb`) — 2026-09-08

Live validation confirmed that `dynamodb:PutResourcePolicy` alone can grant a same-account IAM user
data access to a table. The restricted user's identity policy allowed only `PutResourcePolicy` on
one exact table, and its `GetItem` request was denied before the change. A no-permission user was
independently denied the policy update.

The restricted user installed a table policy naming its exact IAM-user ARN and allowing only
`dynamodb:GetItem`. After DynamoDB's short policy-propagation interval, the same user read the exact
canary without an identity-based data action. The permission is classified Critical because it
directly converts authorization-boundary control into table data access and can grant broader
write, stream, or backup actions when the table policy accepts them.

The result is scoped to the tested same-account user/table path. Cross-account principals and
secondary resources such as indexes, streams, global-table replicas, exports, and backups have
their own supported-action, ARN, KMS, and identity-policy requirements. When table enumeration is
denied, names and ARNs may remain in application configuration, IaC, CI files, environment
variables, logs, error messages, or shell history.

The resource policy was removed before the table was deleted and polled until absent. Both
disposable IAM users, access keys, and the inline policy were deleted; exact DynamoDB and IAM
prefix inventories returned empty.

### Amazon SQS (`sqs`) — 2026-09-08

Live validation confirmed that `sqs:SetQueueAttributes` alone can replace a queue's resource policy
and grant the same-account caller access to message data. A synthetic IAM user had only that action
on one exact queue and was denied `ReceiveMessage` before the change. A no-permission user was
independently denied the attribute update.

The restricted user installed a `Policy` attribute naming its exact IAM-user ARN and allowing only
`sqs:ReceiveMessage`. After propagation, the same user recovered the seeded canary without an
identity-based receive allow. This permission is Critical: besides arbitrary queue-policy control,
the same setter can change redrive, retention, visibility, delay, encryption, and other attributes
that influence confidentiality, integrity, or availability.

The proof requires an owner-account caller because SQS does not permit cross-account callers to use
`SetQueueAttributes`. A known queue URL is sufficient; when `ListQueues` or `GetQueueUrl` is denied,
URLs commonly remain in application configuration, Lambda event-source mappings, environment
variables, IaC, CI files, logs, errors, or shell history.

The policy attribute was cleared before deleting the queue. Both disposable IAM users, access keys,
and the inline policy were deleted; exact SQS and IAM prefix inventories returned empty.

### Amazon SNS (`sns`) — 2026-09-08

Live validation confirmed that `sns:SetTopicAttributes` alone can replace a topic policy and grant
the same-account caller subscription access. A restricted IAM user's identity policy allowed only
`SetTopicAttributes` on one topic plus receive access to a synthetic destination queue. Its
`Subscribe` request was denied before the policy change, and a no-permission user was independently
denied the attribute update.

The restricted user set the topic's `Policy` attribute to name its exact IAM-user ARN and allow
only `sns:Subscribe`. It then subscribed the queue without an identity-based SNS subscribe allow.
An administrator published a later canary, and the restricted user received it from the queue. The
permission is Critical because it can convert policy control into persistent access to future topic
messages and can also authorize publication or other policy-supported topic actions.

The delivery endpoint must separately accept SNS messages. The lab kept all data inside the test
account and used a queue policy restricted to `sns.amazonaws.com` with the exact topic ARN as
`aws:SourceArn`. When SNS listing is denied, topic ARNs can still appear in application settings,
subscriptions, IaC, CI files, logs, errors, or shell history.

The subscription was removed before deleting the topic and queue. Both disposable IAM users,
access keys, inline policy, and queue policy were deleted; exact SNS, SQS, and IAM inventories
returned empty.

### AWS Identity and Access Management (`iam`) — 2026-09-08

Validated `iam:CreateAccessKey` as a direct cross-user credential takeover primitive. A synthetic
target user had only `organizations:DescribeOrganization`; the attacking user had only
`iam:CreateAccessKey` on that exact target ARN. The attacker was denied the Organizations call,
and a separate no-permission user was denied access-key creation. The attacking user then created
an access key for the target, and the returned credentials successfully retrieved the lab
organization's exact ID and ARN. This observes inherited target authorization rather than merely
an accepted IAM control-plane response.

`iam:ListUsers` is not required. Target names and ARNs can instead be recovered from CloudTrail,
resource policies, trust policies, infrastructure-as-code, CI/CD configuration, application
settings, environment variables, logs, and access-denied messages. A target that already has two
access keys cannot receive another until one is deleted, so `iam:DeleteAccessKey` is only an
optional capacity-making companion permission and not part of the validated singleton.

The proof used a unique prefix and never persisted target credentials in the repository. Cleanup
enumerated and deleted every access key before deleting all three synthetic users and their inline
policies; the exact-prefix IAM user inventory returned empty. A prior propagation-sensitive run
was also cleaned by enumerating every key rather than relying on a cached identifier.

### Amazon Route 53 (`route53`) — 2026-09-08

Validated `route53:ChangeResourceRecordSets` as an existing-zone DNS takeover primitive. A
synthetic public hosted zone began with an A record resolving to `192.0.2.10`. The attacking user
had only the candidate action on the exact hosted-zone ARN, was denied `ListHostedZones`, and knew
the zone ID and record name. A separate no-permission user was denied the same UPSERT. The attacker
changed the existing record to `192.0.2.99`; after Route 53 reported the change synchronized, a
direct query to the zone's public authoritative name server returned `192.0.2.99`.

The permission is High in isolation because control of an existing record can redirect application
or email traffic and can satisfy some DNS-based ownership checks; the final impact depends on what
the name serves and on transport authentication. The already-recorded multi-permission private-DNS
and Private CA chain remains Critical separately. `route53:ListHostedZones` is not required: zone
IDs and record names commonly appear in IaC state, deployment output, CloudTrail, application and
resolver configuration, CI/CD variables, logs, errors, console URLs, and NS/SOA lookups.

Cleanup first deleted the exact altered record and then the synthetic hosted zone. Both IAM users,
their access keys, and the inline policy were deleted. Exact Route 53 and IAM prefix inventories
returned empty; no existing account-owned zone was modified.

### AWS Elastic Load Balancing V2 (`elasticloadbalancing`) — 2026-09-08

Validated `elasticloadbalancing:ModifyListener` as an Application Load Balancer traffic-redirection
primitive. A synthetic internet-facing ALB listener initially returned the literal body `benign`.
The attacking user had only the candidate permission on the exact listener ARN, could not call
`DescribeListeners`, and knew the listener ARN. A separate no-permission user was denied the same
modification. The attacker replaced the default action with an HTTPS redirect to
`attacker.invalid`; a real request to the ALB then returned the exact attacker-selected `Location`.

No target group, backend, service role, `iam:PassRole`, or ELB list/read permission was required for
the tested redirect. The permission is High because it can divert requests away from an existing
listener, although TLS behavior, client redirect handling, and the listener's traffic determine
whether secrets are exposed. Listener ARNs and ALB names can be recovered without ELB listing from
IaC state, CloudTrail, deployment output, CI/CD configuration, application inventories, logs,
errors, metrics dimensions, and console URLs.

Cleanup deleted the listener and ALB, waited for load-balancer deletion, and retried the security
group deletion until delayed ENI detachment completed. Both IAM users, every access key, and the
inline policy were deleted. Exact-prefix ALB, security-group, and IAM inventories returned empty.
Two earlier harness-only failures—the CLI shorthand parser and a non-portable case-insensitive
`awk` expression—also ran full cleanup and did not count as security results.

### Amazon Cognito Identity (`cognito-identity`) — 2026-09-08

Validated `cognito-identity:UpdateIdentityPool` as a public credential-enablement primitive. A
synthetic identity pool had unauthenticated access disabled but already had an unauthenticated IAM
role assigned. That role could read one exact private S3 canary. An unsigned `GetId` request failed
before the change. The attacking user had only `UpdateIdentityPool` on the exact pool ARN, could
not list identity pools, and a separate no-permission user was denied the update. The attacker
enabled unauthenticated identities; an unsigned client then obtained an identity ID and temporary
role credentials and used them to read the exact canary.

This path requires the latent unauthenticated role assignment and its effective permissions. The
attacker did not need `SetIdentityPoolRoles`, `iam:PassRole`, IAM read access, or any signed
permission for the public `GetId`/`GetCredentialsForIdentity` calls. Cognito enhanced-flow
scope-down policies still limit the resulting session. Identity-pool IDs and names are commonly
public client configuration and can also be recovered from mobile/web bundles, environment
variables, IaC, CI/CD output, logs, errors, and deep links when list access is denied.

Cleanup deleted the identity pool, role and inline policy, S3 object and bucket, both users, every
access key, and the candidate policy. Exact Cognito pool, IAM user/role, and S3 bucket inventories
returned empty.

### Amazon EC2 (`ec2`) — `ModifyInstanceAttribute` network exposure — 2026-09-08

Validated that `ec2:ModifyInstanceAttribute` alone can replace the security groups on a known
running instance's primary network interface. A synthetic instance ran an HTTP service containing
an exact canary while its initial security group had no ingress. The request timed out before the
change. The attacking user had only the candidate action, could not describe the instance, and a
separate no-permission user was denied modification. After the attacker supplied the ID of a
synthetic security group allowing TCP/8080, the same public-IP request returned the exact canary.

The `groups` path did not require stopping or starting the instance, modifying the network
interface directly, reading EC2 inventory, passing a role, or changing user data. It requires a
known instance ID and replacement security-group ID. Those identifiers commonly appear in IMDS,
hostnames, DNS, IaC state, deployment and CI/CD output, CloudTrail, Systems Manager, monitoring,
logs, errors, and console URLs. The action is Critical because it can expose otherwise unreachable
administrative or data services; actual reachability still depends on routing, NACLs, the service
bind address, and other network controls.

Cleanup terminated the instance and waited for the terminal state; its delete-on-termination root
volume disappeared. Both security groups, both IAM users, all access keys, and the inline policy
were deleted. Exact instance, volume, security-group, and IAM prefix inventories returned empty.

### Amazon Route 53 Domains (`route53domains`) — 2026-09-08

Validated `route53domains:GetDomainDetail` as a registration-data disclosure. A disposable user
with only that action could not call `ListDomains`, while a separate no-permission user was denied
the detail request. For one known domain, the candidate call returned 33 nonempty fields across the
registrant, administrative, and technical contacts plus a status entry. The harness counted fields
in memory and did not print or persist any names, addresses, email addresses, telephone numbers,
nameservers, or other response values.

The API authorizes the action against `Resource: "*"`; a first per-domain-ARN attempt was denied
against resource `*`, then fully cleaned. The domain name itself needs no AWS permission to
discover because DNS, certificate-transparency records, application URLs, emails, public source,
and client configuration commonly expose it. Neither run changed the registered domain. Both
sets of disposable users, every access key, and inline policies were deleted; exact IAM prefix
inventory returned empty.

### Amazon Resource Groups Tagging API (`tag`) — 2026-09-08

No new independent escalation primitive was found for `tag:TagResources`. The first hypothesis
gave a user a latent `secretsmanager:GetSecretValue` allow conditioned on
`aws:ResourceTag/Access=allowed` plus only the generic tagging action. Its pre-tag secret read and
resource enumeration were denied, and a no-tagging control could not call the API. Although the
candidate `TagResources` request returned HTTP success, the secret remained untagged and the
conditional read stayed denied; the harness correctly rejected the result.

A second isolated run captured the response's per-resource result. `FailedResourcesMap` reported
`AccessDeniedException`, and an administrator read confirmed the original synthetic tag was
unchanged. This matches the CLI/API requirement: the caller needs `tag:TagResources` **and** the
resource-owning service's tagging permission—for example `secretsmanager:TagResource`. That
service-specific permission can already make the same tag change directly, so adding the generic
action does not unlock a separate ABAC path. Consumers must inspect `FailedResourcesMap`; a zero
exit status or HTTP 200 alone is a false positive.

Both synthetic secrets were force-deleted and polled until absent. All three disposable users,
every access key, and inline policy were deleted; exact Secrets Manager and IAM inventories
returned empty. No HackTricks attack entry or permission-severity promotion was made.

### AWS Certificate Manager (`acm`) — 2026-09-08

Validated `acm:ExportCertificate` as direct private-key disclosure for an exportable certificate.
The lab requested one unique public certificate with export enabled and certificate-transparency
logging disabled, then validated it using one unique CNAME beneath an authorized hosted zone. The
attacking user had only `ExportCertificate` on the exact certificate ARN and was denied
`ListCertificates`; a separate no-permission user was denied export. The successful response
contained an encrypted private-key PEM. Because the caller chooses the export passphrase, the
harness decrypted it and confirmed that its derived public-key fingerprint exactly matched the
issued certificate. No key material or fingerprint was printed or persisted.

The path requires a known certificate ARN and a certificate that was issued as exportable. This
action does not turn existing non-exportable or imported certificates into exportable ones. ARN
fallbacks include ALB/NLB listeners, CloudFront and API Gateway configuration, CloudFormation/IaC
state, deployment output, CloudTrail, certificate deployment configuration, logs, and console
URLs. The permission is Critical because the returned private key can enable service impersonation
where the certificate remains trusted.

The validation CNAME was deleted from the existing zone before the synthetic certificate was
deleted. The certificate, both IAM users, every access key, and the inline policy were removed;
exact ACM, Route 53 record, and IAM inventories returned empty. A first harness run translated no
ACM `Value` field into Route 53's `ResourceRecords` shape, failed before DNS mutation, and was also
fully cleaned; it did not count as a security result.

### P0 prerequisite audit — 2026-09-08

Read-only inventories resolved nine currently untestable P0 rows as `blocked`, not safe or
negative. The organization has `ALL` features but contains only its management account, so AWS RAM
cross-account sharing and Organizations delegation/SCP/account-movement hypotheses have no
independent authorized consumer. No share or organization policy was changed. IAM Identity Center
returned no instances, which also leaves Identity Store and SSO Directory without a target;
Control Tower returned no landing zones. Enabling either organization-wide control plane solely
for a test would exceed an isolated disposable fixture.

Directory Service and registered WorkSpaces directory inventories were empty, as were WorkSpaces,
Secure Browser portals, and Storage Gateways. WorkSpaces therefore lacks its directory prerequisite;
Secure Browser lacks a configured portal and identity provider; Storage Gateway lacks an activated
appliance and backing store. None of those services was created or mutated. Their tracker notes
retain the exact missing prerequisite so a future authorized lab with the service already present
can resume the security-impact test rather than infer a result from API documentation.

### AWS Resource Groups (`resource-groups`) — 2026-09-08

No new high-impact standalone technique was found. The `GroupResources` API is not a generic path
for arbitrary groups: the installed current CLI documents support only EC2 HostManagement,
CapacityReservationPool, and ResourceGroups ApplicationGroup types. Creating an empty group or a
generic group for arbitrary manual membership was rejected. Even supported group membership is
organizational metadata and does not grant access to the member resource.

Two data-boundary tests used private S3 canaries. A tag-query group did not surface its newly tagged
bucket to an identity with only `ListGroupResources`, because resolving that query also requires
`tag:GetResources`. A deterministic CloudFormation-stack group produced the same explicit
`Forbidden` result: that query type additionally requires `cloudformation:DescribeStacks`,
`cloudformation:ListStackResources`, and `tag:GetResources`. The identities remained denied direct
S3 reads, list operations, and the no-permission controls. The dependent read permissions can
enumerate resource ARNs and types, but group membership itself does not authorize access, so no
High/Critical finding or HackTricks attack entry was created.

Both groups, both private buckets and objects, the CloudFormation stack, all four disposable users,
every access key, and inline policies were deleted. Exact Resource Groups, CloudFormation, S3, and
IAM prefix inventories returned empty.

### AWS Security Token Service (`sts`) — evidence reconciliation — 2026-09-08

The earlier live-tested `sts:GetFederationToken` result from commit `46c3d77` is now registered in
the stricter disclosure-evidence map and tracker. It mints a separate temporary access key, secret,
and session token for the current IAM user; requested session policies intersect with the user's
authority, so it cannot escalate beyond that user. It remains High as credential hand-off and a
session-lifetime extension primitive, not Critical privilege escalation. HackTricks already records
the exact IAM-user prerequisite, 36-hour maximum, role/session restriction, permissionless
`GetCallerIdentity` fallback, and a 15-minute restrictive demonstration.

This reconciliation created no infrastructure and intentionally did not mint another STS session,
because issued STS credentials cannot be explicitly destroyed. `AssumeRole`, SAML, web-identity,
service-bearer, delegated-token, and root-session paths remain governed by their separate trust,
provider/token, companion-permission, organization, and task-policy prerequisites; no unconditional
impact is inferred from the STS action name alone.

Concurrent live evidence for the `iotsitewise` asset-property read APIs and SimpleDB `GetAttributes`
and `Select` arrived while the EKS review was running. Their dedicated regression tests and
HackTricks document mappings were already committed, so the two P2 tracker rows were reconciled to
`validated`; this reconciliation created no infrastructure and made no new severity decision.

Concurrent live evidence for TwinMaker `GetWorkspace`, `GetComponentType`, and `GetPropertyValue`
arrived during the subsequent prerequisite review and was reconciled to its existing dedicated
HackTricks mapping under the same no-new-infrastructure rule.

### Amazon EKS (`eks`) — 2026-09-08

Validated the `eks:CreateAccessEntry` plus `eks:AssociateAccessPolicy` pair as direct Kubernetes
cluster-admin escalation. A synthetic EKS control plane used API-and-ConfigMap authentication and
no worker nodes. The attacking IAM user had only those two EKS actions, could not list clusters,
and its signed Kubernetes token initially received `Unauthorized`; a separate no-permission user
was denied access-entry creation. The attacker created a `STANDARD` entry for itself and associated
`AmazonEKSClusterAdminPolicy` with cluster scope. A fresh token then made
`kubectl auth can-i '*' '*' --all-namespaces` return `yes` against the real Kubernetes API.

The proof needed no `DescribeCluster`, `iam:PassRole`, node role, managed node group, or workload.
It does require a cluster authentication mode containing `API`, a known cluster name/endpoint/CA,
and permission for both control-plane actions. When EKS reads are denied, those values can appear
in kubeconfig files, IaC state, deployment output, CI/CD variables, CloudTrail, logs, errors,
application configuration, and console URLs.

An independent second cluster tested whether `CreateAccessEntry` alone could specify the built-in
Kubernetes `system:masters` group. EKS rejected it with `InvalidParameterException` because group
names cannot start with `system:`. The singleton was therefore not promoted; the two-action pair is
the validated Critical result. Both access entries and clusters were deleted and polled absent,
then their roles, users, every access key, policies, generated ENIs/security groups, and exact local
kubeconfig files were removed. All exact-prefix inventories returned empty.

### CodeConnections and agent-channel prerequisite review — 2026-09-08

`codeconnections:UseConnection` is a permissions-only authorization gate used by integrated
consumers; the current caller-facing CodeConnections API exposes no operation that returns its
installation token or private repository contents. The account contains five AVAILABLE real
GitHub/Bitbucket connections, which were deliberately not consumed or altered. Exploitation also
needs a consumer operation such as CodeBuild/CodePipeline create or update plus its service-role and
often `iam:PassRole` prerequisites. No standalone CodeConnections technique was promoted; impact
must be attributed to and tested through the actual consumer.

The current AWS CLI contains no `ec2messages` or `ssmmessages` service model, and Systems Manager
reported no managed nodes. The former is an agent message-delivery plane; the latter's control/data
channel operations require managed-node/session material such as the stream token issued by
`StartSession`. With neither a node nor token, ordinary IAM-user calls cannot reach an independent
channel target. Both prefixes are `blocked`, not negative, until an authorized managed-node fixture
can test stolen-token and cross-node controls.

SageMaker geospatial was reachable only in `us-west-2` during the regional check and contained no
Earth Observation jobs; `eu-west-1` returned a service/authorization-resolution error. Testing job
reads or exports requires a synthetic source collection, job, and execution role, so that prefix is
also retained as blocked rather than inferred safe.

### Amazon S3 Object Lambda (`s3-object-lambda`) — 2026-09-08

The Q16 access-point-policy self-grant hypothesis is blocked by service eligibility. The synthetic
fixture successfully created a private source bucket/object, supporting S3 access point, published
Lambda transformer version, and an execution role limited to `WriteGetObjectResponse`. AWS then
rejected `CreateAccessPointForObjectLambda` with the explicit statement that S3 Object Lambda is
available only to existing customers already using the service and selected APN partners. The
authorized account has no pre-existing Object Lambda access point.

No policy was set and no transformed read was attempted, so there is no positive or negative claim
about `PutObjectLambdaAccessPointPolicy`. The supporting access point, Lambda function/version,
execution role and policy, object and bucket were deleted. The failure occurred before disposable
reader users were created. Exact Object Lambda access-point, S3 access-point/bucket, Lambda, IAM
user/role inventories returned empty, and the local source and ZIP were removed.

### Amazon OpenSearch Service (`es`) — 2026-09-08

`es:UpdateDomainConfig` alone was validated as a domain resource-policy takeover. A synthetic
public HTTPS domain initially allowed only the lab administrator, which inserted a randomized
canary. The least-privilege test user had only `UpdateDomainConfig` on the exact domain ARN: a
signed data-plane request returned HTTP 403 before the change, `ListDomainNames` was denied, and an
empty-permission control could not update the domain. The test user then replaced the access policy
with one granting its own ARN only `es:ESHttpGet` on that domain's subresources. After processing
completed, the same signed request returned HTTP 200 and the exact canary.

The result requires a known domain name and a reachable endpoint; VPC placement, fine-grained
access control, explicit denies, and customer-managed KMS authorization can impose additional
boundaries. One preliminary harness failed on an empty Bash-array expansion before creating users
or a canary; that domain was also deleted. Both domains reached deletion, every test user, access
key, and policy was removed, and exact-prefix domain and user inventories returned empty.

The catalog's separate `opensearch` IAM prefix is for OpenSearch Applications, direct query, and
auto-optimize operations; it is not an alias for `es`. `ListApplications` returned empty in both
`eu-west-1` and `us-east-1`, so application login/query hypotheses remain blocked without a
disposable application. The validated managed-domain result is attributed only to `es`.

### Amazon EKS Auth (`eks-auth`) — 2026-09-08

`eks-auth:AssumeRoleForPodIdentity` was validated as a credential-access primitive when the caller
has a live Pod-bound EKS service-account token. The least-privilege IAM user had only that action
on `Resource: *`; it was denied EKS cluster listing and direct access to a synthetic S3 canary. An
empty-permission user could not exchange the same token, and changing one token character caused
`InvalidTokenException`. With the valid token, the candidate received the role associated with
the `proof/reader` service account and those temporary credentials read the exact canary.

The token prerequisite is material. A service-account-only token with the correct
`pods.eks.amazonaws.com` audience was rejected because it lacked the required
`kubernetes.io/pod` claim. The successful proof used a TokenRequest bound to a real, unscheduled
Pod object and therefore included the live Pod UID; no worker node or workload execution was
needed. The action does not let a caller choose an arbitrary role: EKS resolves the existing Pod
Identity association for the token's cluster, namespace, service account, and Pod binding.

The association, Pod/namespace, no-node cluster, bucket/object, cluster and pod roles, IAM users,
access keys, policies, generated cluster security group, and local kubeconfig were deleted. The
returned temporary credentials were never printed or persisted, and the only resource they could
read was deleted during cleanup. Exact-prefix cluster, role, user, and bucket inventories returned
empty.

### AWS Config (`config`) — 2026-09-08

The Q03 remediation hypothesis did not produce an independent escalation. A complete disposable
recorder and delivery channel evaluated a synthetic IAM user as `NON_COMPLIANT`; a custom SSM
Automation document stored a constant execution-role ARN whose only privilege was writing a proof
object. The candidate had exactly `config:PutRemediationConfigurations` and
`config:StartRemediationExecution`, while an empty-permission control was denied.

The candidate could configure the document and request manual remediation without
`iam:PassRole`, but Config reported `FAILED` at `Initialization`: the initiating user lacked the
necessary Systems Manager and resource permissions. No SSM Automation execution existed and no
proof object was written. The account initially lacked `AWSServiceRoleForConfigRemediation`, so a
service-linked role was created before the final run; its presence did not remove the initiator
permission check. Adding direct SSM execution and resource authority would collapse the path into
the already documented `ssm:StartAutomationExecution` technique rather than make the Config pair a
separate primitive.

Two preliminary fixtures were also removed: one exposed that the managed rule keys IAM resources
by immutable `UserId`, and one hit access-key propagation before authorization. All Config rules,
recorders, delivery channels, documents, buckets, objects, prefixed roles/users, keys, and policies
were deleted. IAM service-linked-role deletion initially returned transient internal errors with an
empty usage list; a later deletion task reached `SUCCEEDED`, and `GetRole` returned `NoSuchEntity`.

### Amazon Redshift (`redshift`) and Data API (`redshift-data`) — 2026-09-09

Two provisioned-cluster credential actions were independently validated without discovery
permissions. One IAM user had exactly `redshift:GetClusterCredentials`; a second had exactly
`redshift:GetClusterCredentialsWithIAM`; both used `Resource: *` for the isolated authorization
test and both were denied `DescribeClusters`. Each API returned a temporary username/password,
and each credential set connected to the synthetic cluster over TLS and selected the randomized
canary. An empty-permission control was denied both credential calls. `DescribeClusters` is thus a
discovery convenience, not part of either minimum credential path; a known cluster ID, endpoint,
database, and applicable database-user privileges are the material prerequisites.

The same fixture rejected two Data API bypass hypotheses. A user with only
`redshift-data:GetStatementResult` supplied a valid completed statement UUID created by the lab
administrator, but the API returned `ResourceNotFoundException: Query does not exist`; the
empty-permission control was denied. Replacing that policy with exactly
`redshift-data:ExecuteStatement` plus `redshift-data:GetStatementResult` still could not submit the
query without underlying Redshift authentication authority. A provisioned-cluster Data API path
therefore also needs `redshift:GetClusterCredentials`/`GetClusterCredentialsWithIAM`, or a
secret-based path and its separate Secrets Manager authorization, so those impacts are not
attributed to the Data API actions alone.

The test used the region's smallest currently orderable single-node class, `ra3.large`; obsolete
`dc2.large`, zero-retention, and unencrypted create requests were rejected before provisioning and
their support resources were removed. Both completed clusters were deleted without final
snapshots. All automated/manual snapshots, subnet groups, ingress security groups, IAM users,
access keys, policies, and the temporary PostgreSQL driver directory were re-enumerated absent.

### AWS KMS (`kms`) — 2026-09-08

The isolated `kms:CreateGrant` self-grant test is blocked by the mandatory cleanup requirement. The
authorized region currently contains only AWS-managed keys; customers cannot manage grants or key
policies on those keys. Creating a customer-managed test key would leave it in `PendingDeletion`
for AWS's mandatory 7–30-day waiting period, so it could not be destroyed in this review session.
No KMS key, alias, ciphertext, grant, user, or policy was created. Existing documented KMS attack
paths remain classified, but this pass makes no new live-validation claim.

### AWS Private Certificate Authority (`acm-pca`) — 2026-09-08

The planned certificate-issuance and mTLS impersonation test is also blocked by cleanup semantics.
There is no existing private CA in the authorized region. A newly created private CA that reaches
`PENDING_CERTIFICATE` or `DISABLED` remains in a restorable `DELETED` state for a mandatory 7–30
days. Creating it would therefore violate the requirement to remove all infrastructure before the
test completes. No CA, certificate, role, user, policy, or relying service was created, and no
issuance-impact claim is added from this pass.
