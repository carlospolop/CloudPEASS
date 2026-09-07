# Cloud Privilege Escalation Awesome Script Suite 🚀🛡️

![/cloudpeass.png](/cloudpeass.png)

Welcome to the **Cloud Privilege Escalation Awesome Script Suite** – your one-stop solution to **find your permissions** whenever you compromise a principal in a **Red Team** across major cloud platforms: **Azure, GCP, and AWS**. This suite is designed to help you determine all your permissions and also what it's possible to accomplish with them, focusing on **privilege escalation** and accessing **sensitive information** 🔥, and other potential attack vectors **without modifying any resources**.

This toolkit leverages advanced techniques to enumerate your permissions (it uses different permission enumeration techniques depending on the cloud) and utilizes insights from **[HackTricks Cloud](https://cloud.hacktricks.wiki/en/index.html)** plus a curated permissions catalog (**Blue-CloudPEASS**) to classify permissions as **critical / high / medium / low**.

---

<details>
<summary><h2>AzurePEAS 💼🖥️</h2></summary>

**AzurePEAS** enumerates the effective permissions of a compromised user, service principal, or managed identity in Azure Resource Manager and Microsoft Entra ID. It performs no Azure write/delete operations and never executes commands inside workloads.

### Enumeration order and fallbacks

1. **Token claims (no directory permissions required):** identifies the principal and records Graph `scp`, `roles`, and `wids` claims. These are useful even when every Graph enumeration endpoint returns `403`.
2. **Effective ARM permissions:** asks Azure's permissions endpoint at every discovered subscription, resource group, resource, management group, and explicitly supplied scope. This does not require permission to list IAM role assignments.
3. **IAM reconstruction:** when allowed, lists transitive ARM/Entra assignments, role definitions, conditions, and PIM-eligible roles. Failure here does not stop other methods.
4. **Resource discovery evidence:** successful read-only subscription, resource-group, and resource calls are reported even when IAM cannot be read.
5. **Azure CLI fallback:** when `--use-az-cli` is used and ARM returns no permissions, AzurePEAS can probe Azure CLI commands that are demonstrably read-only and require no arguments. It uses no shell, disables dynamic extension installation and prompts, and skips unknown or potentially state-changing commands. Use `--azure-services` to make this faster or `--skip-az-cli-fallback` to disable it.

If resource listing is denied but you know an ARM resource ID from a VM's metadata, logs, scripts, or a previous foothold, pass it with `--scopes`. AzurePEAS will query that scope directly. This is the most reliable low-permission fallback.

### Authentication

- Reuse an existing Azure CLI login: `--use-az-cli` (recommended when available).
- Supply ARM/Graph access tokens with arguments or `AZURE_ARM_TOKEN` / `AZURE_GRAPH_TOKEN`.
- Use device code with MFA by running without credentials.
- Use username/password or service-principal credentials with `--use-username-password` (legacy; no MFA).
- Supply an existing FOCI refresh token with `--foci-refresh-token` to try the optional M365 checks.

Tokens are never printed. Prefer environment variables over command-line arguments because command-line values may be visible in process listings. `AZURE_PASSWORD` and `AZURE_FOCI_REFRESH_TOKEN` are supported.

Known ARM and Microsoft Graph audiences for Azure public, US Government/DoD, and China clouds (plus legacy Germany ARM) are routed only to their matching trusted API host. Azure CLI authentication follows the cloud configured in `az`; optional FOCI/M365 features still depend on service availability in that cloud.

### Microsoft 365 quick checks

With a usable FOCI refresh token, AzurePEAS performs bounded, read-only checks for SharePoint, OneDrive, Outlook, Teams, OneNote, contacts, and tasks. Use `--not-enumerate-m365` to omit them. These checks indicate accessible data; they are not intended to download a complete tenant.

### Examples

```bash
# Reuse the current az login and enumerate one subscription
python3 AzurePEAS.py --use-az-cli --check-only-these-subs <SUBSCRIPTION_ID>

# Tokens from the environment
export AZURE_ARM_TOKEN="<ARM_TOKEN>"
export AZURE_GRAPH_TOKEN="<GRAPH_TOKEN>"
python3 AzurePEAS.py --no-ask

# Resource-list fallback: check exact known scopes directly
python3 AzurePEAS.py --arm-token "<TOKEN>" \
  --check-only-these-subs <SUBSCRIPTION_ID> \
  --scopes "/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RG>/providers/Microsoft.KeyVault/vaults/<VAULT>"

# Limit the last-resort CLI probes
python3 AzurePEAS.py --use-az-cli --azure-services vm,keyvault,storage

# ARM only, JSON report
python3 AzurePEAS.py --use-az-cli --skip-entraid --out-json-path azure-results.json

# Full option reference
python3 AzurePEAS.py --help
```

</details>

---

<details>
<summary><h2>GCPPEAS 🌐🔍</h2></summary>

**GCPPEAS** enumerates the current principal's effective GCP permissions and highlights privilege-escalation and sensitive-access paths. Its transport rejects non-read-only endpoints: it never creates, changes, enables, executes, invokes, starts, stops, or deletes cloud resources.

### How it works

GCPPEAS layers several independent techniques so a denied enumeration call does not stop the scan:

1. **Permissionless/local clues:** explicit `--project`, `--service-account`, and repeatable `--resource` values are always tested. On a GCP workload, the metadata server supplies the current project, VM, and attached service account without IAM permissions. Credential and standard project environment variables are also used.
2. **Container and resource discovery:** Resource Manager search, Cloud Asset Inventory, and independent service-specific list calls discover projects, folders, organizations, VMs, Functions, buckets, service accounts, secrets, Cloud Run services/jobs, Artifact Registry repositories, Pub/Sub topics/subscriptions/snapshots, BigQuery datasets/tables/routines, Workflows, KMS key rings/keys, and Cloud DNS managed zones. Each failure is isolated and summarized; regional fallbacks continue when only some locations are denied.
3. **Effective permission tests:** Google's `queryTestablePermissions` supplies the current, resource-applicable catalog and `testIamPermissions` checks it in batches. These methods avoid parsing platform-dependent `gcloud help` output. If catalog lookup fails, GCPPEAS falls back to official predefined roles, a public catalog, and finally a built-in core set. Failed or partial tests are reported rather than silently treated as zero permissions.
4. **IAM policy supplement:** where `getIamPolicy` is allowed, direct/public/domain/known-group bindings and custom roles add context. Static grants are never merged over a successful effective test because IAM Deny, principal access boundaries, or request conditions may block them. If effective testing is unavailable, policy permissions are retained but clearly labeled as unverified. BigQuery datasets, which do not expose a dataset-level `testIamPermissions` method, use read-only metadata/list capability probes; BigQuery itself documents that table/routine tests can fail open.

Knowing a resource name is often enough to test permissions even when the principal cannot list its parent. Examples:

```bash
python3 GCPPEAS.py --project victim-project --only-specified
python3 GCPPEAS.py --resource gs://known-bucket --only-specified
python3 GCPPEAS.py --resource projects/victim-project/secrets/known-secret --only-specified
python3 GCPPEAS.py --resource projects/victim-project/datasets/known_dataset/tables/known_table --only-specified
python3 GCPPEAS.py --resource //run.googleapis.com/projects/victim-project/locations/us-central1/services/known-service --only-specified
python3 GCPPEAS.py --resource dns-zone:projects/victim-project/managedZones/known-zone --only-specified
```

`--billing-project` only sets the quota-project header; GCPPEAS never enables an API or changes billing/IAM. Read calls and `testIamPermissions` can still appear in audit or access logs, so read-only does not mean invisible.

### Authentication

Authentication follows the same fallback style as the other PEASS tools:

- `--token`, then `CLOUDSDK_AUTH_ACCESS_TOKEN`
- `--sa-credentials-path`, then `GOOGLE_APPLICATION_CREDENTIALS`
- Application Default Credentials, including workload metadata credentials

Examples:

```bash
# Existing gcloud user session
export CLOUDSDK_AUTH_ACCESS_TOKEN="$(gcloud auth print-access-token)"
python3 GCPPEAS.py --project victim-project --only-specified

# Service-account JSON
python3 GCPPEAS.py --sa-credentials-path credentials.json --project victim-project

# ADC / attached workload identity
python3 GCPPEAS.py

# Keep output locally for later analysis
python3 GCPPEAS.py --project victim-project --out-json-path gcp-results.json
```

GCPPEAS reports Workspace-capable OAuth scopes—including Gmail, Drive, Calendar, Admin SDK, Chat, Classroom, and editors—but does not automatically read Workspace content. A token containing both Workspace and Cloud scopes is called out as a cross-control-plane credential. Service-account impersonation/signing/key permissions now distinguish directly shared Workspace resources (which do not require domain-wide delegation) from user impersonation through DWD. Complete Cloud DNS record-write pairs and user access to organization `setIamPolicy` also receive concise GCP↔Workspace pivot notes with their required conditions and known-resource fallbacks.

### Useful controls

- `--only-specified`: avoid broad container searches and scan only supplied projects/resources.
- `--skip-iam-policies`: use the permissionless `testIamPermissions` path without policy reads.
- `--skip-bruteforce`: policy-only mode; usually less complete.
- `--skip-asset-inventory`: use service-specific discovery fallbacks only.
- `--resource`: repeat for known resource names; comma-separated values are also accepted.
- `--billing-project`: quota project only; no state change.
- `--threads`, `--timeout`, `--retries`: bound concurrency and transient failures.
- `--proxy`, `--insecure`, `--debug`: troubleshooting controls.

Run `python3 GCPPEAS.py --help` for the complete current option list.

</details>

---

<details>
<summary><h2>AWSPEAS ⚡️🔐</h2></summary>

**AWSPEAS** enumerates the current AWS principal's permissions and highlights privilege-escalation and sensitive-access opportunities while leaving the target unchanged. It never calls AWS create, update, delete, invoke, run, start, send, or execute operations.

### How It Works

AWSPEAS uses three permission-free-or-read-only fallbacks:

1. **IAM policy reads:** Reads the current user or role, all paginated inline/attached/group policies, managed-policy default versions, resource scopes, conditions, explicit denies, `NotAction`, `NotResource`, and permissions boundaries. If granular calls are blocked, it tries `GetAccountAuthorizationDetails` independently.

2. **IAM simulation:** If policy visibility is partial, empty, conditional, or boundary-limited, it tries `SimulatePrincipalPolicy`. Simulation is read-only and does not execute the tested actions. Because AWS otherwise evaluates resource-scoped actions against `*`, AWSPEAS uses explicitly supplied `--resource-arn` values and safely discovered Secrets Manager ARNs for a second resource-specific pass. Assumed-role sessions are resolved to their IAM role ARN when IAM permits it. The AWS action catalog falls back to installed botocore models when the online AWS catalog is unavailable.

3. **Live read-only probes:** If both methods above are incomplete, AWSPEAS tests only read command families (`List`, `Get`, `Describe`, `BatchGet`, `Head`, `Lookup`, and `Search`). The AWS CLI is optional unless this fallback is needed. Help parsing supports plain, groff, and Unicode bullet formats, with botocore service models as an OS-independent fallback. Use `--aws-services` to limit requests or `--bruteforce-always` to check for resource-policy access even after complete IAM reads.

Optional managed-policy inference can suggest unconfirmed permissions from successful live probes. Inferred permissions are labeled separately and must not be treated as confirmed.

AWS authorization can also depend on SCPs, RCPs, session policies, resource policies, VPC endpoint policies, request context, and service-specific behavior. AWSPEAS reports these limitations rather than presenting static policy statements as universally effective access.

### Operational Security Considerations ⚠️

- **Canary detection:** AWSPEAS first tries to decode the account ID locally from modern AKIA/ASIA access-key IDs. This can stop before the first STS call for known canary accounts. It then checks the returned ARN/name for canary patterns. With `--no-ask`, a possible canary stops safely.
- **CloudTrail:** Read calls can still be logged. "Read-only" means no target state is intentionally changed, not that the scan is invisible.


### Authentication & Execution Requirements

AWSPEAS accepts an AWS profile, explicit credentials, or the normal boto3 credential chain (environment variables, container/instance roles, web identity, and configured defaults). A region is optional; it uses the session/environment region and then `us-east-1`. The AWS CLI is needed only for live probes.

### AWSPEAS Help & Usage

- **Help:**  
  To view all the command options, run:

```bash
python3 ./AWSPEAS.py --help

usage: AWSPEAS.py [-h] [--profile PROFILE | --access-key-id ACCESS_KEY_ID]
                  [--secret-access-key SECRET_ACCESS_KEY] [--session-token SESSION_TOKEN]
                  [--region REGION] [--out-json-path OUT_JSON_PATH] [--threads THREADS]
                  [--debug] [--aws-services AWS_SERVICES] [--skip-iam-policies]
                  [--resource-arn RESOURCE_ARN]
                  [--skip-simulation] [--skip-bruteforce] [--bruteforce-always]
                  [--skip-managed-policies-guess] [--no-ask]

options:
  -h, --help            show this help message and exit
  --profile PROFILE     AWS profile (otherwise use the normal AWS credential chain)
  --access-key-id ACCESS_KEY_ID
                        AWS Access Key ID
  --secret-access-key SECRET_ACCESS_KEY
                        AWS Secret Access Key (required with --access-key-id)
  --session-token SESSION_TOKEN
                        AWS Session Token (optional, for temporary credentials)
  --out-json-path OUT_JSON_PATH
                        Output JSON file path (e.g. /tmp/aws_results.json)
  --threads THREADS     Number of threads to use
  --debug               Print more infromation when brute-forcing permissions
  --region REGION       Region for regional probes (optional)
  --aws-services AWS_SERVICES
                        Filter AWS services to brute-force permissions for indicating them as a comma separated list (e.g. --aws-services
                        s3,ec2,lambda,rds,sns,sqs,cloudwatch,cloudfront,iam,dynamodb)
  --resource-arn RESOURCE_ARN
                        Known ARN to test with resource-specific IAM simulation; repeat the option or pass comma-separated ARNs
  --skip-iam-policies   Skip retrieving permissions from IAM policies
  --skip-simulation     Skip simulating permissions using simulate-principal-policy
  --skip-bruteforce     Skip brute-force enumeration (automatic by default when IAM/simulation fail)
  --bruteforce-always   Run live read-only probes even when policy enumeration is complete
  --skip-managed-policies-guess
                        Skip guessing permissions based on AWS managed policies
  --no-ask              Do not prompt; use defaults (but stop safely on possible canary credentials)
```

- **Usage Examples:**  

```bash
# Normal AWS credential chain (environment, role, or default profile)
python3 AWSPEAS.py

# Named profile; region is optional
python3 AWSPEAS.py --profile <AWS_PROFILE> --region <AWS_REGION> --no-ask

# Test a known resource ARN when it cannot be discovered with a safe List API
python3 AWSPEAS.py --profile <AWS_PROFILE> --resource-arn arn:aws:s3:::known-bucket --no-ask

# Using AWS credentials directly (Access Key + Secret Key)
python3 AWSPEAS.py --access-key-id <ACCESS_KEY_ID> --secret-access-key <SECRET_ACCESS_KEY> --region <AWS_REGION>

# Using temporary credentials (Access Key + Secret Key + Session Token)
python3 AWSPEAS.py --access-key-id <ACCESS_KEY_ID> --secret-access-key <SECRET_ACCESS_KEY> --session-token <SESSION_TOKEN> --region <AWS_REGION>

# Usage with specific AWS services (faster brute-force if needed)
python3 AWSPEAS.py --profile <AWS_PROFILE> --region <AWS_REGION> --aws-services s3,ec2,lambda,rds,sns,sqs,cloudwatch,cloudfront,iam,dynamodb

# Skip IAM and simulation, go directly to brute-force
python3 AWSPEAS.py --profile <AWS_PROFILE> --region <AWS_REGION> --skip-iam-policies --skip-simulation

# Only use IAM policies (skip simulation and brute-force)
python3 AWSPEAS.py --profile <AWS_PROFILE> --region <AWS_REGION> --skip-simulation --skip-bruteforce

# Try IAM and simulation, but never brute-force
python3 AWSPEAS.py --profile <AWS_PROFILE> --region <AWS_REGION> --skip-bruteforce

# Live read-only fallback only
python3 AWSPEAS.py --profile <AWS_PROFILE> --region <AWS_REGION> --skip-iam-policies --skip-simulation --skip-managed-policies-guess

# Also probe for read access granted by resource policies
python3 AWSPEAS.py --profile <AWS_PROFILE> --aws-services s3api,sqs,sns --bruteforce-always
```

</details>
