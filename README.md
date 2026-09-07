# Cloud Privilege Escalation Awesome Script Suite 🚀🛡️

![/cloudpeass.png](/cloudpeass.png)

Welcome to the **Cloud Privilege Escalation Awesome Script Suite** – your one-stop solution to **find your permissions** whenever you compromise a principal in a **Red Team** across major cloud platforms: **Azure, GCP, and AWS**. This suite is designed to help you determine all your permissions and also what it's possible to accomplish with them, focusing on **privilege escalation** and accessing **sensitive information** 🔥, and other potential attack vectors **without modifying any resources**.

This toolkit leverages advanced techniques to enumerate your permissions (it uses different permission enumeration techniques depending on the cloud) and utilizes insights from **[HackTricks Cloud](https://cloud.hacktricks.wiki/en/index.html)** plus a curated permissions catalog (**Blue-CloudPEASS**) to classify permissions as **critical / high / medium / low**.

---

<details>
<summary><h2>AzurePEAS 💼🖥️</h2></summary>

**AzurePEAS** is dedicated to **enumerating the principals permissions** within your **Azure** and **Entra ID** environments, with a special focus on detecting **privilege escalation pathways** and identifying **potential security risks**. It can also **enumerate several Microsoft 365** services for a quick recon. Here are the key features and requirements:

- **Comprehensive Permissions Check**  
  AzurePEAS finds all resources accessible to the principal and the permissions he has over them. It retrieves permissions for both **Azure (ARM API)** and **Entra ID (Graph API)**, ensuring a thorough analysis of your cloud permissions.

- **Authentication Requirements**  
  AzurePEAS supports multiple authentication methods:
  - **Device Code Flow (Default):** Simply run without parameters for interactive browser-based authentication (supports MFA) 🔐
  - **Pre-existing Tokens:** Provide **ARM** and/or **Graph** tokens directly
  - **Username/Password:** Use `--use-username-password` flag for automation (non-MFA accounts only)
  - **FOCI Refresh Token:** Generate tokens and access M365 services
  
  **Note:** Most permissions can be collected without needing extra enumeration privileges. However, some specific operations might need additional scopes.

- **Microsoft 365 Enumeration (M356)**  
  If you provide AzurePEAS with a **FOCI refresh token** or valid **credentials (username and password)**, it extends its scanning capabilities to enumerate various **Microsoft 365** services, including:
  - **SharePoint** 📂
  - **OneDrive** ☁️
  - **Outlook** 📧
  - **Teams** 💬
  - **OneNote** 📝
  - **Contacts** 👥
  - **Tasks** ✅

  This additional enumeration is intended to indicate whether any data exists in these services, enabling further manual investigation if needed. The process is not exhaustive but serves as a useful preliminary check.

### AzurePEAS Help

To see the complete list of options, run:

```bash
python3 ./AzurePEAS.py --help

usage: AzurePEAS.py [-h] [--tenant-id TENANT_ID] [--arm-token ARM_TOKEN] [--graph-token GRAPH_TOKEN] [--foci-refresh-token FOCI_REFRESH_TOKEN] [--not-enumerate-m365] [--skip-entraid]
                    [--username USERNAME] [--password PASSWORD] [--use-username-password] [--check-only-these-subs CHECK_ONLY_THESE_SUBS] [--out-json-path OUT_JSON_PATH]
                    [--threads THREADS]

Run AzurePEASS to find all your current privileges in Azure and EntraID and check for potential privilege escalation attacks. To check for Azure permissions an ARM token is needed.
To check for Entra ID permissions a Graph token is needed.

options:
  -h, --help            show this help message and exit
  --tenant-id TENANT_ID
                        Indicate the tenant id
  --arm-token ARM_TOKEN
                        Azure Management authentication token
  --graph-token GRAPH_TOKEN
                        Azure Graph authentication token
  --foci-refresh-token FOCI_REFRESH_TOKEN
                        FOCI Refresh Token
  --not-enumerate-m365  Don't enumerate M365 permissions
  --skip-entraid        Skip EntraID permissions enumeration and only focus on Azure subscriptions
  --username USERNAME   Username for authentication (used with --use-username-password)
  --password PASSWORD   Password for authentication (used with --use-username-password)
  --use-username-password
                        Use username/password flow instead of device code flow (only works without MFA)
  --check-only-these-subs CHECK_ONLY_THESE_SUBS
                        In case you just want to check specific subscriptions, provide a comma-separated list of subscription IDs (e.g. 'sub1,sub2')
  --out-json-path OUT_JSON_PATH
                        Output JSON file path (e.g. /tmp/azure_results.json)
  --threads THREADS     Number of threads to use
```

### AzurePEAS Usage Examples

**1. Simple Interactive Authentication (Recommended)** �

Just run with no parameters for device code flow (works with MFA):

```bash
# Simplest - prompts for tenant or uses 'organizations'
python3 AzurePEAS.py

# With tenant auto-discovery from email domain
python3 AzurePEAS.py --username user@domain.com
```

**2. Obtaining Tokens Manually** 🔑

If you prefer to generate tokens beforehand:

```bash
# Get Azure ARM token
export AZURE_ARM_TOKEN=$(az account get-access-token --resource-type arm | jq -r .accessToken)

# Get Azure Graph token
export AZURE_GRAPH_TOKEN=$(az account get-access-token --resource-type ms-graph | jq -r .accessToken)

# Get Graph Token with enough scopes (use powershell)
Connect-MgGraph -Scopes "RoleAssignmentSchedule.Read.Directory"
$Parameters = @{
    Method     = "GET"
    Uri        = "/v1.0/me"
    OutputType = "HttpResponseMessage"
}
$Response = Invoke-MgGraphRequest @Parameters
$Headers = $Response.RequestMessage.Headers
$Headers.Authorization.Parameter
```

**3. Running AzurePEAS Using Pre-existing Tokens**

Provide tokens via command line or environment variables:

```bash
python3 AzurePEAS.py --arm-token <TOKEN> --graph-token <TOKEN>
# or use environment variables
export AZURE_ARM_TOKEN=<TOKEN>
export AZURE_GRAPH_TOKEN=<TOKEN>
python3 AzurePEAS.py
```

**4. Username/Password Authentication (Non-MFA or Service Principals)** ⚠️

For automation scripts with non-MFA accounts:

```bash
python3 AzurePEAS.py --use-username-password --username <USERNAME> --password <PASSWORD>
```

**5. Using FOCI Refresh Token**

For M365 enumeration capabilities:

```bash
python3 AzurePEAS.py --tenant-id <TENANT_ID> --foci-refresh-token <TOKEN>
```

**6. Focus on Azure Subscriptions Only**

Skip EntraID and M365 enumeration to only check Azure subscription permissions:

```bash
python3 AzurePEAS.py --skip-entraid
```

**7. Check Specific Subscriptions Only**

Limit enumeration to specific subscriptions:

```bash
python3 AzurePEAS.py --check-only-these-subs <SUB_ID1>,<SUB_ID2>
```

</details>

---

<details>
<summary><h2>GCPPEAS 🌐🔍</h2></summary>

**GCPPEAS** enumerates the current principal's effective GCP permissions and highlights privilege-escalation and sensitive-access paths. Its transport rejects non-read-only endpoints: it never creates, changes, enables, executes, invokes, starts, stops, or deletes cloud resources.

### How it works

GCPPEAS layers several independent techniques so a denied enumeration call does not stop the scan:

1. **Permissionless/local clues:** explicit `--project`, `--service-account`, and repeatable `--resource` values are always tested. On a GCP workload, the metadata server supplies the current project, VM, and attached service account without IAM permissions. Credential and standard project environment variables are also used.
2. **Container and resource discovery:** Resource Manager search, Cloud Asset Inventory, and independent service-specific list calls discover projects, folders, organizations, VMs, Functions, buckets, service accounts, secrets, Cloud Run services/jobs, Artifact Registry repositories, Pub/Sub resources, BigQuery datasets, Workflows, and KMS keys. Each failure is isolated and summarized.
3. **Effective permission tests:** Google's `queryTestablePermissions` supplies the current, resource-applicable catalog and `testIamPermissions` checks it in batches. These methods avoid parsing platform-dependent `gcloud help` output. If catalog lookup fails, GCPPEAS falls back to official predefined roles, a public catalog, and finally a built-in core set.
4. **IAM policy supplement:** where `getIamPolicy` is allowed, direct/public/domain/known-group bindings and custom roles add context. Conditional bindings are not assumed to apply; the effective test decides the current result. BigQuery datasets, which do not expose a dataset-level `testIamPermissions` method, use read-only metadata/list capability probes.

Knowing a resource name is often enough to test permissions even when the principal cannot list its parent. Examples:

```bash
python3 GCPPEAS.py --project victim-project --only-specified
python3 GCPPEAS.py --resource gs://known-bucket --only-specified
python3 GCPPEAS.py --resource projects/victim-project/secrets/known-secret --only-specified
python3 GCPPEAS.py --resource //run.googleapis.com/projects/victim-project/locations/us-central1/services/known-service --only-specified
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

GCPPEAS reports Gmail/Drive-capable OAuth scopes but does not automatically read mailbox or Drive content.

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

2. **IAM simulation:** If policy visibility is partial, empty, conditional, or boundary-limited, it tries `SimulatePrincipalPolicy`. Simulation is read-only and does not execute the tested actions. Assumed-role sessions are resolved to their IAM role ARN when IAM permits it. The AWS action catalog falls back to installed botocore models when the online AWS catalog is unavailable.

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
