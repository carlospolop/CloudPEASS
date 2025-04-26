# Cloud Privilege Escalation Awesome Script Suite 🚀🛡️

![/cloudpeass.jpg](/cloudpeass.jpg)

Welcome to the **Cloud Privilege Escalation Awesome Script Suite** – your one-stop solution to **find your permissions** whenever you compromise a principal in a **Red Team** across major cloud platforms: **Azure, GCP, and AWS**. This suite is designed to help you determine all your permissions and also what it's possible to accomplish using compromised them, focusing on **privilege escalation** and accessing **sensitive information** 🔥, and other potential attack vectors **without modifying any resources**.

This toolkit leverages advanced techniques to enumerate your permissions (it uses different permission enumreation tehcniques depending on the cloud) and utilizes insights from **[HackTricks Cloud](https://cloud.hacktricks.wiki/en/index.html)** as well as **HackTricks AI** 🤖 to map sensitive permissions to potential attacks. Note that **no sensitive data is sent to the AI, only names of resources and permissions**, but if you prefer not to use the AI analysis, simply append the **`--not-use-hacktricks-ai`** flag when executing the tools.

---

## AzurePEAS 💼🖥️

**AzurePEAS** is dedicated to **enumerating the principals permissions** within your **Azure** and **Entra ID** environments, with a special focus on detecting **privilege escalation pathways** and identifying **potential security risks**. It can also **enumerate several Microsoft 365** services for a quick recon. Here are the key features and requirements:

- **Comprehensive Permissions Check**  
  AzurePEAS finds all resources accessible to the principal and the permisions he has over them. It retrieves permissions for both **Azure (ARM API)** and **Entra ID (Graph API)**, ensuring a thorough analysis of your cloud permissions.

- **Authentication Requirements**  
  To operate effectively, AzurePEAS requires:
  - A token with access to the **Azure ARM API** to find all the resources and permissions of the principal has inside Azure Management.
  - A token with access to the **Azure Graph API** to find all the resources and permissions of the principal has inside Entra ID.
  - If a **FOCI refresh token** or valid **credentials (username and password)** are provided, AzurePEAS can generate the previous tokens itself and also enumerate various Microsoft 365 services.
  
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
usage: AzurePEAS.py [-h] [--tenant-id TENANT_ID] [--arm-token ARM_TOKEN] [--graph-token GRAPH_TOKEN] [--foci-refresh-token FOCI_REFRESH_TOKEN] [--not-enumerate-m365]
                    [--username USERNAME] [--password PASSWORD] [--out-json-path OUT_JSON_PATH] [--threads THREADS] [--not-use-hacktricks-ai]

Run AzurePEASS to find all your current privileges in Azure and EntraID and check for potential privilege escalation attacks. To check for Azure permissions an ARM token
is needed. To check for Entra ID permissions a Graph token is needed.

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
  --username USERNAME   Username for authentication
  --password PASSWORD   Password for authentication
  --out-json-path OUT_JSON_PATH
                        Output JSON file path (e.g. /tmp/azure_results.json)
  --threads THREADS     Number of threads to use
  --not-use-hacktricks-ai
                        Don't use Hacktricks AI to analyze permissions
```

### AzurePEAS Usage Examples

**1. Obtaining Tokens** 🔑

Before executing the script, generate your tokens with the following commands:

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

**2. Running AzurePEAS Using Tokens**

You can run AzurePEAS by either providing the tokens via the command line or by having them set as environment variables:

```bash
python3 AzurePEAS.py [--arm-token <AZURE_MANAGEMENT_TOKEN>] [--graph-token <AZURE_GRAPH_TOKEN>]
```

**3. Running AzurePEAS Using Credentials/FOCI token for improved enumeration**

For additional enumeration of Microsoft 365 services, you can supply:

- A **FOCI refresh token**:

  ```bash
  python3 AzurePEAS.py [--tenant-id <TENANT_ID>] [--foci-refresh-token <FOCI_REFRESH_TOKEN>]
  ```

- **Username and password credentials**:

  ```bash
  python3 AzurePEAS.py [--username <USERNAME>] [--password <PASWORD>]
  ```

---


## GCPPEAS 🌐🔍

**GCPPEAS** is designed to enumerate **all your permissions on Google Cloud Platform (GCP)**, uncovering potential **privilege escalation** paths and other attack vectors—all without modifying any resources. It starts by **collecting the projects, folders, and organizations** that the compromised principal can enumerate, then expands its search to discover **additional assets such as Virtual Machines, Functions, Storage buckets, and Service Accounts**. This holistic approach minimizes blind spots and increases the chance of identifying permissions.

### How It Works

- **Resource Discovery:**  
  GCPPEAS begins by gathering the provided projects, folders, or organizations and then discovers more resources within those containers.

- **Permissions Enumeration:**  
  It employs **two main techniques** to assess the user's permissions:
  - **IAM Policy Retrieval:**  
    Attempts to fetch the IAM policies of resources (this requires `*.getIamPolicy` permissions and might not be available in all cases).
  - **Brute Force Testing:**  
    Utilizes the GCP **`testIamPermissions`** API to brute force permission checks across all resources. This method is inherently non-intrusive—it does **not** modify any resource or configuration.
  
  > **Note:**  
  > If you encounter errors indicating that the service `cloudresourcemanager.googleapis.com` is not enabled, you can:
  > - Try to enable it with:  
  >   ```bash
  >   gcloud services enable cloudresourcemanager.googleapis.com
  >   ```
  > - Alternatively, create a new project under your control, enable the service there, assign the **`roles/serviceusage.serviceUsageConsumer`** role to the compromised principal, and use the `--billing-project` flag in GCPPEAS indicating the name ID of this project (this will allow you to brute-force permissions in the victim project even if that victim project doesn't have the service enabled).
  > 
  > The same approach applies if the error is related to `cloudidentity.googleapis.com`.

- **Attack Surface Analysis:**  
  Once permissions are collected, GCPPEAS correlates the data to pinpoint potential privilege escalation paths. Although some permissions might be directly assigned to individual resources—possibly resulting in false negatives—the tool also enumerates additional assets (like VMs, Storage, Functions, and Service Accounts) and tests their permissions to minimize such oversights.

- **Authentication Requirements:**  
  To execute GCPPEAS, you must provide either a **GCP access token** or a **JSON file with Service Account credentials**.

### "Backdoor" `gcloud` for Google Drive Access 📂☁️

By default `gcloud` doesn't generate tokens with Drive access, but it can, so here you havea  couple of options:

- **Option 1:**  
  Authenticate using the following if you know the username and password:
  ```bash
  gcloud auth login --enable-gdrive-access
  ```
  
- **Option 2:**  
  If you have compromised the victims laptop, modify the **`GetScopes`** function in the Python library (typically located at `/opt/homebrew/Caskroom/google-cloud-sdk/458.0.1/google-cloud-sdk/lib/surface/auth/login.py`) so that the `https://www.googleapis.com/auth/drive` scope is always included:
  
```python
def GetScopes(args):
    scopes = config.CLOUDSDK_SCOPES
    # Include the REAUTH scope for users with 2FA enabled.
    scopes += (config.REAUTH_SCOPE,)
    
    # Always add Google Drive scope
    scopes += (auth_util.GOOGLE_DRIVE_SCOPE,)
    if args.enable_gdrive_access:
        scopes += (auth_util.GOOGLE_DRIVE_SCOPE,)
    return scopes
```

 The next time `gcloud auth login` is run, it will include the Drive scope. This method is particularly useful if you have access to the victim's machine and can modify the library.

### Generate Gmail & Drive Token 💌☁️

Follow these steps to create an access token that grants GCPPEAS access to Gmail and Google Drive:

0. **Project Setup:**  
   - Select or create a project in the [Google Cloud Console](https://console.cloud.google.com/).
   - Optionally, use an AppSheet function to automate project creation.

1. **Enable APIs:**  
   - Enable the **Gmail API**:
     
     ```bash
     gcloud services enable gmail.googleapis.com
     ```
     
   - Enable the **Drive API**:
     
     ```bash
     gcloud services enable drive.googleapis.com
     ```

2. **Configure OAuth Consent:**  
   - Go to the **OAuth consent screen** in the Cloud Console and set up an application named **GCPPEAS**. Use your email as the test user.

3. **Create OAuth Client:**  
   - Generate an OAuth client with:
     - **Name:** GCPPEAS
     - **Application Type:** Desktop Application  
   - Download the client secret JSON file.

4. **Add Required Scopes:**  
   - In the **Data access** settings, include the following scopes:
     - `https://www.googleapis.com/auth/gmail.readonly`
     - `https://www.googleapis.com/auth/drive`

5. **Generate the Access Token:**  
   - Use the following Python script to initiate the OAuth flow and obtain your token:
  
```python
# python3 -m pip install google-auth-oauthlib
from google_auth_oauthlib.flow import InstalledAppFlow

# Define the necessary scopes
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/drive"
]

# Path to your downloaded client secret JSON file
CLIENT_SECRET_FILE = "/path/to/client_secret.json"

# Initialize and run the OAuth flow
flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)
creds = flow.run_local_server(port=0)

# Output the access token
print("Access Token:", creds.token)
```

### GCPPEAS Help & Usage

- **Help:**  
  To display all available command options, run:
  
  ```bash
  python3 ./GCPPEAS.py --help
  usage: GCPPEAS.py [-h] [--projects PROJECTS | --folders FOLDERS | --organizations ORGANIZATIONS |
                  --service-accounts SERVICE_ACCOUNTS] (--sa-credentials-path SA_CREDENTIALS_PATH | --token TOKEN)
                  [--extra-token EXTRA_TOKEN] [--dont-get-iam-policies] [--out-json-path OUT_JSON_PATH] [--threads THREADS]
                  [--not-use-hacktricks-ai] [--billing-project BILLING_PROJECT] [--proxy PROXY] [--print-invalid-permissions]

GCPPEASS: Enumerate GCP permissions and check for privilege escalations and other attacks with HackTricks AI.

options:
  -h, --help            show this help message and exit
  --projects PROJECTS   Known project IDs (project names) separated by commas
  --folders FOLDERS     Known folder IDs (folder number) separated by commas
  --organizations ORGANIZATIONS
                        Known organization IDs separated by commas
  --service-accounts SERVICE_ACCOUNTS
                        Known service account emails separated by commas
  --sa-credentials-path SA_CREDENTIALS_PATH
                        Path to credentials.json
  --token TOKEN         Raw access token
  --extra-token EXTRA_TOKEN
                        Extra token potentially with access over Gmail and/or Drive
  --dont-get-iam-policies
                        Do not get IAM policies for the resources
  --out-json-path OUT_JSON_PATH
                        Output JSON file path (e.g. /tmp/gcp_results.json)
  --threads THREADS     Number of threads to use
  --not-use-hacktricks-ai
                        Don't use Hacktricks AI to analyze permissions
  --billing-project BILLING_PROJECT
                        Indicate the billing project to use to brute-force permissions
  --proxy PROXY         Indicate a proxy to use to connect to GCP for debugging (e.g. 127.0.0.1:8080)
  --print-invalid-permissions
                        Print found invalid permissions to improve th speed of the tool

```

- **Usage Example:**  
  Set your environment token and run GCPPEAS with your desired parameters:
  
  ```bash
  # Get token from gcloud
  export CLOUDSDK_AUTH_ACCES_TOKEN=$(gcloud auth print-access-token)

  # Run GCPPEAS (you can also pass an extra token for Gmail/Drive access)
  python3 GCPPEAS.py [--token <TOKEN>] [--extra-token <EXTRA_TOKEN>] [--projects <PROJECT_ID1>,<PROJECT_ID2>] [--folders <FOLDER_ID1>,<FOLDER_ID2>] [--organizations <ORGANIZATION_ID>] [--service-accounts <SA_EMAIL1>,<SA_EMAIL2>] [--billing-project <BILLING_PROJECT_ID>]
  ```

---

## AWSPEAS ⚡️🔐

**AWSPEAS** is your ultimate tool for enumerating **AWS permissions** and uncovering potential **privilege escalation** paths and other attack vectors—all while leaving your target environment unchanged. It leverages multiple techniques to gather, simulate, and even infer permissions, giving you deep insights into the security posture of your AWS setup.

### How It Works

- **IAM Policy Enumeration:**  
  Retrieves and reviews all IAM policies attached to the compromised principal. *(Requires appropriate IAM permissions.)*

- **Permission Simulation:**  
  If the previous technique didn't work, it simulates the effective permissions of the principal to determine what actions can be performed. *(Requires a single IAM permission.)*

- **Brute-Force Enumeration:**  
  If the previous technique didn't work, it systematically tests **List, Get, and Describe API calls via the AWS CLI**.  
  - **Service Filtering:** Use the **`--aws-services`** flag to target only specific services for a faster enumeration process.  
  - **Policy Inference:** Integrates a version of **[aws-Perms2ManagedPolicies](https://github.com/carlospolop/aws-Perms2ManagedPolicies)** to predict additional permissions based on the identified permissions and AWS managed policies.

### Operational Security Considerations ⚠️

- **Canary Account Detection:**  
  AWSPEAS tries to detect if the AWS account ID appears to belong to a **Canary service**. If a canary account is suspected, you'll be prompted for confirmation before the tool proceeds. Moreover, after the first interaction with the AWS API, the name of the principal is also gathered and AWSPEAS use it to try to detect if the principal is a canary account. Note that at this pioint it might be **too late** because an API interaction has already been done, but at least you will be warned about it.


### Authentication & Execution Requirements

Before running AWSPEAS, ensure that you have:
- Properly configured the **AWS profile** (used to connect to the target AWS account)
- The **AWS CLI** installed and configured on your PATH

### AWSPEAS Help & Usage

- **Help:**  
  To view all the command options, run:

```bash
python3 ./AWSPEAS.py --help
usage: AWSPEAS.py [-h] --profile PROFILE [--out-json-path OUT_JSON_PATH] [--threads THREADS] [--not-use-hacktricks-ai] [--debug]
                  --region REGION [--aws-services AWS_SERVICES]

Run AWSPEASS to find all your current permissions in AWS and check for potential privilege escalation risks. AWSPEASS requires the
name of the profile to use to connect to AWS.

options:
  -h, --help            show this help message and exit
  --profile PROFILE     AWS profile to use
  --out-json-path OUT_JSON_PATH
                        Output JSON file path (e.g. /tmp/aws_results.json)
  --threads THREADS     Number of threads to use
  --not-use-hacktricks-ai
                        Don't use Hacktricks AI to analyze permissions
  --debug               Print more infromation when brute-forcing permissions
  --region REGION       Indicate the region to use for brute-forcing permissions
  --aws-services AWS_SERVICES
                        Filter AWS services to brute-force permissions for indicating them as a comma separated list (e.g. --aws-
                        services s3,ec2,lambda,rds,sns,sqs,cloudwatch,cloudfront,iam,dynamodb)
```

- **Usage Examples:**  

```bash
# Basic usage with profile and region
python3 AWSPEAS.py --profile <AWS_PROFILE> --region <AWS_REGION>

# Usage with specific AWS services (e.g., S3, EC2, Lambda, etc.)
python3 AWSPEAS.py --profile <AWS_PROFILE> --region <AWS_REGION> --aws-services s3,ec2,lambda,rds,sns,sqs,cloudwatch,cloudfront,iam,dynamodb
```
