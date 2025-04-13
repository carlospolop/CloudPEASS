# Cloud Privilege Escalation Awesome Script Suite

**Still in development phase!**

The current goal of **Cloud PEASS** is simple: Once you manage to get **some credentials to access Azure, GCP or AWS**, use different techniques to **get the permissions the principal has** and highlight all the **potential attacks** (privilege escalation, read sensitive information, etc) it's possible to do.

The sensitive permissions and attacks are discovered based on the sensitive permissions documented in **[HackTricks Cloud](https://cloud.hacktricks.wiki/en/index.html) and also asking the HackTricks AI**.

**Note that at the moment HackTricks AI will share information with OpenAI**, however, as we just share permission and resource names and not the actual data, it should be safe to use. If you don't want to use HackTricks AI, you can use the **`--not-use-hacktricks-ai`** flag.

## AzurePEASS

AzurePEASS will check all **your permissions in Azure and in Entra ID** and will try to find **privilege escalation** paths and other potential attacks.

AzurePEASS will use different API endpoints to find all the resources a principal has access to and then get all the permissions of those resources. It will also check for **Entra ID permissions** in different scopes.

Note that you will need to provide a token with access over the **ARM API** and another one with access over the **Graph API**.

Note also that some specific permissions and scopes are needed to get all the information, but **the most part of the permissions can be gathered without requiring any specific enumeration permission**.

**M356**: If you provide AzurePEASS with a **FOCI refresh token or some credentials** (username and password), it'll also be able to enumerate several Microsoft 365 services: **Sharepoint, OneDrive, Outlook, Teams, OneNote, Contacts, Tasks**. Note that the enumeration is not exhaustive and it's not the goal of the tool to be. The goal of the tool is just to let you know if there is any data in these services so you can check them manualy later.

- Help:

```bash
python3 ./AzurePEASS.py --help
usage: AzurePEASS.py [-h] [--tenant-id TENANT_ID] [--arm-token ARM_TOKEN] [--graph-token GRAPH_TOKEN] [--foci-refresh-token FOCI_REFRESH_TOKEN] [--username USERNAME]
                     [--password PASSWORD] [--out-json-path OUT_JSON_PATH] [--threads THREADS] [--not-use-hacktricks-ai]

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
  --username USERNAME   Username for authentication
  --password PASSWORD   Password for authentication
  --out-json-path OUT_JSON_PATH
                        Output JSON file path (e.g. /tmp/azure_results.json)
  --threads THREADS     Number of threads to use
  --not-use-hacktricks-ai
                        Don't use Hacktricks AI to analyze permissions
```

- Usage

```bash
# Get tokens
export AZURE_ARM_TOKEN=$(az account get-access-token --resource-type arm | jq -r .accessToken)
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

# e.g.
## You can indicate the tokens via command line or just exporting the previous env variables is enough
python3 AzurePEASS.py [--arm-token <AZURE_MANAGEMENT_TOKEN>] [--graph-token <AZURE_GRAPH_TOKEN>]

## FOCI refresh token for extra M365 enumeration
python3 AzurePEASS.py [--tenant-id <TENANT_ID>] [--foci-refresh-token <FOCI_REFRESH_TOKEN>]

## Credentials for extra M365 enumeration
python3 AzurePEASS.py [--username <USERNAME>] [--password <PASSWORD>]
```

## GCPPEASS

**This is still in development and testing, not ready yet**

GCPPEASS will check all **your permissions in GCP** and will try to find **privilege escalation** paths and other potential attacks.

GCPPEASS will **brute force all the permissions** over all the projects, folders and organizations the user can list and also over the given projects, folders or organizations via the CLI and then it's check for **potential attacks** (like privilege escalation). This could create false negatives, as the principal might have **permissions directly assigned to specific resources** that won't be able to see. Although, usually permissions are assigned at the project level, so this way we should be able to find most of the permissions. GCPPEASS also tries to **enumerate all the VMs, Storages, Functions and SAs** and brute force the permissions over them to reduce these false negatives.

Note that you will need to provide a **GCP access token**.

### "Backdoor" `gcloud` for Drive access

The application `gcloud` logins into an application that supports the scope to access Google Drive. Actually, using `gcloud auth login --enable-gdrive-access` It's possible to generate a regular access token that can be used to access the Google Drive API. 

In macOS (and in Linux and Windows I guess) it's possible to modify the code of the python library used by `gcloud` and change the code in `/opt/homebrew/Caskroom/google-cloud-sdk/458.0.1/google-cloud-sdk/lib/surface/auth/login.py` forcing the `gcloud` application to always request the `https://www.googleapis.com/auth/drive` scope when logging in. For this you can modifify the **`GetScopes`** function to always add the Google Drive scope:

```python
def GetScopes(args):
  scopes = config.CLOUDSDK_SCOPES
  # Add REAUTH scope in case the user has 2fact activated.
  # This scope is only used here and when refreshing the access token.
  scopes += (config.REAUTH_SCOPE,)

  scopes += (auth_util.GOOGLE_DRIVE_SCOPE,)
  if args.enable_gdrive_access:
    scopes += (auth_util.GOOGLE_DRIVE_SCOPE,)
  return scopes
```

### Generate Gmail & Drive token

0. Find a project you own or create a new one in the Google Cloud Console:
  - Find a project you have created
  - Create a project
  - Create an AppSheet function that will create a GCP project for you

1. Start enbling the Gmail & Drive API in a GCP project: `gcloud services enable gmail.googleapis.com` and `gcloud services enable drive.googleapis.com`

2. Go to `OAuth consent screen` in the web portal and configure an applciation called 'GCPPEASS' and set the users emaila ddress whenever an emaila ddress is needed.
  - Select the `External` user type and add the users email address as `Test Address`.

3. Create a client indicating the name `GCPPEASS` and the type `Desktop Applicaiton` and download the secret.

4. Go to `Data access` and add the following scopes:
  * https://www.googleapis.com/auth/gmail.readonly
  * https://www.googleapis.com/auth/drive

5. Run a code like the following one to login into the app and generate an access token:

```python
# python3 -m pip install google-auth-oauthlib
from google_auth_oauthlib.flow import InstalledAppFlow

# Define the scopes you need
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/drive"
]

# Path to your downloaded client secret JSON file
CLIENT_SECRET_FILE = "/path/to/client_secret.json"

# Initialize the OAuth flow
flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)

# Run the local server flow to get user consent
creds = flow.run_local_server(port=0)

# Print the access token
print("Access Token:", creds.token)
```

- Help

```bash
python3 ./GCPPEASS.py --help
usage: GCPPEASS.py [-h] [--project PROJECT | --folder FOLDER | --organization ORGANIZATION]
                   (--sa-credentials-path SA_CREDENTIALS_PATH | --token TOKEN) [--extra-token EXTRA_TOKEN]
                   [--out-json-path OUT_JSON_PATH] [--threads THREADS] [--not-use-hacktricks-ai]

GCPPEASS: Enumerate GCP permissions and check for privilege escalations and other attacks with HackTricks AI.

options:
  -h, --help            show this help message and exit
  --project PROJECT     Project ID
  --folder FOLDER       Folder ID
  --organization ORGANIZATION
                        Organization ID
  --sa-credentials-path SA_CREDENTIALS_PATH
                        Path to credentials.json
  --token TOKEN         Raw access token
  --extra-token EXTRA_TOKEN
                        Extra token potentially with access over Gmail and/or Drive
  --out-json-path OUT_JSON_PATH
                        Output JSON file path (e.g. /tmp/gcp_results.json)
  --threads THREADS     Number of threads to use
  --not-use-hacktricks-ai
                        Don't use Hacktricks AI to analyze permissions
```

- Usage

```bash
# Get token
export CLOUDSDK_AUTH_ACCESS_TOKEN=$(gcloud auth print-access-token)

# e.g.
## You can indicate the token via command line or just exporting the previous env variable is enough
## Use an extra token to give GCPPEASS access to gmail and drive
python3 GCPPEASS.py [--token <TOKEN>] [--extra-token <EXTRA_TOKEN>] [--project <PROJECT_ID>] [--folder <FOLDER_ID>] [--organization <ORGANIZATION_ID>]
```

## AWSPEASS

**This is still in development and testing, not ready yet**

AWSPEASS will find as many **permissions as possible in AWS** and will try to find **privilege escalation** paths and other potential attacks.

Methods to find permissions:

- Try to check all the **IAM policies attached to your principal** (IAM permissions are required to do this)
- Try to **simulate all the permissions of the principal** (one IAM permission is required to do this)
- Try to **brute-force as many List, Get & Describe permissions** as possible using the **`aws cli`**. This doesn't require any specific permission, but it will be slower and won't be able to find other type of permissions (like `Put` or `Create` permissions).
  - To reduce the bruteforce-timing you can indicate the **`--aws-services`** flag to brute-force only the services you are interested in.
  - If brute-force is used, AWSPEASS integrates a version of **[aws-Perms2ManagedPolicies](https://github.com/carlospolop/aws-Perms2ManagedPolicies)** to try to **guess more permissions** based on the permissions found.

**Opsec**: AWSPEASS will get the account ID of the principal. Then, based on known canary account IDs, it will try to guess if it belongs to a **Canary service** or not and will **ask the user if he wants to continue if it finds it suspicious**. Then, it'll also get the name of the principal (this will generate a log) and based on that name it'll try to **guess if it's a canary principal or not**. As at this point a log will be generated, it'll just continue with the enumeration but at least it'll let you know.

Note that you will need to configure and **indicate the profile and region** to use to AWSPEASS.

- Help

```bash
python3 AWSPEASS.py -h
usage: AWSPEASS.py [-h] --profile PROFILE [--out-json-path OUT_JSON_PATH] [--threads THREADS] [--not-use-hacktricks-ai] [--debug] --region REGION [--aws-services AWS_SERVICES]

Run AWSPEASS to find all your current permissions in AWS and check for potential privilege escalation risks. AWSPEASS requires the name of the profile to use to connect to AWS.

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
                        Filter AWS services to brute-force permissions for indicating them as a comma separated list (e.g. --aws-services
                        s3,ec2,lambda,rds,sns,sqs,cloudwatch,cloudfront,iam,dynamodb)
```

- Usage

```bash
# e.g.
python3 AWSPEASS.py --profile <AWS_PROFILE> --region <AWS_REGION>
python3 AWSPEASS.py --profile <AWS_PROFILE> --region <AWS_REGION> --aws-services s3,ec2,lambda,rds,sns,sqs,cloudwatch,cloudfront,iam,dynamodb
```