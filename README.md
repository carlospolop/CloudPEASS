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

- Help:

```bash
python3 AzurePEASS.py -h
usage: AzurePEASS.py [-h] [--arm-token ARM_TOKEN] [--graph-token GRAPH_TOKEN] [--out-json-path OUT_JSON_PATH] [--threads THREADS] [--not-use-hacktricks-ai]

Run AzurePEASS to find all your current privileges in Azure and EntraID and check for potential privilege escalation attacks. To check for Azure permissions an ARM token
is neded. To check for Entra ID permissions a Graph token is needed.

options:
  -h, --help            show this help message and exit
  --arm-token ARM_TOKEN
                        Azure Management authentication token
  --graph-token GRAPH_TOKEN
                        Azure Graph authentication token
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
```

## GCPPEASS

**This is still in development and testing, not ready yet**

GCPPEASS will check all **your permissions in GCP** and will try to find **privilege escalation** paths and other potential attacks.

GCPPEASS will **brute force all the permissions** over all the projects, folders and organizations the user can list and also over the given projects, folders or organizations via the CLI and then it's check for **potential attacks** (like privilege escalation). This could create false negatives, as the principal might have **permissions directly assigned to specific resources** that won't be able to see. Although, usually permissions are assigned at the project level, so this way we should be able to find most of the permissions. GCPPEASS also tries to **enumerate all the VMs, Storages, Functions and SAs** and brute force the permissions over them to reduce these false negatives.

Note that you will need to provide a **GCP access token**.

- Help

```bash
python3 GCPPEASS.py -h
usage: GCPPEASS.py [-h] [--project PROJECT | --folder FOLDER | --organization ORGANIZATION] (--sa-credentials-path SA_CREDENTIALS_PATH | --token TOKEN)
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
python3 GCPPEASS.py [--token <TOKEN>]
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