# Cloud PEASS

**Still in development phase!**

The current goal of **Cloud PEASS** is simple: Once you manage to get **some credentials to access Azure, GCP or AWS**, use different techniques to **get the permissions the principal has** and highlight all the **potential attacks** (privilege escalation, read sensitive information, etc) it's possible to do.

The sensitive permissions and attacks are discovered based on the sensitive permissions documented in **[HackTricks Cloud](https://cloud.hacktricks.wiki/en/index.html) and also asking the HackTricks AI**.

## Azure PEASS

Azure PEASS will check all **your permissions in Azure and in Entra ID** and will try to find **privilege escalation** paths and other potential attacks.

Note that you will need to provide a token with access over the **ARM API** and another one with access over the **Graph API**.

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
python3 AzurePEASS.py [--arm-token <AZURE_MANAGEMENT_TOKEN>] [--graph-token <GRPAH_TOKEN>]
```

## GCP PEASS

**This is still in development and testing, not ready yet**

GCP PEASS will check all **your permissions in GCP** and will try to find **privilege escalation** paths and other potential attacks.

Note that you will need to provide a token with access over the **ARM API** and another one with access over the **Graph API**.

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