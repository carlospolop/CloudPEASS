# Cloud PEASS


THIS IS EAARLY ALPHA, DON'T USE IT YET!

## Azure PEASS

Usage:

```bash
python3 AzurePEASS.py --arm-token <AZURE_MANAGEMENT_TOKEN> [--threads N] [--filter-type TYPE] [--json]
# e.g.

python3 AzurePEASS.py --arm-token "$(az account get-access-token --resource-type arm | jq -r .accessToken)" --graph-token "$(az account get-access-token --resource-type ms-graph | jq -r .accessToken)"
```

Note:
- The token should be an Azure Resource Manager token (https://management.azure.com).
