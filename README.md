# Find My Az Management Permissions

**The tool accepts an Az Management access token as parameter and finds all the resources that pricipal can access and all the granular permission that principal has over each resource it has access to.**

This script uses an Azure Management API access token to:
  1. List all subscriptions the user can access.
  2. For each subscription, enumerate all resources (with optional filtering) and check the user's permissions.
  3. Check permissions over the subscription itself if not present in the resources list.
  4. List all management groups and check the user's permissions on them.

Usage:
    `python FindMyAzPerms.py --token <AZURE_MANAGEMENT_TOKEN> [--threads N] [--filter-type TYPE] [--json]`

Example:
    `python FindMyAzPerms.py --token eyJhbGciOi... --threads 8 --filter-type Microsoft.Compute/virtualMachines`

Note:
- The token should be an Azure Resource Manager token (https://management.azure.com).
