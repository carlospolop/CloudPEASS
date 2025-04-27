

very_sensitive_combinations = [
    ["microsoft.directory/applications/credentials/update"],
    ["microsoft.directory/applications.myOrganization/credentials/update"],
    ["microsoft.directory/applications/owners/update"],
    ["microsoft.directory/applications/allProperties/update"],
    ["microsoft.directory/servicePrincipals/credentials/update"],
    ["microsoft.directory/servicePrincipals/synchronizationCredentials/manage"],
    ["microsoft.directory/servicePrincipals/owners/update"],
    ["microsoft.directory/servicePrincipals/getPasswordSingleSignOnCredentials", "microsoft.directory/servicePrincipals/managePasswordSingleSignOnCredentials"],
    ["microsoft.directory/groups/allProperties/update"],
    ["microsoft.directory/groups/owners/update"],
    ["microsoft.directory/groups/members/update"],
    ["microsoft.directory/groups/dynamicMembershipRule/update"],
    ["microsoft.directory/users/password/update"],
    ["microsoft.directory/users/basic/update"],
    ["microsoft.directory/devices/registeredOwners/update"],
    ["microsoft.directory/devices/registeredUsers/update"],
    ["microsoft.directory/deviceLocalCredentials/password/read"],


    ["Microsoft.Authorization/roleAssignments/write"],
    ["Microsoft.Authorization/roleDefinitions/Write"],
    ["Microsoft.Authorization/elevateAccess/action"],

    ["Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write"],
    ["Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"],
    
    
    ["Microsoft.Web/sites/publish/Action"],
    ["Microsoft.Web/sites/basicPublishingCredentialsPolicies/read"],

    ["Microsoft.Automation/automationAccounts/runbooks/publish/action"],
    ["Microsoft.Automation/automationAccounts/schedules/write"],
    ["Microsoft.Automation/automationAccounts/jobSchedules/write"],
    ["Microsoft.Automation/automationAccounts/runbooks/draft/write"],
    ["Microsoft.Automation/automationAccounts/sourceControls/write"],

    ["Microsoft.ContainerRegistry/registries/listCredentials/action"],
    ["Microsoft.ContainerRegistry/registries/tokens/write", "Microsoft.ContainerRegistry/registries/generateCredentials/action"],
    ["Microsoft.ContainerRegistry/registries/listBuildSourceUploadUrl/action", "Microsoft.ContainerRegistry/registries/scheduleRun/action"],
    ["Microsoft.ContainerRegistry/registries/tasks/write"],
    ["Microsoft.ContainerRegistry/registries/importImage/action"],

    ["Microsoft.ContainerInstance/containerGroups/containers/exec/action"],
    ["Microsoft.App/containerApps/getAuthToken/action"],

    ["Microsoft.App/jobs/write"],

    ["Microsoft.DocumentDB/databaseAccounts/sqlRoleDefinitions/write", "Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/write"],
    ["Microsoft.DocumentDB/databaseAccounts/mongodbRoleDefinitions/write", "Microsoft.DocumentDB/databaseAccounts/mongodbUserDefinitions/write"],

    ["Microsoft.DocumentDB/databaseAccounts/listKeys/action"],
    ["Microsoft.DocumentDB/mongoClusters/write"],

    ["Microsoft.Web/sites/host/listkeys/action"],
    ["Microsoft.Web/sites/host/functionKeys/write"],
    ["Microsoft.Web/sites/host/masterKey/write"],
    ["Microsoft.Web/sites/config/list/action"],
    ["Microsoft.Web/sites/config/list/action", "Microsoft.Web/sites/config/write"],
    ["Microsoft.Web/sites/hostruntime/vfs/write"],
    ["Microsoft.Web/sites/publishxml/action"],
    ["Microsoft.Web/sites/config/write", "Microsoft.Web/sites/config/list/action"],

    ["Microsoft.Logic/workflows/write"],
    ["Microsoft.Web/sites/basicPublishingCredentialsPolicies/read", "Microsoft.Web/sites/write", "Microsoft.Web/sites/config/list/action)"],

    ["Microsoft.DBforMySQL/flexibleServers/write"],
    ["Microsoft.DBforMySQL/flexibleServers/write", "Microsoft.DBforMySQL/flexibleServers/backups/read"],
    ["Microsoft.DBforMySQL/flexibleServers/administrators/write"],

    ["Microsoft.DBforPostgreSQL/flexibleServers/write"],
    ["Microsoft.DBforPostgreSQL/flexibleServers/write", "Microsoft.DBforPostgreSQL/flexibleServers/backups/read"],
    ["Microsoft.DBforPostgreSQL/flexibleServers/administrators/write"],

    ["Microsoft.ServiceBus/namespaces/authorizationrules/listKeys/action"],
    ["Microsoft.ServiceBus/namespaces/authorizationrules/regenerateKeys/action"],
    ["Microsoft.ServiceBus/namespaces/AuthorizationRules/write"],
    ["Microsoft.ServiceBus/namespaces/*/authorizationRules/ListKeys/action"],
    ["Microsoft.ServiceBus/namespaces/*/authorizationRules/regenerateKeys/action"],
    ["Microsoft.ServiceBus/namespaces/*/authorizationRules/write"],
    ["Microsoft.ServiceBus/namespaces/write"],

    ["Microsoft.Web/staticSites/snippets/write"],
    ["Microsoft.Web/staticSites/listSecrets/action"],
    ["Microsoft.Web/staticSites/write"],
    ["Microsoft.Web/staticSites/createUserInvitation/action"],

    ["Microsoft.Storage/storageAccounts/listkeys/action"],
    ["Microsoft.Storage/storageAccounts/regenerateKey/action"],
    ["Microsoft.Storage/storageAccounts/fileServices/takeOwnership/action"],
    ["Microsoft.Storage/storageAccounts/fileServices/fileshares/files/modifypermissions/action"],
    ["Microsoft.Storage/storageAccounts/fileServices/fileshares/files/actassuperuser/action"],
    ["Microsoft.Storage/storageAccounts/localusers/write"],
    ["Microsoft.Storage/storageAccounts/localusers/regeneratePassword/action"],

    ["Microsoft.Sql/servers/write"],
    ["Microsoft.Sql/servers/administrators/write"],
    ["Microsoft.Sql/servers/azureADOnlyAuthentications/write"],
    ["Microsoft.Sql/servers/databases/dataMaskingPolicies/write"],
    
    ["Microsoft.DesktopVirtualization/hostPools/retrieveRegistrationToken/action"],

    ["Microsoft.Compute/virtualMachines/extensions/write"],
    ["Microsoft.Compute/virtualMachines/write"],
    ["Microsoft.Compute/galleries/applications/versions/write"],
    ["Microsoft.Compute/virtualMachines/runCommand/action"],
    ["Microsoft.Compute/virtualMachines/login/action"],
    ["Microsoft.Compute/virtualMachines/loginAsAdmin/action"],

    ["Microsoft.KeyVault/vaults/secrets/getSecret/action"],

    ["Owner *"]
]

sensitive_combinations = [
    ["microsoft.directory/bitlockerKeys/key/read"],
    ["*/update"],

    ["*/write"],
    ["*/action"],
    ["Microsoft.Web/sites/hostruntime/vfs/read"],
    ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],
    ["Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read"],
    ["Microsoft.KeyVault/vaults/certificates/purge/action"],
    ["Microsoft.Storage/storageAccounts/queueServices/queues/messages/read"],
    ["Microsoft.Storage/storageAccounts/tableServices/tables/entities/read"]
]