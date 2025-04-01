

very_sensitive_combinations = [
    ["iam.serviceAccounts.actAs"],
    ["*.setIamPolicy"],

    ["iam.serviceAccounts.getAccessToken"],
    ["iam.serviceAccountKeys.create"],
    ["iam.serviceAccounts.implicitDelegation"],
    ["iam.serviceAccounts.signBlob"],
    ["iam.serviceAccounts.signJwt"],
    ["iam.serviceAccounts.getOpenIdToken"],

    ["appengine.instances.enableDebug"],
    
    ["artifactregistry.repositories.uploadArtifacts"],

    ["clientauthconfig.clients.getWithSecret", "clientauthconfig.clients.listWithSecrets"],

    ["cloudbuild.repositories.accessReadToken"],
    ["cloudbuild.repositories.accessReadWriteToken"],

    ["cloudfunctions.functions.sourceCodeSet"],

    ["compute.projects.setCommonInstanceMetadata"],
    ["compute.instances.setMetadata"],
    ["compute.instances.osLogin"],
    ["compute.instances.osAdminLogin"],
    ["osconfig.patchDeployments.create"],
    ["osconfig.patchJobs.exec"]    ,

    ["composer.environments.create"],
    ["composer.environments.update"],

    ["container.clusters.get"],
    ["container.roles.escalate"],
    ["container.clusterRoles.escalate"],
    ["container.roles.bind"],
    ["container.clusterRoles.bind"],

    ["container.cronJobs.create"],
    ["container.cronJobs.update"],
    ["container.daemonSets.create"], 
    ["container.daemonSets.update"],
    ["container.deployments.create"],
    ["container.deployments.update"],
    ["container.jobs.create"],
    ["container.jobs.update"], 
    ["container.pods.create"],
    ["container.pods.update"],
    ["container.replicaSets.create"],
    ["container.replicaSets.update"],
    ["container.replicationControllers.create"],
    ["container.replicationControllers.update"],
    ["container.scheduledJobs.create"],
    ["container.scheduledJobs.update"],
    ["container.statefulSets.create"],
    ["container.statefulSets.update"],
    ["container.secrets.get"],
    ["container.secrets.list"],
    ["container.pods.exec"],
    ["container.pods.portForward"],
    ["container.serviceAccounts.createToken"],
    ["container.mutatingWebhookConfigurations.create"],
    ["container.mutatingWebhookConfigurations.update"],

    ["dataproc.jobs.create", "storage.objects.get"],
    
    ["deploymentmanager.deployments.create"],
    ["deploymentmanager.deployments.update"],
    
    ["iam.roles.update"],
    ["iam.serviceAccounts.getAccessToken"],
    ["iam.serviceAccountKeys.create"],
    ["iam.serviceAccounts.implicitDelegation"],
    ["iam.serviceAccounts.signBlob"],
    ["iam.serviceAccounts.signJwt"],
    ["iam.serviceAccounts.getOpenIdToken"],

    ["orgpolicy.policy.set"],

    ["run.jobs.runWithOverrides"],

    ["secretmanager.versions.access"],

    ["source.repos.update"],

    ["storage.hmacKeys.create"],

    ["cloudsql.users.create"],
    ["cloudsql.users.update"]
]

sensitive_combinations = [
    ["apikeys.keys.create"],
    ["apikeys.keys.getKeyString"],
    ["apikeys.keys.list"],
    ["apikeys.keys.undelete"],
    ["serviceusage.apiKeys.create"],
    ["serviceusage.apiKeys.list"],
    ["*.create"],
    ["*.update"],
    ["bigquery.tables.getData"],
    ["cloudbuild.connections.fetchLinkableRepositories"],
    ["cloudkms.cryptoKeyVersions.useToDecrypt"],
    ["cloudkms.cryptoKeyVersions.useToDecryptViaDelegation"],
    ["storage.objects.get"],
    ["storage.objects.delete"],
    ["appengine.memcache.addKey"],
    ["appengine.memcache.getKey"],
    ["appengine.memcache.list"],
    ["cloudbuild.builds.approve"],
    ["cloudfunctions.functions.sourceCodeGet"],
    ["cloudsql.users.list"],
    ["cloudsql.instances.export"],
    ["cloudkms.cryptoKeyVersions.destroy"],
    ["logging.logs.delete"],
    ["logging.sinks.delete"],
    ["logging.logMetrics.delete"],
    ["monitoring.alertPolicies.delete"],
    ["monitoring.dashboards.delete"],
    ["monitoring.notificationChannels.delete"],
    ["pubsub.topics.publish"],
    ["securitycenter.findings.setMute"],
    ["securitycenter.findings.bulkMuteUpdate"]
]