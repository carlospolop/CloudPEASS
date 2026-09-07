"""GCP attack-path permissions that supplement the generic risk classifier.

Single-item combinations are intentional: this module is also consumed by
older CloudPEASS integrations. Multi-item combinations model paths that need
all listed permissions before they become critical.
"""


very_sensitive_combinations = [
    # IAM policy changes and principal impersonation.
    ["*.setIamPolicy"],
    ["iam.serviceAccounts.actAs"],
    ["iam.serviceAccounts.getAccessToken"],
    [
        "iam.serviceAccounts.implicitDelegation",
        "iam.serviceAccounts.getAccessToken",
    ],
    ["iam.serviceAccounts.signBlob"],
    ["iam.serviceAccounts.signJwt"],
    ["iam.serviceAccountKeys.create"],
    ["iam.roles.update"],

    # Credential, secret, and decryption material.
    ["apikeys.keys.getKeyString"],
    ["clientauthconfig.clients.getWithSecret"],
    ["clientauthconfig.clients.listWithSecrets"],
    ["cloudkms.cryptoKeyVersions.useToDecrypt"],
    ["cloudkms.cryptoKeyVersions.useToDecryptViaDelegation"],
    ["secretmanager.versions.access"],
    ["storage.hmacKeys.create"],

    # Direct code execution or supply-chain replacement.
    ["appengine.instances.enableDebug"],
    ["cloudbuild.builds.create"],
    [
        "cloudfunctions.functions.create",
        "cloudfunctions.functions.sourceCodeSet",
        "iam.serviceAccounts.actAs",
    ],
    ["cloudfunctions.functions.update", "iam.serviceAccounts.actAs"],
    ["composer.environments.create", "iam.serviceAccounts.actAs"],
    ["composer.environments.update"],
    ["compute.projects.setCommonInstanceMetadata"],
    ["compute.instances.setMetadata"],
    ["compute.instances.osLogin"],
    ["compute.instances.osAdminLogin"],
    ["osconfig.patchDeployments.create"],
    ["osconfig.patchJobs.exec"],
    ["run.jobs.run", "run.jobs.runWithOverrides"],
    [
        "workflows.workflows.create",
        "iam.serviceAccounts.actAs",
        "workflows.executions.create",
    ],

    # GKE RBAC escalation, secret access, and workload execution.
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
    # Deployment services can execute as more privileged service accounts.
    [
        "dataproc.clusters.get",
        "dataproc.clusters.use",
        "dataproc.jobs.create",
        "dataproc.jobs.get",
        "dataproc.jobs.list",
        "storage.objects.create",
        "storage.objects.get",
    ],
    [
        "dataflow.jobs.create",
        "resourcemanager.projects.get",
        "iam.serviceAccounts.actAs",
    ],
    ["deploymentmanager.deployments.create"],
    ["deploymentmanager.deployments.update"],

    # Database account takeover.
    ["cloudsql.users.create"],
    ["cloudsql.users.update"],
]


sensitive_combinations = [
    # Credentials or identity-related changes that usually need more context.
    ["apikeys.keys.create"],
    ["artifactregistry.repositories.uploadArtifacts"],
    ["iam.serviceAccounts.getOpenIdToken"],
    ["cloudbuild.repositories.accessReadToken"],
    ["cloudbuild.repositories.accessReadWriteToken"],
    ["container.clusters.get"],
    ["container.clusters.getCredentials"],
    ["container.pods.portForward"],
    ["orgpolicy.policy.set"],

    # Direct data access, invocation, or message injection.
    ["artifactregistry.repositories.downloadArtifacts"],
    ["bigquery.tables.getData"],
    ["cloudfunctions.functions.sourceCodeGet"],
    ["cloudsql.instances.connect"],
    ["cloudsql.instances.export"],
    ["pubsub.subscriptions.consume"],
    ["pubsub.topics.publish"],
    ["run.routes.invoke"],
    ["source.repos.get"],
    ["source.repos.update"],
    ["storage.objects.create"],
    ["storage.objects.delete"],
    ["storage.objects.get"],
    ["workflows.executions.create"],

    # Security-control or evidence tampering.
    ["cloudbuild.builds.approve"],
    ["logging.logs.delete"],
    ["logging.sinks.delete"],
    ["logging.logMetrics.delete"],
    ["monitoring.alertPolicies.delete"],
    ["monitoring.notificationChannels.delete"],
    ["securitycenter.findings.setMute"],
    ["securitycenter.findings.bulkMuteUpdate"],
]


# Every Critical/High exact permission or combination above must match one of
# these evidence families. The referenced HackTricks Cloud page contains the
# concrete abuse or data-access procedure; tests prevent adding an unreferenced
# high-severity permission by accident.
risk_documentation = (
    ("*.setIamPolicy", "gcp-privilege-escalation/gcp-misc-perms-privesc.md"),
    ("cloudbuild.builds.approve", "gcp-post-exploitation/gcp-cloud-build-post-exploitation.md"),
    ("cloudfunctions.functions.sourceCodeGet", "gcp-post-exploitation/gcp-cloud-functions-post-exploitation.md"),
    ("cloudkms.cryptoKeyVersions.destroy", "gcp-post-exploitation/gcp-kms-post-exploitation.md"),
    ("dataflow.jobs.create", "gcp-post-exploitation/gcp-dataflow-post-exploitation.md"),
    ("logging.views.access", "gcp-post-exploitation/gcp-app-engine-post-exploitation.md"),
    ("pubsub.topics.publish", "gcp-post-exploitation/gcp-pub-sub-post-exploitation.md"),
    ("resourcemanager.projects.get", "gcp-post-exploitation/gcp-dataflow-post-exploitation.md"),
    ("storage.objects.update", "gcp-post-exploitation/gcp-storage-post-exploitation.md"),
    ("apikeys.*", "gcp-privilege-escalation/gcp-serviceusage-privesc.md"),
    ("appengine.*", "gcp-privilege-escalation/gcp-appengine-privesc.md"),
    ("artifactregistry.*", "gcp-privilege-escalation/gcp-artifact-registry-privesc.md"),
    ("bigquery.*", "gcp-privilege-escalation/gcp-bigquery-privesc.md"),
    ("bigtable.*", "gcp-post-exploitation/gcp-bigtable-post-exploitation.md"),
    ("clientauthconfig.*", "gcp-privilege-escalation/gcp-clientauthconfig-privesc.md"),
    ("cloudbuild.*", "gcp-privilege-escalation/gcp-cloudbuild-privesc.md"),
    ("cloudfunctions.*", "gcp-privilege-escalation/gcp-cloudfunctions-privesc.md"),
    ("cloudkms.*", "gcp-privilege-escalation/gcp-kms-privesc.md"),
    ("cloudsql.*", "gcp-post-exploitation/gcp-cloud-sql-post-exploitation.md"),
    ("composer.*", "gcp-privilege-escalation/gcp-composer-privesc.md"),
    ("compute.*", "gcp-privilege-escalation/gcp-compute-privesc/README.md"),
    ("container.*", "gcp-privilege-escalation/gcp-container-privesc.md"),
    ("dataflow.*", "gcp-privilege-escalation/gcp-dataflow-privesc.md"),
    ("dataproc.*", "gcp-privilege-escalation/gcp-dataproc-privesc.md"),
    ("deploymentmanager.*", "gcp-privilege-escalation/gcp-deploymentmaneger-privesc.md"),
    ("iam.*", "gcp-privilege-escalation/gcp-iam-privesc.md"),
    ("logging.*", "gcp-post-exploitation/gcp-logging-post-exploitation.md"),
    ("monitoring.*", "gcp-post-exploitation/gcp-monitoring-post-exploitation.md"),
    ("orgpolicy.*", "gcp-privilege-escalation/gcp-orgpolicy-privesc.md"),
    ("osconfig.*", "gcp-privilege-escalation/gcp-compute-privesc/README.md"),
    ("pubsub.*", "gcp-privilege-escalation/gcp-pubsub-privesc.md"),
    ("resourcemanager.*", "gcp-privilege-escalation/gcp-resourcemanager-privesc.md"),
    ("run.*", "gcp-privilege-escalation/gcp-run-privesc.md"),
    ("secretmanager.*", "gcp-privilege-escalation/gcp-secretmanager-privesc.md"),
    ("securitycenter.*", "gcp-post-exploitation/gcp-security-post-exploitation.md"),
    ("source.*", "gcp-privilege-escalation/gcp-sourcerepos-privesc.md"),
    ("storage.*", "gcp-privilege-escalation/gcp-storage-privesc.md"),
    ("workflows.*", "gcp-privilege-escalation/gcp-workflows-privesc.md"),
)
