import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import google.oauth2.credentials
import googleapiclient.discovery
from tqdm import tqdm
import re
import os
from bs4 import BeautifulSoup
from colorama import Fore, Style, init, Back

from src.CloudPEASS.cloudpeass import CloudPEASS
from src.sensitive_permissions.gcp import very_sensitive_combinations, sensitive_combinations



init(autoreset=True)

GCP_MALICIOUS_RESPONSE_EXAMPLE = """[
    {
        "Title": "Escalate Privileges via Compute Engine",
        "Description": "With compute.instances.setIamPolicy permission, an attacker can grant itself a role with the previous permissions and escalate privileges abusing them. Here is an example adding roles/compute.admin to a Service.",
        "Commands": "cat <<EOF > policy.json
bindings:
- members:
  - serviceAccount:$SERVER_SERVICE_ACCOUNT
  role: roles/compute.admin
version: 1
EOF

gcloud compute instances set-iam-policy $INSTANCE policy.json --zone=$ZONE"
    },
    [...]
]"""

GCP_SENSITIVE_RESPONSE_EXAMPLE = """[
    {
        "permission": "cloudfunctions.functions.sourceCodeSet",
        "is_very_sensitive": true,
        "is_sensitive": false,
        "description": "An attacker with this permission could modify the code of a Function to ecalate privileges to the SA used by the function."
    },
    [...]
]"""

NOT_COMPUTE_PERMS = [
    "compute.acceleratorTypes.get",
	"compute.acceleratorTypes.list",
	"compute.addresses.create",
	"compute.addresses.createInternal",
	"compute.addresses.createTagBinding",
	"compute.addresses.delete",
	"compute.addresses.deleteInternal",
	"compute.addresses.deleteTagBinding",
	"compute.addresses.get",
	"compute.addresses.list",
	"compute.addresses.listEffectiveTags",
	"compute.addresses.listTagBindings",
	"compute.addresses.setLabels",
	"compute.addresses.use",
	"compute.addresses.useInternal",
	"compute.advice.calendarMode",
	"compute.autoscalers.create",
	"compute.autoscalers.delete",
	"compute.autoscalers.get",
	"compute.autoscalers.list",
	"compute.autoscalers.update",
	"compute.backendBuckets.addSignedUrlKey",
	"compute.backendBuckets.create",
	"compute.backendBuckets.createTagBinding",
	"compute.backendBuckets.delete",
	"compute.backendBuckets.deleteSignedUrlKey",
	"compute.backendBuckets.deleteTagBinding",
	"compute.backendBuckets.get",
	"compute.backendBuckets.getIamPolicy",
	"compute.backendBuckets.list",
	"compute.backendBuckets.listEffectiveTags",
	"compute.backendBuckets.listTagBindings",
	"compute.backendBuckets.setIamPolicy",
	"compute.backendBuckets.setSecurityPolicy",
	"compute.backendBuckets.update",
	"compute.backendBuckets.use",
	"compute.backendServices.addSignedUrlKey",
	"compute.backendServices.create",
	"compute.backendServices.createTagBinding",
	"compute.backendServices.delete",
	"compute.backendServices.deleteSignedUrlKey",
	"compute.backendServices.deleteTagBinding",
	"compute.backendServices.get",
	"compute.backendServices.getIamPolicy",
	"compute.backendServices.list",
	"compute.backendServices.listEffectiveTags",
	"compute.backendServices.listTagBindings",
	"compute.backendServices.setIamPolicy",
	"compute.backendServices.setSecurityPolicy",
	"compute.backendServices.update",
	"compute.backendServices.use",
	"compute.commitments.create",
	"compute.commitments.get",
	"compute.commitments.list",
	"compute.commitments.update",
	"compute.commitments.updateReservations",
	"compute.crossSiteNetworks.create",
	"compute.crossSiteNetworks.delete",
	"compute.crossSiteNetworks.get",
	"compute.crossSiteNetworks.list",
	"compute.crossSiteNetworks.update",
	"compute.diskTypes.get",
	"compute.diskTypes.list",
	"compute.disks.addResourcePolicies",
	"compute.disks.create",
	"compute.disks.createSnapshot",
	"compute.disks.delete",
	"compute.disks.get",
	"compute.disks.getIamPolicy",
	"compute.disks.list",
	"compute.disks.listEffectiveTags",
	"compute.disks.removeResourcePolicies",
	"compute.disks.resize",
	"compute.disks.setIamPolicy",
	"compute.disks.setLabels",
	"compute.disks.startAsyncReplication",
	"compute.disks.stopAsyncReplication",
	"compute.disks.stopGroupAsyncReplication",
	"compute.disks.update",
	"compute.disks.use",
	"compute.disks.useReadOnly",
	"compute.externalVpnGateways.create",
	"compute.externalVpnGateways.createTagBinding",
	"compute.externalVpnGateways.delete",
	"compute.externalVpnGateways.deleteTagBinding",
	"compute.externalVpnGateways.get",
	"compute.externalVpnGateways.list",
	"compute.externalVpnGateways.listEffectiveTags",
	"compute.externalVpnGateways.listTagBindings",
	"compute.externalVpnGateways.setLabels",
	"compute.externalVpnGateways.use",
	"compute.firewallPolicies.cloneRules",
	"compute.firewallPolicies.copyRules",
	"compute.firewallPolicies.create",
	"compute.firewallPolicies.createTagBinding",
	"compute.firewallPolicies.delete",
	"compute.firewallPolicies.deleteTagBinding",
	"compute.firewallPolicies.get",
	"compute.firewallPolicies.getIamPolicy",
	"compute.firewallPolicies.list",
	"compute.firewallPolicies.listEffectiveTags",
	"compute.firewallPolicies.listTagBindings",
	"compute.firewallPolicies.move",
	"compute.firewallPolicies.setIamPolicy",
	"compute.firewallPolicies.update",
	"compute.firewallPolicies.use",
	"compute.firewalls.create",
	"compute.firewalls.createTagBinding",
	"compute.firewalls.delete",
	"compute.firewalls.deleteTagBinding",
	"compute.firewalls.get",
	"compute.firewalls.list",
	"compute.firewalls.listEffectiveTags",
	"compute.firewalls.listTagBindings",
	"compute.firewalls.update",
	"compute.forwardingRules.create",
	"compute.forwardingRules.createTagBinding",
	"compute.forwardingRules.delete",
	"compute.forwardingRules.deleteTagBinding",
	"compute.forwardingRules.get",
	"compute.forwardingRules.list",
	"compute.forwardingRules.listEffectiveTags",
	"compute.forwardingRules.listTagBindings",
	"compute.forwardingRules.pscCreate",
	"compute.forwardingRules.pscDelete",
	"compute.forwardingRules.pscSetLabels",
	"compute.forwardingRules.pscSetTarget",
	"compute.forwardingRules.pscUpdate",
	"compute.forwardingRules.setLabels",
	"compute.forwardingRules.setTarget",
	"compute.forwardingRules.update",
	"compute.forwardingRules.use",
	"compute.futureReservations.cancel",
	"compute.futureReservations.create",
	"compute.futureReservations.delete",
	"compute.futureReservations.get",
	"compute.futureReservations.getIamPolicy",
	"compute.futureReservations.list",
	"compute.futureReservations.setIamPolicy",
	"compute.futureReservations.update",
	"compute.globalAddresses.create",
	"compute.globalAddresses.createInternal",
	"compute.globalAddresses.createTagBinding",
	"compute.globalAddresses.delete",
	"compute.globalAddresses.deleteInternal",
	"compute.globalAddresses.deleteTagBinding",
	"compute.globalAddresses.get",
	"compute.globalAddresses.list",
	"compute.globalAddresses.listEffectiveTags",
	"compute.globalAddresses.listTagBindings",
	"compute.globalAddresses.setLabels",
	"compute.globalAddresses.use",
	"compute.globalForwardingRules.create",
	"compute.globalForwardingRules.createTagBinding",
	"compute.globalForwardingRules.delete",
	"compute.globalForwardingRules.deleteTagBinding",
	"compute.globalForwardingRules.get",
	"compute.globalForwardingRules.list",
	"compute.globalForwardingRules.listEffectiveTags",
	"compute.globalForwardingRules.listTagBindings",
	"compute.globalForwardingRules.pscCreate",
	"compute.globalForwardingRules.pscDelete",
	"compute.globalForwardingRules.pscGet",
	"compute.globalForwardingRules.pscSetLabels",
	"compute.globalForwardingRules.pscSetTarget",
	"compute.globalForwardingRules.pscUpdate",
	"compute.globalForwardingRules.setLabels",
	"compute.globalForwardingRules.setTarget",
	"compute.globalForwardingRules.update",
	"compute.globalNetworkEndpointGroups.attachNetworkEndpoints",
	"compute.globalNetworkEndpointGroups.create",
	"compute.globalNetworkEndpointGroups.createTagBinding",
	"compute.globalNetworkEndpointGroups.delete",
	"compute.globalNetworkEndpointGroups.deleteTagBinding",
	"compute.globalNetworkEndpointGroups.detachNetworkEndpoints",
	"compute.globalNetworkEndpointGroups.get",
	"compute.globalNetworkEndpointGroups.list",
	"compute.globalNetworkEndpointGroups.listEffectiveTags",
	"compute.globalNetworkEndpointGroups.listTagBindings",
	"compute.globalNetworkEndpointGroups.use",
	"compute.globalOperations.delete",
	"compute.globalOperations.get",
	"compute.globalOperations.getIamPolicy",
	"compute.globalOperations.list",
	"compute.globalOperations.setIamPolicy",
	"compute.globalPublicDelegatedPrefixes.create",
	"compute.globalPublicDelegatedPrefixes.delete",
	"compute.globalPublicDelegatedPrefixes.get",
	"compute.globalPublicDelegatedPrefixes.list",
	"compute.globalPublicDelegatedPrefixes.updatePolicy",
	"compute.healthChecks.create",
	"compute.healthChecks.createTagBinding",
	"compute.healthChecks.delete",
	"compute.healthChecks.deleteTagBinding",
	"compute.healthChecks.get",
	"compute.healthChecks.list",
	"compute.healthChecks.listEffectiveTags",
	"compute.healthChecks.listTagBindings",
	"compute.healthChecks.update",
	"compute.healthChecks.use",
	"compute.healthChecks.useReadOnly",
	"compute.httpHealthChecks.create",
	"compute.httpHealthChecks.createTagBinding",
	"compute.httpHealthChecks.delete",
	"compute.httpHealthChecks.deleteTagBinding",
	"compute.httpHealthChecks.get",
	"compute.httpHealthChecks.list",
	"compute.httpHealthChecks.listEffectiveTags",
	"compute.httpHealthChecks.listTagBindings",
	"compute.httpHealthChecks.update",
	"compute.httpHealthChecks.use",
	"compute.httpHealthChecks.useReadOnly",
	"compute.httpsHealthChecks.create",
	"compute.httpsHealthChecks.createTagBinding",
	"compute.httpsHealthChecks.delete",
	"compute.httpsHealthChecks.deleteTagBinding",
	"compute.httpsHealthChecks.get",
	"compute.httpsHealthChecks.list",
	"compute.httpsHealthChecks.listEffectiveTags",
	"compute.httpsHealthChecks.listTagBindings",
	"compute.httpsHealthChecks.update",
	"compute.httpsHealthChecks.use",
	"compute.httpsHealthChecks.useReadOnly",
	"compute.images.create",
	"compute.images.delete",
	"compute.images.deprecate",
	"compute.images.get",
	"compute.images.getFromFamily",
	"compute.images.getIamPolicy",
	"compute.images.list",
	"compute.images.listEffectiveTags",
	"compute.images.setIamPolicy",
	"compute.images.setLabels",
	"compute.images.update",
	"compute.images.useReadOnly",
	"compute.instanceGroupManagers.create",
	"compute.instanceGroupManagers.createTagBinding",
	"compute.instanceGroupManagers.delete",
	"compute.instanceGroupManagers.deleteTagBinding",
	"compute.instanceGroupManagers.get",
	"compute.instanceGroupManagers.list",
	"compute.instanceGroupManagers.listEffectiveTags",
	"compute.instanceGroupManagers.listTagBindings",
	"compute.instanceGroupManagers.update",
	"compute.instanceGroupManagers.use",
	"compute.instanceGroups.create",
	"compute.instanceGroups.createTagBinding",
	"compute.instanceGroups.delete",
	"compute.instanceGroups.deleteTagBinding",
	"compute.instanceGroups.get",
	"compute.instanceGroups.list",
	"compute.instanceGroups.listEffectiveTags",
	"compute.instanceGroups.listTagBindings",
	"compute.instanceGroups.update",
	"compute.instanceGroups.use",
	"compute.instanceSettings.get",
	"compute.instanceSettings.update",
	"compute.instanceTemplates.create",
	"compute.instanceTemplates.delete",
	"compute.instanceTemplates.get",
	"compute.instanceTemplates.getIamPolicy",
	"compute.instanceTemplates.list",
	"compute.instanceTemplates.setIamPolicy",
	"compute.instanceTemplates.useReadOnly",
	"compute.instances.create",
	"compute.instances.list",
	"compute.instances.pscInterfaceCreate",
	"compute.instantSnapshots.create",
	"compute.instantSnapshots.delete",
	"compute.instantSnapshots.export",
	"compute.instantSnapshots.get",
	"compute.instantSnapshots.getIamPolicy",
	"compute.instantSnapshots.list",
	"compute.instantSnapshots.setIamPolicy",
	"compute.instantSnapshots.setLabels",
	"compute.instantSnapshots.useReadOnly",
	"compute.interconnectAttachments.create",
	"compute.interconnectAttachments.createTagBinding",
	"compute.interconnectAttachments.delete",
	"compute.interconnectAttachments.deleteTagBinding",
	"compute.interconnectAttachments.get",
	"compute.interconnectAttachments.list",
	"compute.interconnectAttachments.listEffectiveTags",
	"compute.interconnectAttachments.listTagBindings",
	"compute.interconnectAttachments.setLabels",
	"compute.interconnectAttachments.update",
	"compute.interconnectAttachments.use",
	"compute.interconnectLocations.get",
	"compute.interconnectLocations.list",
	"compute.interconnectRemoteLocations.get",
	"compute.interconnectRemoteLocations.list",
	"compute.interconnects.create",
	"compute.interconnects.createTagBinding",
	"compute.interconnects.delete",
	"compute.interconnects.deleteTagBinding",
	"compute.interconnects.get",
	"compute.interconnects.getMacsecConfig",
	"compute.interconnects.list",
	"compute.interconnects.listEffectiveTags",
	"compute.interconnects.listTagBindings",
	"compute.interconnects.setLabels",
	"compute.interconnects.update",
	"compute.interconnects.use",
	"compute.licenseCodes.get",
	"compute.licenseCodes.getIamPolicy",
	"compute.licenseCodes.list",
	"compute.licenseCodes.setIamPolicy",
	"compute.licenseCodes.update",
	"compute.licenses.create",
	"compute.licenses.delete",
	"compute.licenses.get",
	"compute.licenses.getIamPolicy",
	"compute.licenses.list",
	"compute.licenses.setIamPolicy",
	"compute.machineImages.create",
	"compute.machineImages.delete",
	"compute.machineImages.get",
	"compute.machineImages.getIamPolicy",
	"compute.machineImages.list",
	"compute.machineImages.setIamPolicy",
	"compute.machineImages.useReadOnly",
	"compute.machineTypes.get",
	"compute.machineTypes.list",
	"compute.multiMig.create",
	"compute.multiMig.delete",
	"compute.multiMig.get",
	"compute.multiMig.list",
	"compute.networkAttachments.create",
	"compute.networkAttachments.createTagBinding",
	"compute.networkAttachments.delete",
	"compute.networkAttachments.deleteTagBinding",
	"compute.networkAttachments.get",
	"compute.networkAttachments.getIamPolicy",
	"compute.networkAttachments.list",
	"compute.networkAttachments.listEffectiveTags",
	"compute.networkAttachments.listTagBindings",
	"compute.networkAttachments.setIamPolicy",
	"compute.networkAttachments.update",
	"compute.networkEdgeSecurityServices.create",
	"compute.networkEdgeSecurityServices.createTagBinding",
	"compute.networkEdgeSecurityServices.delete",
	"compute.networkEdgeSecurityServices.deleteTagBinding",
	"compute.networkEdgeSecurityServices.get",
	"compute.networkEdgeSecurityServices.list",
	"compute.networkEdgeSecurityServices.listEffectiveTags",
	"compute.networkEdgeSecurityServices.listTagBindings",
	"compute.networkEdgeSecurityServices.update",
	"compute.networkEndpointGroups.attachNetworkEndpoints",
	"compute.networkEndpointGroups.create",
	"compute.networkEndpointGroups.createTagBinding",
	"compute.networkEndpointGroups.delete",
	"compute.networkEndpointGroups.deleteTagBinding",
	"compute.networkEndpointGroups.detachNetworkEndpoints",
	"compute.networkEndpointGroups.get",
	"compute.networkEndpointGroups.list",
	"compute.networkEndpointGroups.listEffectiveTags",
	"compute.networkEndpointGroups.listTagBindings",
	"compute.networkEndpointGroups.use",
	"compute.networkProfiles.get",
	"compute.networkProfiles.list",
	"compute.networks.access",
	"compute.networks.addPeering",
	"compute.networks.create",
	"compute.networks.createTagBinding",
	"compute.networks.delete",
	"compute.networks.deleteTagBinding",
	"compute.networks.get",
	"compute.networks.getEffectiveFirewalls",
	"compute.networks.getRegionEffectiveFirewalls",
	"compute.networks.list",
	"compute.networks.listEffectiveTags",
	"compute.networks.listPeeringRoutes",
	"compute.networks.listTagBindings",
	"compute.networks.mirror",
	"compute.networks.removePeering",
	"compute.networks.setFirewallPolicy",
	"compute.networks.switchToCustomMode",
	"compute.networks.update",
	"compute.networks.updatePeering",
	"compute.networks.updatePolicy",
	"compute.networks.use",
	"compute.networks.useExternalIp",
	"compute.nodeGroups.addNodes",
	"compute.nodeGroups.create",
	"compute.nodeGroups.delete",
	"compute.nodeGroups.deleteNodes",
	"compute.nodeGroups.get",
	"compute.nodeGroups.getIamPolicy",
	"compute.nodeGroups.list",
	"compute.nodeGroups.performMaintenance",
	"compute.nodeGroups.setIamPolicy",
	"compute.nodeGroups.setNodeTemplate",
	"compute.nodeGroups.simulateMaintenanceEvent",
	"compute.nodeGroups.update",
	"compute.nodeTemplates.create",
	"compute.nodeTemplates.delete",
	"compute.nodeTemplates.get",
	"compute.nodeTemplates.getIamPolicy",
	"compute.nodeTemplates.list",
	"compute.nodeTemplates.setIamPolicy",
	"compute.nodeTypes.get",
	"compute.nodeTypes.list",
	"compute.organizations.disableXpnHost",
	"compute.organizations.disableXpnResource",
	"compute.organizations.enableXpnHost",
	"compute.organizations.enableXpnResource",
	"compute.organizations.listAssociations",
	"compute.organizations.setFirewallPolicy",
	"compute.organizations.setSecurityPolicy",
	"compute.oslogin.updateExternalUser",
	"compute.packetMirrorings.create",
	"compute.packetMirrorings.createTagBinding",
	"compute.packetMirrorings.delete",
	"compute.packetMirrorings.deleteTagBinding",
	"compute.packetMirrorings.get",
	"compute.packetMirrorings.list",
	"compute.packetMirrorings.listEffectiveTags",
	"compute.packetMirrorings.listTagBindings",
	"compute.packetMirrorings.update",
	"compute.projects.get",
	"compute.projects.setCloudArmorTier",
	"compute.projects.setCommonInstanceMetadata",
	"compute.projects.setDefaultNetworkTier",
	"compute.projects.setDefaultServiceAccount",
	"compute.projects.setManagedProtectionTier",
	"compute.projects.setUsageExportBucket",
	"compute.publicAdvertisedPrefixes.create",
	"compute.publicAdvertisedPrefixes.delete",
	"compute.publicAdvertisedPrefixes.get",
	"compute.publicAdvertisedPrefixes.list",
	"compute.publicAdvertisedPrefixes.update",
	"compute.publicAdvertisedPrefixes.updatePolicy",
	"compute.publicDelegatedPrefixes.create",
	"compute.publicDelegatedPrefixes.createTagBinding",
	"compute.publicDelegatedPrefixes.delete",
	"compute.publicDelegatedPrefixes.deleteTagBinding",
	"compute.publicDelegatedPrefixes.get",
	"compute.publicDelegatedPrefixes.list",
	"compute.publicDelegatedPrefixes.listEffectiveTags",
	"compute.publicDelegatedPrefixes.listTagBindings",
	"compute.publicDelegatedPrefixes.update",
	"compute.publicDelegatedPrefixes.updatePolicy",
	"compute.publicDelegatedPrefixes.use",
	"compute.regionBackendServices.create",
	"compute.regionBackendServices.createTagBinding",
	"compute.regionBackendServices.delete",
	"compute.regionBackendServices.deleteTagBinding",
	"compute.regionBackendServices.get",
	"compute.regionBackendServices.getIamPolicy",
	"compute.regionBackendServices.list",
	"compute.regionBackendServices.listEffectiveTags",
	"compute.regionBackendServices.listTagBindings",
	"compute.regionBackendServices.setIamPolicy",
	"compute.regionBackendServices.setSecurityPolicy",
	"compute.regionBackendServices.update",
	"compute.regionBackendServices.use",
	"compute.regionFirewallPolicies.cloneRules",
	"compute.regionFirewallPolicies.create",
	"compute.regionFirewallPolicies.createTagBinding",
	"compute.regionFirewallPolicies.delete",
	"compute.regionFirewallPolicies.deleteTagBinding",
	"compute.regionFirewallPolicies.get",
	"compute.regionFirewallPolicies.getIamPolicy",
	"compute.regionFirewallPolicies.list",
	"compute.regionFirewallPolicies.listEffectiveTags",
	"compute.regionFirewallPolicies.listTagBindings",
	"compute.regionFirewallPolicies.setIamPolicy",
	"compute.regionFirewallPolicies.update",
	"compute.regionFirewallPolicies.use",
	"compute.regionHealthCheckServices.create",
	"compute.regionHealthCheckServices.delete",
	"compute.regionHealthCheckServices.get",
	"compute.regionHealthCheckServices.list",
	"compute.regionHealthCheckServices.update",
	"compute.regionHealthCheckServices.use",
	"compute.regionHealthChecks.create",
	"compute.regionHealthChecks.createTagBinding",
	"compute.regionHealthChecks.delete",
	"compute.regionHealthChecks.deleteTagBinding",
	"compute.regionHealthChecks.get",
	"compute.regionHealthChecks.list",
	"compute.regionHealthChecks.listEffectiveTags",
	"compute.regionHealthChecks.listTagBindings",
	"compute.regionHealthChecks.update",
	"compute.regionHealthChecks.use",
	"compute.regionHealthChecks.useReadOnly",
	"compute.regionNetworkEndpointGroups.attachNetworkEndpoints",
	"compute.regionNetworkEndpointGroups.create",
	"compute.regionNetworkEndpointGroups.createTagBinding",
	"compute.regionNetworkEndpointGroups.delete",
	"compute.regionNetworkEndpointGroups.deleteTagBinding",
	"compute.regionNetworkEndpointGroups.detachNetworkEndpoints",
	"compute.regionNetworkEndpointGroups.get",
	"compute.regionNetworkEndpointGroups.list",
	"compute.regionNetworkEndpointGroups.listEffectiveTags",
	"compute.regionNetworkEndpointGroups.listTagBindings",
	"compute.regionNetworkEndpointGroups.use",
	"compute.regionNotificationEndpoints.create",
	"compute.regionNotificationEndpoints.delete",
	"compute.regionNotificationEndpoints.get",
	"compute.regionNotificationEndpoints.list",
	"compute.regionNotificationEndpoints.update",
	"compute.regionNotificationEndpoints.use",
	"compute.regionOperations.delete",
	"compute.regionOperations.get",
	"compute.regionOperations.getIamPolicy",
	"compute.regionOperations.list",
	"compute.regionOperations.setIamPolicy",
	"compute.regionSecurityPolicies.create",
	"compute.regionSecurityPolicies.createTagBinding",
	"compute.regionSecurityPolicies.delete",
	"compute.regionSecurityPolicies.deleteTagBinding",
	"compute.regionSecurityPolicies.get",
	"compute.regionSecurityPolicies.list",
	"compute.regionSecurityPolicies.listEffectiveTags",
	"compute.regionSecurityPolicies.listTagBindings",
	"compute.regionSecurityPolicies.update",
	"compute.regionSecurityPolicies.use",
	"compute.regionSslCertificates.create",
	"compute.regionSslCertificates.createTagBinding",
	"compute.regionSslCertificates.delete",
	"compute.regionSslCertificates.deleteTagBinding",
	"compute.regionSslCertificates.get",
	"compute.regionSslCertificates.list",
	"compute.regionSslCertificates.listEffectiveTags",
	"compute.regionSslCertificates.listTagBindings",
	"compute.regionSslPolicies.create",
	"compute.regionSslPolicies.createTagBinding",
	"compute.regionSslPolicies.delete",
	"compute.regionSslPolicies.deleteTagBinding",
	"compute.regionSslPolicies.get",
	"compute.regionSslPolicies.list",
	"compute.regionSslPolicies.listAvailableFeatures",
	"compute.regionSslPolicies.listEffectiveTags",
	"compute.regionSslPolicies.listTagBindings",
	"compute.regionSslPolicies.update",
	"compute.regionSslPolicies.use",
	"compute.regionTargetHttpProxies.create",
	"compute.regionTargetHttpProxies.createTagBinding",
	"compute.regionTargetHttpProxies.delete",
	"compute.regionTargetHttpProxies.deleteTagBinding",
	"compute.regionTargetHttpProxies.get",
	"compute.regionTargetHttpProxies.list",
	"compute.regionTargetHttpProxies.listEffectiveTags",
	"compute.regionTargetHttpProxies.listTagBindings",
	"compute.regionTargetHttpProxies.setUrlMap",
	"compute.regionTargetHttpProxies.use",
	"compute.regionTargetHttpsProxies.create",
	"compute.regionTargetHttpsProxies.createTagBinding",
	"compute.regionTargetHttpsProxies.delete",
	"compute.regionTargetHttpsProxies.deleteTagBinding",
	"compute.regionTargetHttpsProxies.get",
	"compute.regionTargetHttpsProxies.list",
	"compute.regionTargetHttpsProxies.listEffectiveTags",
	"compute.regionTargetHttpsProxies.listTagBindings",
	"compute.regionTargetHttpsProxies.setSslCertificates",
	"compute.regionTargetHttpsProxies.setUrlMap",
	"compute.regionTargetHttpsProxies.update",
	"compute.regionTargetHttpsProxies.use",
	"compute.regionTargetTcpProxies.create",
	"compute.regionTargetTcpProxies.createTagBinding",
	"compute.regionTargetTcpProxies.delete",
	"compute.regionTargetTcpProxies.deleteTagBinding",
	"compute.regionTargetTcpProxies.get",
	"compute.regionTargetTcpProxies.list",
	"compute.regionTargetTcpProxies.listEffectiveTags",
	"compute.regionTargetTcpProxies.listTagBindings",
	"compute.regionTargetTcpProxies.use",
	"compute.regionUrlMaps.create",
	"compute.regionUrlMaps.createTagBinding",
	"compute.regionUrlMaps.delete",
	"compute.regionUrlMaps.deleteTagBinding",
	"compute.regionUrlMaps.get",
	"compute.regionUrlMaps.invalidateCache",
	"compute.regionUrlMaps.list",
	"compute.regionUrlMaps.listEffectiveTags",
	"compute.regionUrlMaps.listTagBindings",
	"compute.regionUrlMaps.update",
	"compute.regionUrlMaps.use",
	"compute.regionUrlMaps.validate",
	"compute.regions.get",
	"compute.regions.list",
	"compute.reservationBlocks.get",
	"compute.reservationBlocks.list",
	"compute.reservationBlocks.performMaintenance",
	"compute.reservations.create",
	"compute.reservations.delete",
	"compute.reservations.get",
	"compute.reservations.list",
	"compute.reservations.performMaintenance",
	"compute.reservations.resize",
	"compute.reservations.update",
	"compute.resourcePolicies.create",
	"compute.resourcePolicies.delete",
	"compute.resourcePolicies.get",
	"compute.resourcePolicies.getIamPolicy",
	"compute.resourcePolicies.list",
	"compute.resourcePolicies.setIamPolicy",
	"compute.resourcePolicies.update",
	"compute.resourcePolicies.use",
	"compute.resourcePolicies.useReadOnly",
	"compute.routers.create",
	"compute.routers.createTagBinding",
	"compute.routers.delete",
	"compute.routers.deleteRoutePolicy",
	"compute.routers.deleteTagBinding",
	"compute.routers.get",
	"compute.routers.getRoutePolicy",
	"compute.routers.list",
	"compute.routers.listBgpRoutes",
	"compute.routers.listEffectiveTags",
	"compute.routers.listRoutePolicies",
	"compute.routers.listTagBindings",
	"compute.routers.update",
	"compute.routers.updateRoutePolicy",
	"compute.routers.use",
	"compute.routes.create",
	"compute.routes.createTagBinding",
	"compute.routes.delete",
	"compute.routes.deleteTagBinding",
	"compute.routes.get",
	"compute.routes.list",
	"compute.routes.listEffectiveTags",
	"compute.routes.listTagBindings",
	"compute.securityPolicies.addAssociation",
	"compute.securityPolicies.copyRules",
	"compute.securityPolicies.create",
	"compute.securityPolicies.createTagBinding",
	"compute.securityPolicies.delete",
	"compute.securityPolicies.deleteTagBinding",
	"compute.securityPolicies.get",
	"compute.securityPolicies.list",
	"compute.securityPolicies.listEffectiveTags",
	"compute.securityPolicies.listTagBindings",
	"compute.securityPolicies.move",
	"compute.securityPolicies.removeAssociation",
	"compute.securityPolicies.setLabels",
	"compute.securityPolicies.update",
	"compute.securityPolicies.use",
	"compute.serviceAttachments.create",
	"compute.serviceAttachments.createTagBinding",
	"compute.serviceAttachments.delete",
	"compute.serviceAttachments.deleteTagBinding",
	"compute.serviceAttachments.get",
	"compute.serviceAttachments.getIamPolicy",
	"compute.serviceAttachments.list",
	"compute.serviceAttachments.listEffectiveTags",
	"compute.serviceAttachments.listTagBindings",
	"compute.serviceAttachments.setIamPolicy",
	"compute.serviceAttachments.update",
	"compute.serviceAttachments.use",
	"compute.snapshotSettings.get",
	"compute.snapshotSettings.update",
	"compute.snapshots.create",
	"compute.snapshots.delete",
	"compute.snapshots.get",
	"compute.snapshots.getIamPolicy",
	"compute.snapshots.list",
	"compute.snapshots.listEffectiveTags",
	"compute.snapshots.setIamPolicy",
	"compute.snapshots.setLabels",
	"compute.snapshots.useReadOnly",
	"compute.spotAssistants.get",
	"compute.sslCertificates.create",
	"compute.sslCertificates.createTagBinding",
	"compute.sslCertificates.delete",
	"compute.sslCertificates.deleteTagBinding",
	"compute.sslCertificates.get",
	"compute.sslCertificates.list",
	"compute.sslCertificates.listEffectiveTags",
	"compute.sslCertificates.listTagBindings",
	"compute.sslPolicies.create",
	"compute.sslPolicies.createTagBinding",
	"compute.sslPolicies.delete",
	"compute.sslPolicies.deleteTagBinding",
	"compute.sslPolicies.get",
	"compute.sslPolicies.list",
	"compute.sslPolicies.listAvailableFeatures",
	"compute.sslPolicies.listEffectiveTags",
	"compute.sslPolicies.listTagBindings",
	"compute.sslPolicies.update",
	"compute.sslPolicies.use",
	"compute.storagePools.create",
	"compute.storagePools.delete",
	"compute.storagePools.get",
	"compute.storagePools.getIamPolicy",
	"compute.storagePools.list",
	"compute.storagePools.setIamPolicy",
	"compute.storagePools.update",
	"compute.storagePools.use",
	"compute.subnetworks.create",
	"compute.subnetworks.createTagBinding",
	"compute.subnetworks.delete",
	"compute.subnetworks.deleteTagBinding",
	"compute.subnetworks.expandIpCidrRange",
	"compute.subnetworks.get",
	"compute.subnetworks.getIamPolicy",
	"compute.subnetworks.list",
	"compute.subnetworks.listEffectiveTags",
	"compute.subnetworks.listTagBindings",
	"compute.subnetworks.mirror",
	"compute.subnetworks.setIamPolicy",
	"compute.subnetworks.setPrivateIpGoogleAccess",
	"compute.subnetworks.update",
	"compute.subnetworks.use",
	"compute.subnetworks.useExternalIp",
	"compute.subnetworks.usePeerMigration",
	"compute.targetGrpcProxies.create",
	"compute.targetGrpcProxies.createTagBinding",
	"compute.targetGrpcProxies.delete",
	"compute.targetGrpcProxies.deleteTagBinding",
	"compute.targetGrpcProxies.get",
	"compute.targetGrpcProxies.list",
	"compute.targetGrpcProxies.listEffectiveTags",
	"compute.targetGrpcProxies.listTagBindings",
	"compute.targetGrpcProxies.update",
	"compute.targetGrpcProxies.use",
	"compute.targetHttpProxies.create",
	"compute.targetHttpProxies.createTagBinding",
	"compute.targetHttpProxies.delete",
	"compute.targetHttpProxies.deleteTagBinding",
	"compute.targetHttpProxies.get",
	"compute.targetHttpProxies.list",
	"compute.targetHttpProxies.listEffectiveTags",
	"compute.targetHttpProxies.listTagBindings",
	"compute.targetHttpProxies.setUrlMap",
	"compute.targetHttpProxies.update",
	"compute.targetHttpProxies.use",
	"compute.targetHttpsProxies.create",
	"compute.targetHttpsProxies.createTagBinding",
	"compute.targetHttpsProxies.delete",
	"compute.targetHttpsProxies.deleteTagBinding",
	"compute.targetHttpsProxies.get",
	"compute.targetHttpsProxies.list",
	"compute.targetHttpsProxies.listEffectiveTags",
	"compute.targetHttpsProxies.listTagBindings",
	"compute.targetHttpsProxies.setCertificateMap",
	"compute.targetHttpsProxies.setQuicOverride",
	"compute.targetHttpsProxies.setSslCertificates",
	"compute.targetHttpsProxies.setSslPolicy",
	"compute.targetHttpsProxies.setUrlMap",
	"compute.targetHttpsProxies.update",
	"compute.targetHttpsProxies.use",
	"compute.targetInstances.create",
	"compute.targetInstances.createTagBinding",
	"compute.targetInstances.delete",
	"compute.targetInstances.deleteTagBinding",
	"compute.targetInstances.get",
	"compute.targetInstances.list",
	"compute.targetInstances.listEffectiveTags",
	"compute.targetInstances.listTagBindings",
	"compute.targetInstances.setSecurityPolicy",
	"compute.targetInstances.use",
	"compute.targetPools.addHealthCheck",
	"compute.targetPools.addInstance",
	"compute.targetPools.create",
	"compute.targetPools.createTagBinding",
	"compute.targetPools.delete",
	"compute.targetPools.deleteTagBinding",
	"compute.targetPools.get",
	"compute.targetPools.list",
	"compute.targetPools.listEffectiveTags",
	"compute.targetPools.listTagBindings",
	"compute.targetPools.removeHealthCheck",
	"compute.targetPools.removeInstance",
	"compute.targetPools.setSecurityPolicy",
	"compute.targetPools.update",
	"compute.targetPools.use",
	"compute.targetSslProxies.create",
	"compute.targetSslProxies.createTagBinding",
	"compute.targetSslProxies.delete",
	"compute.targetSslProxies.deleteTagBinding",
	"compute.targetSslProxies.get",
	"compute.targetSslProxies.list",
	"compute.targetSslProxies.listEffectiveTags",
	"compute.targetSslProxies.listTagBindings",
	"compute.targetSslProxies.setBackendService",
	"compute.targetSslProxies.setCertificateMap",
	"compute.targetSslProxies.setProxyHeader",
	"compute.targetSslProxies.setSslCertificates",
	"compute.targetSslProxies.setSslPolicy",
	"compute.targetSslProxies.update",
	"compute.targetSslProxies.use",
	"compute.targetTcpProxies.create",
	"compute.targetTcpProxies.createTagBinding",
	"compute.targetTcpProxies.delete",
	"compute.targetTcpProxies.deleteTagBinding",
	"compute.targetTcpProxies.get",
	"compute.targetTcpProxies.list",
	"compute.targetTcpProxies.listEffectiveTags",
	"compute.targetTcpProxies.listTagBindings",
	"compute.targetTcpProxies.update",
	"compute.targetTcpProxies.use",
	"compute.targetVpnGateways.create",
	"compute.targetVpnGateways.createTagBinding",
	"compute.targetVpnGateways.delete",
	"compute.targetVpnGateways.deleteTagBinding",
	"compute.targetVpnGateways.get",
	"compute.targetVpnGateways.list",
	"compute.targetVpnGateways.listEffectiveTags",
	"compute.targetVpnGateways.listTagBindings",
	"compute.targetVpnGateways.setLabels",
	"compute.targetVpnGateways.use",
	"compute.urlMaps.create",
	"compute.urlMaps.createTagBinding",
	"compute.urlMaps.delete",
	"compute.urlMaps.deleteTagBinding",
	"compute.urlMaps.get",
	"compute.urlMaps.invalidateCache",
	"compute.urlMaps.list",
	"compute.urlMaps.listEffectiveTags",
	"compute.urlMaps.listTagBindings",
	"compute.urlMaps.update",
	"compute.urlMaps.use",
	"compute.urlMaps.validate",
	"compute.vpnGateways.create",
	"compute.vpnGateways.createTagBinding",
	"compute.vpnGateways.delete",
	"compute.vpnGateways.deleteTagBinding",
	"compute.vpnGateways.get",
	"compute.vpnGateways.list",
	"compute.vpnGateways.listEffectiveTags",
	"compute.vpnGateways.listTagBindings",
	"compute.vpnGateways.setLabels",
	"compute.vpnGateways.use",
	"compute.vpnTunnels.create",
	"compute.vpnTunnels.createTagBinding",
	"compute.vpnTunnels.delete",
	"compute.vpnTunnels.deleteTagBinding",
	"compute.vpnTunnels.get",
	"compute.vpnTunnels.list",
	"compute.vpnTunnels.listEffectiveTags",
	"compute.vpnTunnels.listTagBindings",
	"compute.vpnTunnels.setLabels",
	"compute.wireGroups.create",
	"compute.wireGroups.delete",
	"compute.wireGroups.get",
	"compute.wireGroups.list",
	"compute.wireGroups.update",
	"compute.zoneOperations.delete",
	"compute.zoneOperations.get",
	"compute.zoneOperations.getIamPolicy",
	"compute.zoneOperations.list",
	"compute.zoneOperations.setIamPolicy",
	"compute.zones.get",
	"compute.zones.list"
]

NOT_SA_PERMS = [
	"iam.serviceAccounts.create",
    "iam.serviceAccounts.list"
]

NOT_STORAGE_PERMS = [
    "storage.objects.getIamPolicy",
	"storage.objects.setIamPolicy"
]

NOT_FUNCTIONS_PERMS = [
    "cloudfunctions.functions.create",
	"cloudfunctions.functions.list",
	"cloudfunctions.locations.list"
]

class GCPPEASS(CloudPEASS):
    def __init__(self, credentials, project, folder, org, very_sensitive_combos, sensitive_combos, not_use_ht_ai, num_threads, out_path=None):
        self.credentials = credentials
        self.project = project
        self.folder = folder
        self.org = org
        self.all_gcp_perms = self.download_gcp_permissions()

        super().__init__(very_sensitive_combos, sensitive_combos, "GCP", not_use_ht_ai, num_threads,
                         GCP_MALICIOUS_RESPONSE_EXAMPLE, GCP_SENSITIVE_RESPONSE_EXAMPLE, out_path)

    def download_gcp_permissions(self):
        base_ref_page = requests.get("https://cloud.google.com/iam/docs/permissions-reference").text
        permissions = re.findall('<td id="([^"]+)"', base_ref_page)
        print(f"{Fore.GREEN}Gathered {len(permissions)} GCP permissions to check")
        return permissions

    def get_relevant_permissions(self, res_type=None):
        if res_type.lower() == "vm":
            return [p for p in self.all_gcp_perms if p.startswith("compute") and p not in NOT_COMPUTE_PERMS]
        elif res_type.lower() == "function":
            return [p for p in self.all_gcp_perms if p.startswith("cloudfunctions") and p not in NOT_FUNCTIONS_PERMS]
        elif res_type.lower() == "storage":
            return [p for p in self.all_gcp_perms if p.startswith("storage") and p not in NOT_STORAGE_PERMS]
        elif res_type.lower() == "service_account":  # **New branch for service accounts**
            return [p for p in self.all_gcp_perms if p.startswith("iam.serviceAccounts") and p not in NOT_SA_PERMS]
        else:
            return self.all_gcp_perms

    def check_permissions(self, resource_id, perms, verbose=False):
        """
        Test if the user has the indicated permissions on a resource.

        Supported resource types:
        - projects
        - folders
        - organizations
        - functions
        - vms
        - storage
        - Service account
        """
        if "/functions/" in resource_id:
            req = googleapiclient.discovery.build("cloudfunctions", "v1", credentials=self.credentials).projects().locations().functions().testIamPermissions(
                resource=resource_id,
                body={"permissions": perms},
            )
        elif "/instances/" in resource_id:
            req = googleapiclient.discovery.build("compute", "v1", credentials=self.credentials).instances().testIamPermissions(
                project=resource_id.split("/")[1],
                resource=resource_id.split("/")[-1],
                zone=resource_id.split("/")[3],
                body={"permissions": perms},
            )
        elif "/storage/" in resource_id:
            req = googleapiclient.discovery.build("storage", "v1", credentials=self.credentials).buckets().testIamPermissions(
                bucket=resource_id.split("/")[-1],
                permissions=perms,
            )
        elif "/serviceAccounts/" in resource_id:
            req = googleapiclient.discovery.build("iam", "v1", credentials=self.credentials) \
				.projects().serviceAccounts().testIamPermissions(
					resource=resource_id,
					body={"permissions": perms}
				)
        elif resource_id.startswith("projects/"):
            req = googleapiclient.discovery.build("cloudresourcemanager", "v3", credentials=self.credentials).projects().testIamPermissions(
                resource=resource_id,
                body={"permissions": perms},
            )
        elif resource_id.startswith("folders/"):
            req = googleapiclient.discovery.build("cloudresourcemanager", "v3", credentials=self.credentials).folders().testIamPermissions(
                resource=resource_id,
                body={"permissions": perms},
            )
        elif resource_id.startswith("organizations/"):
            req = googleapiclient.discovery.build("cloudresourcemanager", "v3", credentials=self.credentials).organizations().testIamPermissions(
                resource=resource_id,
                body={"permissions": perms},
            )
        else:
            print(f"{Fore.RED}Unsupported resource type: {resource_id}")
            return []

        have_perms = []
        try:
            returnedPermissions = req.execute()
            have_perms = returnedPermissions.get("permissions", [])
        except googleapiclient.errors.HttpError as e:
            if "Cloud Resource Manager API has not been used" in str(e):
                print(Fore.RED + str(e) + "\nTry to enable the service running: gcloud services enable cloudresourcemanager.googleapis.com")
            # **If a permission is reported as invalid, remove it and retry**
            for perm in perms.copy():
                if " " + perm + " " in str(e):
                    perms.remove(perm)
                    with open("/tmp/rem.text", "a") as f:
                        f.write(perm+"\n")
                    return self.check_permissions(resource_id, perms, verbose)
        except Exception as e:
            print("Error:")
            print(e)

        if have_perms and verbose:
            print(f"Found: {have_perms}")

        return have_perms


    def list_projects(self):
        req = googleapiclient.discovery.build("cloudresourcemanager", "v1", credentials=self.credentials).projects().list()
        try:
            result = req.execute()
            return [proj['projectId'] for proj in result.get('projects', [])]
        except:
            return []

    def list_folders(self):
        req = googleapiclient.discovery.build("cloudresourcemanager", "v2", credentials=self.credentials).folders().search(body={})
        try:
            result = req.execute()
            return [folder['name'].split('/')[-1] for folder in result.get('folders', [])]
        except:
            return []

    def list_organizations(self):
        req = googleapiclient.discovery.build("cloudresourcemanager", "v1", credentials=self.credentials).organizations().search(body={})
        try:
            result = req.execute()
            return [org['name'].split('/')[-1] for org in result.get('organizations', [])]
        except:
            return []

    def list_vms(self, project):
        try:
            request = googleapiclient.discovery.build("compute", "v1", credentials=self.credentials).instances().aggregatedList(project=project)
            vms = []
            while request is not None:
                response = request.execute()
                for zone, instances_scoped_list in response.get('items', {}).items():
                    for instance in instances_scoped_list.get('instances', []):
                        # Construct a unique target identifier for the VM
                        zone_name = instance.get('zone', '').split('/')[-1]
                        target_id = f"projects/{project}/zones/{zone_name}/instances/{instance['name']}"
                        vms.append(target_id)
                request = googleapiclient.discovery.build("compute", "v1", credentials=self.credentials).instances().aggregatedList_next(previous_request=request, previous_response=response)
            return vms
        except Exception:
            return []

    def list_functions(self, project):
        try:
            parent = f"projects/{project}/locations/-"
            response = googleapiclient.discovery.build("cloudfunctions", "v1", credentials=self.credentials).projects().locations().functions().list(parent=parent).execute()
            functions = []
            for function in response.get('functions', []):
                # The function name is already fully qualified
                functions.append(function['name'])
            return functions
        except Exception:
            return []

    def list_storages(self, project):
        try:
            response = googleapiclient.discovery.build("storage", "v1", credentials=self.credentials).buckets().list(project=project).execute()
            buckets = []
            for bucket in response.get('items', []):
                # Construct a unique target identifier for the Storage bucket
                buckets.append(f"projects/{project}/storage/{bucket['name']}")
            return buckets
        except Exception:
            return []
    
    def list_service_accounts(self, project):
        try:
            service = googleapiclient.discovery.build("iam", "v1", credentials=self.credentials)
            # The service account resource name will be like "projects/{project}/serviceAccounts/{email}"
            response = service.projects().serviceAccounts().list(name=f"projects/{project}").execute()
            accounts = []
            for account in response.get('accounts', []):
                accounts.append(account['name'])  # Use the full resource name
            return accounts
        except Exception as e:
            print(f"{Fore.RED}Error listing service accounts for project {project}: {e}")
            return []

    def get_resources_and_permissions(self):
        # Build a list of targets with type information

        print("Listing projects, folders, and organizations...")
        targets = []
        if self.project:
            targets.append({"id": f"projects/{self.project}", "type": "project"})
        if self.folder:
            targets.append({"id": f"folders/{self.folder}", "type": "folder"})
        if self.org:
            targets.append({"id": f"organizations/{self.org}", "type": "organization"})

        for proj in self.list_projects():
            targets.append({"id": f"projects/{proj}", "type": "project"})
        for folder in self.list_folders():
            targets.append({"id": f"folders/{folder}", "type": "folder"})
        for org in self.list_organizations():
            targets.append({"id": f"organizations/{org}", "type": "organization"})

        # For each project, add VMs, Cloud Functions, and Storage buckets
        print("Trying to list VMs, Cloud Functions, and Storage buckets on each project...")
        def process_project(proj):
            local_targets = []
            for vm in self.list_vms(proj):
                local_targets.append({"id": vm, "type": "vm"})
            for func in self.list_functions(proj):
                local_targets.append({"id": func, "type": "function"})
            for bucket in self.list_storages(proj):
                local_targets.append({"id": bucket, "type": "storage"})
            for sa in self.list_service_accounts(proj):
                local_targets.append({"id": sa, "type": "service_account"})
            return local_targets

        # **Process projects concurrently using a thread pool**
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            futures = {executor.submit(process_project, proj): proj for proj in self.list_projects()}
            for future in tqdm(as_completed(futures), total=len(futures), desc="Processing projects"):
                targets.extend(future.result())

        # Start looking for permissions
        found_permissions = []
        lock = Lock()

        # Function to process each target resource
        def process_target(target):
            # Get relevant permissions based on target type
            relevant_perms = self.get_relevant_permissions(target["type"])
            # Split permissions into chunks of 20
            perms_chunks = [relevant_perms[i:i+20] for i in range(0, len(relevant_perms), 20)]
            collected = []

            # Use a thread pool to process each permission chunk concurrently
            with ThreadPoolExecutor(max_workers=5) as executor:
                # Submit tasks for each chunk
                futures = {executor.submit(self.check_permissions, target["id"], chunk): chunk for chunk in perms_chunks}
                # Iterate over completed futures with a progress bar
                for future in tqdm(as_completed(futures), total=len(futures), desc=f"Checking permissions for {target['id']}", leave=False):
                    result = future.result()
                    collected.extend(result)

            return {
                "id": target["id"],
                "name": target["id"].split("/")[-1],
                "permissions": collected,
                "type": target["type"]
            }

        if not targets:
            print(f"{Fore.RED}No targets found! Indicate a project, folder or organization manually. Exiting.")
            exit(1)
        
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            futures = {executor.submit(process_target, target): target for target in targets}
            for future in tqdm(as_completed(futures), total=len(futures)):
                res = future.result()
                with lock:
                    found_permissions.append(res)

        return found_permissions


if __name__ == "__main__":
    #print("Not ready yet!")
    #exit(1)

    parser = argparse.ArgumentParser(description="GCPPEASS: Enumerate GCP permissions and check for privilege escalations and other attacks with HackTricks AI.")

    scope_group = parser.add_mutually_exclusive_group(required=False)
    scope_group.add_argument('--project', help="Project ID")
    scope_group.add_argument('--folder', help="Folder ID")
    scope_group.add_argument('--organization', help="Organization ID")

    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument('--sa-credentials-path', help="Path to credentials.json")
    auth_group.add_argument('--token', help="Raw access token")

    parser.add_argument('--out-json-path', default=None, help="Output JSON file path (e.g. /tmp/gcp_results.json)")
    parser.add_argument('--threads', default=5, type=int, help="Number of threads to use")
    parser.add_argument('--not-use-hacktricks-ai', action="store_false", default=False, help="Don't use Hacktricks AI to analyze permissions")

    args = parser.parse_args()

    token = os.getenv("CLOUDSDK_AUTH_ACCESS_TOKEN", args.token).rstrip()
    sa_credentials_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", args.sa_credentials_path)
    creds = google.oauth2.credentials.Credentials(token) if token else \
        google.oauth2.service_account.Credentials.from_service_account_file(
            sa_credentials_path, scopes=["https://www.googleapis.com/auth/cloud-platform"])

    gcp_peass = GCPPEASS(
        creds, args.project, args.folder, args.organization,
        very_sensitive_combinations, sensitive_combinations,
        not_use_ht_ai=args.not_use_hacktricks_ai,
        num_threads=args.threads,
        out_path=args.out_json_path
    )
    gcp_peass.run_analysis()