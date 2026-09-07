# K8sPEASS permission risk model

K8sPEASS rates the highest locally reproduced offensive impact of an allowed Kubernetes
request. A rating does not mean that the whole attack is guaranteed. The target
may not exist, a resourceNames restriction may select only a decoy, admission
may reject a write, a custom authorizer may disagree with RBAC, or a controller
may ignore attacker-controlled fields. The report preserves those constraints
and labels incomplete evidence.

## Critical

Critical permissions expose credentials or bypass an authorization boundary
directly:

| Permission pattern | Potential attack path |
| --- | --- |
| get, list, watch, or wildcard on Secrets | Read tokens, TLS keys, registry credentials, or application secrets. |
| get, list, watch, or wildcard on all resources | Read Secrets plus every current and future resource in the granted scope. |
| create or wildcard on serviceaccounts/token | Mint a bound token for a named ServiceAccount. |
| get, create, or wildcard on nodes/proxy | Reach kubelet APIs; get-only executed through direct kubelet WebSocket `/exec`, while create-only executed through `/run` directly and via the API-server proxy in the v1.37 test. |
| impersonate or constrained impersonate-on verbs on identity resources | Send authorized requests as another user, group, ServiceAccount, UID, or user-extra value. |
| bind on Roles or ClusterRoles | Bind a role without already holding every permission it grants. |
| escalate on Roles or ClusterRoles | Create or update a role containing permissions the caller does not hold. |

## High

High permissions provide code execution, policy bypass, traffic interception,
control-plane modification, or a strong conditional escalation primitive:

- Pod create and create/update/patch on Deployments, DaemonSets, StatefulSets,
  ReplicaSets, ReplicationControllers, Jobs, and CronJobs.
- Sensitive Pod subresources: exec, attach, portforward, proxy,
  ephemeralcontainers, and direct Pod binding. Service proxy access is also high.
- CSR creation, CSR approval writes, and `approve` on the selected Signer.
- Secret create/update/patch, ConfigMap update/patch, and RBAC
  create/update/patch.
- ValidatingAdmissionPolicyBinding update/patch/delete and Namespace
  create/update/patch when selectors define the policy boundary.
- NetworkPolicy update/patch/delete, Service or EndpointSlice update/patch,
  PersistentVolume create, Node update/patch, and ClusterTrustBundle
  update/patch.
- Create/update/patch wildcards over all resources and non-resource `*` or
  `/debug/*` only after a bounded GET confirms a concrete debug endpoint.

These findings must show their prerequisites. A workload write is most
dangerous when the caller can select a privileged ServiceAccount or a
node-escape configuration and admission allows it. A custom resource is
dangerous only when a live controller consumes its attacker-controlled fields
with a more privileged identity.

## Medium

Medium permissions are useful inputs or resource-specific mutations that do not
normally cross an authorization boundary alone. Examples include Pod logs,
kubelet stats or config reads, reads of workloads, ConfigMaps, identities,
RBAC, topology, traffic, and storage metadata, review oracles for supplied
subjects, Pod patch/delete/eviction/status, CSR status, Signer `sign`/`attest`,
SCC/PSP `use`, controller-specific admission resources, Kyverno/Gatekeeper,
PodTemplate, ServiceAccount, quota, LimitRange, PodDisruptionBudget,
PriorityClass, PVC, snapshot/CSI, CRD/APIService, PodCertificateRequest, DRA,
storage-version-migration, generic custom-resource, kubelet-checkpoint, Lease,
and unverified sensitive non-resource URL grants, plus deletion of an
individual Secret or ServiceAccount.

## Low

Low permissions are ordinary discovery or metadata access with no known direct
high-impact path. Examples include API discovery URLs, self-review APIs,
Namespace reads, and reads of otherwise unclassified resources.

## Ordering and edge cases

The classifier evaluates credential and authorization bypasses before generic
resource families. This prevents a get-all-resources rule from becoming a low
read. It also checks the verb expected by each subresource, so merely reading
the pods/ephemeralcontainers representation is not reported as injection.

Wildcard rules include future API resources and therefore carry version-drift
risk. Custom and controller-specific resources cannot be classified from RBAC
names alone, so their writes remain medium until the live controller effect is
reproduced. Multi-permission chains such as
CSR create plus approve, workload write plus a privileged ServiceAccount, or
Secret create plus read are reported as their individual primitives and must be
joined during attack-path analysis.

An explicit rule can be authorized by RBAC even when its API group/resource is
not installed, or when the served endpoint does not support that verb.
K8sPEASS retains such a rule as a dormant low finding, records its
`potential_severity`, and excludes it from active critical/high totals. This
does not apply to wildcards or virtual authorization resources such as
Signers, impersonated users/groups, and kubelet-only Node subresources.

Non-resource RBAC has the same problem. K8sPEASS uses only bounded, read-only
availability probes for known paths. A successful `/debug/pprof/` probe can
remain high; HTTP 404 becomes dormant low, and an unsafe or inconclusive path
becomes conditional medium. The scanner never calls workload proxy paths.

Special verbs are resource-specific. `bind` and `escalate` are critical only on
Roles/ClusterRoles, and impersonation is critical only on identity resources.
K8sPEASS also treats `unsafe-delete-ignore-read-errors` and DRA's node-aware
`:patch`/`:update` verbs as mutations, while keeping unrelated made-up special
verbs low. A `resourceNames` constraint is preserved in every finding; note
that Kubernetes generally cannot constrain a `create` request by a name that
does not exist yet.
