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
| impersonate users or ServiceAccounts | Send authorized requests as another user or ServiceAccount. Group/UID/extra grants alone cannot start impersonation. |
| bind on Roles or ClusterRoles | Bind a role without already holding every permission it grants. |
| escalate on Roles or ClusterRoles | Create or update a role containing permissions the caller does not hold. |

## High

High permissions provide code execution, policy bypass, traffic interception,
control-plane modification, or a strong conditional escalation primitive:

- Pod create/update/patch and create/update/patch on Deployments, DaemonSets,
  StatefulSets, ReplicaSets, ReplicationControllers, Jobs, and CronJobs. A Pod
  metadata patch can move traffic by changing labels selected by a Service.
- Sensitive Pod subresources: exec, attach, portforward, proxy,
  ephemeralcontainers, and direct Pod binding. Service proxy access is also high.
- CSR creation, CSR approval writes, and `approve` on the selected Signer.
- Secret create/update/patch and ConfigMap create/update/patch. Create-only can
  supply an expected but initially absent object name.
- ValidatingAdmissionPolicy or binding update/patch/delete; admission webhook
  create/update/patch/delete; and MutatingAdmissionPolicy or binding
  create/update/patch. The native mutating-policy paths can inject init or
  sidecar containers into subsequently admitted Pods. A newly registered
  reachable mutating webhook can do the same, while a validating webhook can
  receive full matching objects such as Secrets.
- Exact custom permissions referenced by a canonical negated admission
  `authorizer...check(...).allowed()` match condition. K8sPEASS only elevates
  the exact grant after reading the configuration and confirming it with SSAR.
- Exact create/patch/update/delete permissions over a named parameter object
  referenced by an enforced ValidatingAdmissionPolicy binding. Create is high
  only when the object is observably absent and missing parameters deny;
  patch/update require an existing object; delete additionally requires
  `parameterNotFoundAction: Allow`.
- Namespace create/update/patch when selectors define an admission boundary.
- NetworkPolicy create/update/patch/delete; Service or legacy Endpoints
  create/update/patch; EndpointSlice create/update/patch; Pod or Service status
  update/patch; PersistentVolume create; Node update/patch; and
  ClusterTrustBundle update/patch. The traffic paths include selectorless
  backends, readiness spoofing, Service-name squatting, ExternalName DNS
  redirection, and LoadBalancer IP interception. The ExternalName patch was
  reproduced by changing an existing trusted ClusterIP Service into an alias
  for an attacker Service: the same client hostname then sent its Authorization
  header to the attacker backend.
- Ingress create/patch when an active controller accepts the object.
  Create can expose an internal Service through a new host/path; patch can
  redirect a trusted route to another Service.
- Gateway API HTTPRoute create/patch when an accepted Gateway permits
  the attachment. Tested impacts include exposing an internal Service,
  redirecting a trusted hostname, and silently mirroring requests—including
  authorization headers—to another backend.
- Exact deletion of an existing Service referenced by a
  `failurePolicy: Ignore` admission webhook. The resulting connection failure
  skips that webhook.
- Exact patch/update of a Deployment `/scale` subresource when read-only live
  correlation proves that Deployment owns every ready EndpointSlice Pod behind
  a `failurePolicy: Ignore` webhook Service. Scaling it to zero skips the
  unavailable webhook. Uncorrelated controller scale writes remain medium.
- Exact deletion of that same sole ready Deployment backend. Generic
  Deployment deletion remains medium; only the live fail-open correlation is
  elevated.
- Kubernetes 1.36+ constrained impersonation identity and `impersonate-on:*`
  action grants are high when their matching half exists and the delegated
  action has high or critical impact.
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
subjects, RBAC object writes without matching bind/escalate, Pod delete/eviction,
Node status, CSR status, Signer `sign`/`attest`, group/UID/user-extra
impersonation grants that lack user impersonation,
controller `status`/`scale` subresource writes without the correlated
single-backend fail-open admission case,
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

Classification uses both API group and resource. A custom resource called
`secrets`, `pods`, or `services` in an unrelated API group is not treated as the
built-in object. A core-resource wildcard can include Secrets and is critical;
a wildcard confined to another API group is not. Wildcard rules still include
future resources in their group and therefore carry version-drift risk. Custom
and controller-specific resources cannot be classified from RBAC names alone,
so their writes remain medium until the live controller effect is reproduced.
Multi-permission chains such as
CSR create plus approve, workload write plus a privileged ServiceAccount, or
Secret create plus read are reported as their individual primitives and must be
joined during attack-path analysis.

An explicit rule can be authorized by RBAC even when its API group/resource is
not installed, or when the served endpoint does not support that verb.
K8sPEASS retains such a rule as a dormant low finding, records its
`potential_severity`, and excludes it from active critical/high totals. This
does not apply to wildcards or virtual authorization resources such as
Signers, traditional or constrained impersonation identities, and kubelet-only
Node subresources.

Non-resource RBAC has the same problem. K8sPEASS uses only bounded, read-only
availability probes for known paths. A successful `/debug/pprof/` probe can
remain high; HTTP 404 becomes dormant low, and an unsafe or inconclusive path
becomes conditional medium. The scanner never calls workload proxy paths.

Special verbs are resource-specific. `bind` and `escalate` are critical only on
Roles/ClusterRoles. Traditional user or ServiceAccount impersonation is
critical; group, UID, and extra-field grants are conditional because Kubernetes
also requires user impersonation. Constrained impersonation is reported as two
conditional halves: an `impersonate:<mode>` identity selector and an
`impersonate-on:<mode>:<verb>` action grant.
K8sPEASS also treats `unsafe-delete-ignore-read-errors` and DRA's node-aware
`:patch`/`:update` verbs as mutations, while keeping unrelated made-up special
verbs low. A `resourceNames` constraint is preserved in every finding; note
that Kubernetes generally cannot constrain a `create` request by a name that
does not exist yet.
