# K8sPEASS

K8sPEASS enumerates the effective permissions of the current Kubernetes
identity and explains the dangerous ones. Runtime requests are strictly
read-only: HTTP `GET` plus the three non-persisted self-review APIs
(`SelfSubjectReview`, `SelfSubjectRulesReview`, and
`SelfSubjectAccessReview`). It never creates, updates, patches, or deletes a
resource and never uses exec, attach, port-forward, workload proxying,
TokenRequest, CSR, or dry-run write probes.

The severity taxonomy and complete critical/high permission families are
documented in [K8sPEASS permission risk model](K8sPEASS-risk-model.md).

## Quick start

```bash
python3 K8sPEASS.py --context my-context

# A bearer token can be kept out of the process list.
K8S_TOKEN='ey...' python3 K8sPEASS.py \
  --server https://10.0.0.1:6443 \
  --certificate-authority /path/to/ca.crt

# Automation: do not prompt and skip the slow exhaustive phase.
python3 K8sPEASS.py --no-ask --skip-bruteforce \
  --out-json-path /tmp/k8speass.json
```

The official Python Kubernetes client is preferred. If it is unavailable,
K8sPEASS falls back to `kubectl` and applies the same hard request allowlist.
Kubeconfig, direct bearer-token, client-certificate, and in-cluster service
account authentication are supported. `--namespace` can be repeated when a
namespace name is known but namespace listing is forbidden.
Temporary throttling, API-server 5xx responses, TLS interruptions, connection
resets, and timeouts are retried with bounded backoff. Use `--retries 0` to
disable this or a value up to 5 for unstable links.

## Enumeration strategy

1. Ask the live API server for the authenticated identity. If that review is
   unavailable, show sanitized kubeconfig/in-cluster context data and
   explicitly unverified JWT claims as a fallback.
2. Dynamically discover core APIs, aggregated APIs, CRDs, subresources,
   advertised verbs, API versions, and whether each resource is namespaced.
   Explicit RBAC tuples for an API group/resource or operation that is not
   currently served are retained as dormant grants and do not inflate the
   active critical/high totals. Their potential severity remains in JSON in
   case that API is installed later.
   Sensitive non-resource URL grants use only bounded read-only availability
   checks for known safe paths: confirmed endpoints stay high, HTTP 404 is
   dormant, and unsafe or inconclusive patterns remain conditional/medium.
3. Request a `SelfSubjectRulesReview` for every known namespace. Preserve
   wildcard rules, non-resource URLs, special verbs, subresources, and
   `resourceNames` restrictions. Namespace names are sourced from the API when
   allowed, explicit CLI values, the kubeconfig namespace, and an unverified
   service-account token claim.
4. Confirm summarized high/critical results with exact
   `SelfSubjectAccessReview` calls. If rules review is unavailable or empty,
   run a small fixed set of useful checks so the tool still provides value to
   principals that cannot list RBAC, namespaces, or workload objects. These
   include credential, workload, traffic-redirection, admission-control, and
   traditional/constrained-impersonation checks. They are authorization-review
   requests only and do not exercise the allowed operation.
5. Optionally run an exhaustive matrix over every discovered API resource,
   subresource, advertised verb and known namespace, plus security-sensitive
   special verbs—including Kubernetes 1.36+ constrained impersonation—and
   non-resource URLs. This can be slow and noisy in audit
   logs, so interactive runs ask first. `--brute-force-permissions` is the
   explicit bypass; `--no-ask` safely skips it unless that flag is present.
6. If readable, explain matching RoleBindings/ClusterRoleBindings and their
   Role/ClusterRole rules. RBAC inventory is explanatory only; permission
   results do not depend on being able to list those objects.
7. Passively inspect Pod Security Admission labels, admission webhooks,
   Validating/MutatingAdmissionPolicies, LimitRanges, ResourceQuotas, and
   discoverable Kyverno/Gatekeeper policy objects. Fail-open policies and
   selectors are highlighted, but never called proven bypasses.

## Important interpretation notes

- An allowed create/update/delete-style authorization result does not prove
  that admission will accept the request. The console and JSON output label
  this uncertainty, including observed PSA labels when available.
- `SelfSubjectRulesReview` can be incomplete for some authorizers. K8sPEASS
  preserves the API server's incomplete/evaluation-error state and never turns
  uncertainty into a denial.
- A forbidden namespace list means hidden namespace names may exist. Supply
  known names with repeated `--namespace`; K8sPEASS also tries exact namespace
  `GET` requests so readable PSA labels are not lost.
- Name-constrained `list`/`watch` rules are represented with the required
  `metadata.name` field selector. Some API servers do not confirm selector
  constraints through `SelfSubjectAccessReview`, so a positive rules-review
  result is retained when the exact review returns only “no opinion.”
- The JSON report includes all allowed, denied, and unknown review results,
  active versus dormant/unserved grants, discovery coverage, inaccessible
  optional inventories, admission evidence, and the discovered API-resource
  catalog. The concise console view hides
  low-risk and repeated entries unless `--show-all` is used.
- JSON output is written through a private, uniquely named temporary file and
  atomically replaced, avoiding partial reports and collisions between scans.

Explicit impersonation is available for authorized testing:

```bash
python3 K8sPEASS.py --as system:serviceaccount:demo:reader \
  --as-group system:serviceaccounts --namespace demo
```

This only adds Kubernetes impersonation headers. K8sPEASS does not discover a
permission and then automatically impersonate another identity.
