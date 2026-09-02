# Kubernetes API proxy

Investigation of adding kube-apiserver as a first-class Waypoint listener
mode, plus the impersonating HTTP reverse-proxy implementation that followed
from it.

## Why TCP mode is not enough

A `mode = "tcp"` listener in front of kube-apiserver already works as a
byte pipe: Tailscale `WhoIs` + an empty backend grant, then raw TLS to the
API server. Clients still need a real kubeconfig (client cert or token) that
the cluster trusts. Waypoint never learns *who* is calling Kubernetes, so it
cannot:

- map Tailscale identity onto Kubernetes RBAC
- stop a client from sending `Impersonate-*` headers if they hold a powerful
  token
- treat watches / exec the same as other protocol-aware listeners for
  revalidation and structured errors

The Postgres and MongoDB modes exist because identity-in, scoped-backend-user-out
is the product. Kubernetes needs the same shape, but the backend already has
a first-class impersonation API, so we should not invent per-user
ServiceAccounts unless we have to.

## Recommendation: follow Tailscale's impersonating proxy (implemented)

`mode = "kubernetes"` terminates the client connection (TLS by default),
authenticates the Tailscale peer against `redo.com/cap/waypoint`, then
reverse-proxies HTTP/1.1 to kube-apiserver using **Waypoint's** token. HTTP/2
is deliberately disabled, matching Tailscale, because Kubernetes SPDY
streaming is incompatible with h2. Each request:

1. Strips client `Impersonate-User` / `Impersonate-Group` / `Impersonate-Uid`
   / `Impersonate-Extra-*` headers (clients must not escalate).
2. Sets `Authorization: Bearer <waypoint token>`.
3. Sets `Impersonate-User` to the Tailscale login for user devices, or the
   node FQDN for tagged devices. Groups come from the grant; node tags are the
   fallback groups for tagged devices.

Cluster RBAC stays the source of truth. Waypoint only decides *whether the
peer may use this listener* and *which identity/groups to impersonate*.

This now follows the Tailscale Kubernetes operator's core behavior:

- WhoIs and grant evaluation happen per HTTP request.
- User devices impersonate the login; tagged devices impersonate the node
  FQDN and fall back to node tags as groups.
- The grant payload is `impersonate.groups`.
- Client and upstream HTTP/2 are disabled for SPDY compatibility.
- client-go supplies the upstream token/TLS transport.

The intentional Waypoint differences are listener-scoped
`redo.com/cap/waypoint` grants, Redis connection limits, and OTel telemetry.
Tailscale's explicit exec/attach routes exist to add session recording;
without recording, both implementations use the same ReverseProxy upgrade
path. Waypoint does not yet implement Tailscale's tsrecorder integration.

### ACL grammar

```json
{
  "backends": {
    "eks-prod": {
      "k8s": {
        "impersonate": {
          "groups": ["waypoint:readonly", "system:authenticated"]
        }
      }
    }
  }
}
```

An empty backend object (`"eks-prod": {}`) is still a grant, same as TCP:
impersonate the login name with no extra groups. ClusterRoleBindings on that
username (typically an email) then apply.

Do **not** grant `system:masters` in Waypoint ACLs unless that is the
explicit break-glass intent. Prefer dedicated groups such as
`waypoint:readonly` bound to a narrow ClusterRole.

### Waypoint's apiserver principal

The token in `[listeners.kubernetes]` must be allowed to impersonate:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: waypoint-impersonator
rules:
  - apiGroups: [""]
    resources: ["users", "groups", "serviceaccounts"]
    verbs: ["impersonate"]
  - apiGroups: ["authentication.k8s.io"]
    resources: ["userextras"]
    verbs: ["impersonate"]
```

Bind that to the ServiceAccount (or user) whose token Waypoint presents.
Bind *end-user* groups separately (`Role` / `ClusterRole` on
`waypoint:readonly`, etc.).

In-cluster:

```toml
[[listeners]]
name = "eks-prod"
listen = ":6443"
mode = "kubernetes"
backend = "kubernetes.default.svc:443"
tls = true
tls_mode = "require"

[listeners.kubernetes]
token_file = "/var/run/secrets/kubernetes.io/serviceaccount/token"
ca_file = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
```

The backend transport is built with client-go. Projected ServiceAccount token
files rotate through the same mechanism used by ordinary Kubernetes clients.

### Client kubeconfig

Clients point `cluster.server` at the Waypoint listener. They should **not**
send a privileged token; Waypoint ignores client `Authorization` and
replaces it. A dummy user entry is enough:

```yaml
apiVersion: v1
kind: Config
clusters:
  - name: waypoint
    cluster:
      server: https://waypoint-db:6443
      # trust the Tailscale or file cert served by tls_mode
users:
  - name: waypoint
    user:
      token: unused
contexts:
  - name: waypoint
    context:
      cluster: waypoint
      user: waypoint
current-context: waypoint
```

## Alternatives considered

| Approach | Verdict |
|---|---|
| TCP passthrough | Already available; no identity mapping. Fine as a stopgap. |
| Provision ServiceAccount + RoleBinding per user | Closest to Postgres `EnsureUser`. Heavy: objects to GC, token projection, conflict with GitOps, and Kubernetes already has impersonation for this. Revisit only if impersonation is forbidden in a cluster. |
| Mint short-lived client certs | Needs a CA trusted by the apiserver (`--client-ca-file`). Operationally worse than impersonation for most EKS/GKE/AKS setups. |
| kubectl exec credential plugin | Complements the proxy (fetch a token) but does not replace TLS + HTTP to a stable API URL. Not required for v1. |
| Path/verb ACL in Waypoint | Parsing `/api` vs `/apis` vs subresources is a second RBAC engine. Easy to get wrong (`exec`, `portforward`, `proxy`, `attach`). Defer; use Kubernetes RBAC. |

## Protocol gaps (follow-ups)

The Go `httputil.ReverseProxy` with `FlushInterval: -1` covers REST, watches,
and HTTP Upgrade. HTTP/1.1 is forced on both sides for SPDY compatibility. A
k3s test exercises real RBAC and client-go's SPDY executor through Waypoint.

Still unproven in this tree:

- `kubectl cp` / `attach` / `port-forward` end-to-end
- Aggregated APIs and the Konnectivity / apiserver-network-proxy path
- WebSocket exec negotiation used by newer kubectl clients

Treat those as the next implementation slice, not as design unknowns.

## What we are not doing yet

- Dynamic Kubernetes object provisioning (the Postgres analog)
- Namespace allow-lists in the capability JSON
- A `waypoint kubeconfig` helper command
- Shipping this as a replacement for the Tailscale Kubernetes operator
  (operator still owns subnet routes, API server exposure, and in-cluster
  auth for nodes)

## Mapping to existing Waypoint subsystems

| Subsystem | Kubernetes mode |
|---|---|
| `auth.Authorize` | Unchanged; backend key is the listener name |
| `auth.K8sCap` | Tailscale-compatible `impersonate.groups` |
| `restrict.Tracker` | Connection slots + byte counting on the client conn |
| Revalidation | WhoIs + grant evaluation on every HTTP request |
| Provisioner / Redis locks | Unused (no per-user backend objects) |
| Client `tls_mode` | Defaults to `require` (kubectl always uses TLS) |
| Backend `tls` | HTTPS to kube-apiserver |
| Heartbeat | Mode `kubernetes`; no provisioner credential field |
