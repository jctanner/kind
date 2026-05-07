# Phase 5: Mock OpenShift OAuth Server + Kind OCP Shim

## Context

Phases 1-4 are complete. The full Gateway API + Envoy + ext_authz + kube-auth-proxy chain is working:
- Token auth (Bearer SA tokens via K8s TokenReview) returns 202
- Browser flow fails -- kube-auth-proxy with `--provider=openshift` hits `/.well-known/oauth-authorization-server` on the K8s API server and gets 403 (kind doesn't serve this endpoint)

**Constraint**: Cannot modify the kube-auth-proxy Deployment -- the ODH operator reconciles it. For OpenShift OAuth, it should "just work" without any env var injection or webhook hacks.

**Approach**: Two-part fix:
1. **Kind fork** (`example.src/kind`, OCP_SHIM branch) -- make the K8s API server serve `/.well-known/oauth-authorization-server` so kube-auth-proxy discovers OAuth endpoints transparently
2. **Simulator** -- mock OAuth server handling the actual `/oauth/authorize`, `/oauth/token`, `/oauth/userinfo` flow

## Architecture

### Browser flow after this change

```
Browser --> rh-ai.apps.ocp-sim.localhost:8080 --> proxy --> Envoy --> ext_authz
  --> kube-auth-proxy: no cookie
  --> discovers OAuth via GET https://kubernetes.default.svc/.well-known/oauth-authorization-server
  --> 302 to https://oauth-openshift.apps.ocp-sim.localhost:9443/oauth/authorize
  --> mock auto-approves --> 302 back with code to /oauth2/callback
  --> kube-auth-proxy exchanges code at https://oauth-openshift.apps.ocp-sim.localhost:9443/oauth/token
  --> sets _oauth2_proxy cookie --> 302 to original page
  --> ext_authz passes (valid cookie) --> backend
```

### Components

| Component | Location | Port | Purpose |
|-----------|----------|------|---------|
| API server sidecar | Kind node (static pod) | 6443 | Serves `/.well-known/oauth-authorization-server`, proxies all else to real API server on 16443 |
| Mock OAuth server | Simulator DaemonSet | 9443 (HTTPS) | `/oauth/authorize`, `/oauth/token`, `/oauth/userinfo` |

---

## Part 1: Kind Fork Changes

### 1a. `cmd/ocp-shim/main.go` -- API server front-proxy (~120 lines Go)

A small Go binary that:
- Listens on `--listen=:6443` with TLS using `--tls-cert-file` and `--tls-key-file` (same certs as the API server from `/etc/kubernetes/pki/`)
- For `GET /.well-known/oauth-authorization-server`: returns discovery JSON read from `--well-known-file=/etc/kubernetes/ocp-shim/well-known.json`
- For all other requests: reverse proxies to `--upstream=https://localhost:16443` with TLS skip-verify

This binary is compiled into the kind node image alongside other Go binaries (containerd, runc, crictl, CNI).

### 1b. `images/base/Dockerfile` -- build stage for ocp-shim

Add a new build stage (following the existing pattern for `build-cni`, `build-crictl`, etc.):

```dockerfile
FROM go-build AS build-ocp-shim
COPY --chmod=0755 cmd/ocp-shim/ /go/src/ocp-shim/
WORKDIR /go/src/ocp-shim
RUN CGO_ENABLED=0 GOARCH=$TARGETARCH go build -o /go/bin/ocp-shim .

# In final stage:
COPY --from=build-ocp-shim /go/bin/ocp-shim /usr/local/bin/ocp-shim
```

The ocp-shim source lives in the kind repo at `cmd/ocp-shim/` with its own `go.mod` (minimal deps: just `net/http`, `net/http/httputil`, `crypto/tls` from stdlib).

### 1c. `pkg/cluster/internal/create/actions/ocpshim/ocpshim.go` -- Kind create action

Runs **after kubeadminit**, **before installcni**. Steps:

1. Get control plane node
2. Write `/etc/kubernetes/ocp-shim/well-known.json` to the node:
   ```json
   {
     "issuer": "https://oauth-openshift.apps.ocp-sim.localhost:9443",
     "authorization_endpoint": "https://oauth-openshift.apps.ocp-sim.localhost:9443/oauth/authorize",
     "token_endpoint": "https://oauth-openshift.apps.ocp-sim.localhost:9443/oauth/token",
     "scopes_supported": ["user:check-access","user:full","user:info","user:list-projects"],
     "response_types_supported": ["code","token"],
     "grant_types_supported": ["authorization_code","implicit"],
     "code_challenge_methods_supported": ["plain","S256"]
   }
   ```
3. Read `/etc/kubernetes/manifests/kube-apiserver.yaml` from the node
4. Patch the static pod manifest:
   - Change `--secure-port=6443` to `--secure-port=16443` on the kube-apiserver container
   - Update liveness/readiness/startup probes from port 6443 to 16443
   - Add a sidecar container `ocp-shim` that runs `/usr/local/bin/ocp-shim` on port 6443
   - Mount `/etc/kubernetes/pki` (TLS certs) and `/etc/kubernetes/ocp-shim` (well-known config) into the sidecar
5. Write the patched manifest back to the node
6. Wait for the API server to come back (retry `kubectl get --raw /healthz` with backoff)

### 1d. `pkg/cluster/internal/create/create.go` -- register the action

Insert `ocpshim.NewAction()` after `kubeadminit.NewAction()`:

```go
actionsToRun = append(actionsToRun,
    kubeadminit.NewAction(opts.Config),
    ocpshim.NewAction(),        // <-- NEW
)
```

### Key files (kind fork)

| File | Action |
|------|--------|
| `cmd/ocp-shim/main.go` | Create |
| `cmd/ocp-shim/go.mod` | Create |
| `images/base/Dockerfile` | Modify (add build stage + COPY) |
| `pkg/cluster/internal/create/actions/ocpshim/ocpshim.go` | Create |
| `pkg/cluster/internal/create/create.go` | Modify (add action to chain) |

---

## Part 2: Simulator Changes

### 2a. `simulator/src/oauth.rs` -- Mock OAuth server (~300 lines)

HTTPS server using hyper + tokio-rustls on `0.0.0.0:9443`:
- Generates TLS cert (CN=`oauth-openshift.apps.ocp-sim.localhost`) signed by CaState
- In-memory state: `HashMap<String, AuthCode>` for codes (TTL 5min), `HashMap<String, TokenInfo>` for tokens (TTL 24h)
- Validates `client_id` and `client_secret` against OAuthClient CRs in the cluster

**Endpoints:**
- `GET /oauth/authorize` -- validates `client_id` + `redirect_uri` against OAuthClient CR, generates auth code, immediately 302 redirects back with `?code=<code>&state=<state>` (auto-approve, no login form)
- `POST /oauth/token` -- validates `code` + `client_id` + `client_secret`, returns `{"access_token":"sha256~<random>","token_type":"Bearer","expires_in":86400}`
- `GET /oauth/userinfo` -- validates Bearer token, returns `{"sub":"admin","name":"admin","email":"admin@ocp-sim.localhost","preferred_username":"admin"}`
- `GET /.well-known/oauth-authorization-server` -- returns same discovery JSON (so the OAuth server itself can also serve this)

**On startup**, the controller creates:
- Namespace `openshift-authentication` (if not exists)
- Service `oauth-openshift` in `openshift-authentication` (headless, port 9443)
- Endpoints for the service pointing to node IP:9443
- Route `oauth-openshift` with host `oauth-openshift.apps.ocp-sim.localhost` targeting the service

### 2b. CoreDNS patch for in-cluster DNS

kube-auth-proxy runs as a pod. When it resolves `oauth-openshift.apps.ocp-sim.localhost`, CoreDNS forwards to the host DNS, which returns `127.0.0.1` -- useless inside a pod (127.0.0.1 is the pod itself).

On startup, the OAuth controller patches the CoreDNS ConfigMap in `kube-system` to add a hosts entry mapping `*.apps.ocp-sim.localhost` to the node's internal IP (e.g., `172.18.0.2`). This makes the OAuth URLs resolvable from kube-auth-proxy and all other in-cluster pods.

### 2c. Integrate into `main.rs`

```rust
mod oauth;
// ...
let oauth_handle = tokio::spawn(oauth::run(client.clone(), ca.clone()));
```

### 2d. Dependencies (`Cargo.toml`)

```toml
tokio-rustls = "0.26"
rustls-pemfile = "2"
```

### Key files (simulator)

| File | Action |
|------|--------|
| `simulator/src/oauth.rs` | Create |
| `simulator/src/main.rs` | Modify (add module, spawn task) |
| `simulator/Cargo.toml` | Modify (add tokio-rustls, rustls-pemfile) |
| `deploy/simulator.yaml` | Modify (RBAC + DaemonSet port 9443) |

---

## Part 3: Configuration Changes

### 3a. Kind cluster config (`kind/cluster.yaml`)

Add port 9443 mapping:

```yaml
extraPortMappings:
  - containerPort: 80
    hostPort: 8080
    protocol: TCP
  - containerPort: 443
    hostPort: 8443
    protocol: TCP
  - containerPort: 9443
    hostPort: 9443
    protocol: TCP
```

### 3b. RBAC additions (`deploy/simulator.yaml`)

```yaml
- apiGroups: ["oauth.openshift.io"]
  resources: ["oauthclients"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "watch", "update", "patch"]
```

### 3c. DaemonSet port addition (`deploy/simulator.yaml`)

```yaml
- containerPort: 9443
  hostPort: 9443
  protocol: TCP
```

---

## Implementation Order

1. **Kind fork first** (Go code) -- build ocp-shim binary, add to node image, add create action
2. **Rebuild kind** -- `make build` in the fork, then `kind build node-image` to get a node image with the shim
3. **Recreate cluster** -- `kind create cluster --config kind/cluster.yaml --image <new-node-image>`
4. **Simulator OAuth server** (Rust code) -- add oauth.rs, rebuild, redeploy
5. **Test end-to-end**

## Verification

1. API server well-known endpoint works:
   ```bash
   kubectl get --raw /.well-known/oauth-authorization-server | jq .
   ```
   Should return the discovery JSON with OAuth URLs.

2. Mock OAuth server responds:
   ```bash
   curl -k https://localhost:9443/oauth/userinfo
   # Should return 401 (no token)
   ```

3. kube-auth-proxy logs show successful OAuth discovery (no more "Please configure --login-url" errors)

4. Browser OAuth flow:
   ```bash
   curl -sv -L -H "Host: rh-ai.apps.ocp-sim.localhost" http://localhost:8080/
   # Should see 302 chain: -> /oauth2/start -> OAuth authorize -> callback -> original page
   ```

5. Token auth regression test:
   ```bash
   TOKEN=$(kubectl create token default)
   curl -H "Authorization: Bearer $TOKEN" -H "Host: rh-ai.apps.ocp-sim.localhost" http://localhost:8080/
   # Should return 202 (unchanged from before)
   ```

## Open Questions / Risks

- **TLS trust**: kube-auth-proxy uses `--ssl-insecure-skip-verify={{.InsecureSkipVerify}}` -- if this is `false`, it will reject our self-signed OAuth cert. Verify the GatewayConfig sets this to `true`, or add the simulator CA to the trusted CA bundle.
- **Port 9443 in OAuth URLs**: Unlike real OCP (port 443 via Route), our mock uses 9443. This is fine for a simulator but means the well-known response differs from production OCP.
- **OAuth callback port**: The OAuthClient has `redirectURIs: [https://rh-ai.apps.ocp-sim.localhost/oauth2/callback]` which uses port 443. The browser needs to reach this. Currently host:8443 maps to node:443. Verify the callback flow works through this port mapping.
