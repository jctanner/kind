# OCP Shim: Build & Usage Instructions

## What This Is

The OCP shim makes Kind's API server serve `/.well-known/oauth-authorization-server`, which kube-auth-proxy needs when configured with `--provider=openshift`. It works by inserting a small TLS reverse proxy as a sidecar in the kube-apiserver static pod:

- The real API server moves to port **16443**
- The ocp-shim proxy listens on port **6443** (the original port)
- Requests to `/.well-known/oauth-authorization-server` return OAuth discovery JSON
- All other requests are proxied transparently to the real API server
- Client certificate authentication is preserved via the Kubernetes front-proxy mechanism

This happens automatically during `kind create cluster` — no manual patching required.

## Prerequisites

- Go 1.26+ (check with `go version`)
- Docker or Podman (for building images and running Kind)

## Build Steps

All commands run from the kind repo root (`example.src/kind/`).

### 1. Build the Kind CLI

```bash
make build
```

Produces `./bin/kind`. This binary includes the ocpshim create action.

### 2. Copy ocp-shim source into the build context

The base image Dockerfile expects the ocp-shim source under `images/base/ocp-shim/`. Copy it from the repo root:

```bash
cp -r cmd/ocp-shim images/base/ocp-shim
```

### 3. Build the base image

The base image contains the `ocp-shim` binary along with all other node dependencies (containerd, runc, crictl, CNI plugins).

```bash
docker build --build-arg GO_VERSION=1.26.2 -t kindest/base:ocp-shim ./images/base/
```

This takes several minutes on first build (compiling containerd, runc, etc.). Subsequent builds use Docker layer cache.

### 4. Build the node image

The node image layers Kubernetes binaries on top of the base image. Specify a Kubernetes release version as the first argument:

```bash
./bin/kind build node-image v1.33.1 \
  --type release \
  --base-image kindest/base:ocp-shim \
  --image kindest/node:ocp-shim
```

Or use a local Kubernetes source checkout:

```bash
./bin/kind build node-image /path/to/kubernetes \
  --base-image kindest/base:ocp-shim \
  --image kindest/node:ocp-shim
```

### 5. Create a cluster

With rootless Podman, set the fuse-overlayfs snapshotter (required because overlayfs doesn't work in rootless user namespaces):

```bash
KIND_EXPERIMENTAL_CONTAINERD_SNAPSHOTTER=fuse-overlayfs \
  ./bin/kind create cluster \
  --image localhost/kindest/node:ocp-shim \
  --name ocp-sim
```

With Docker (rootful):

```bash
./bin/kind create cluster \
  --image kindest/node:ocp-shim \
  --name ocp-sim
```

During creation you will see:

```
Creating cluster "ocp-sim" ...
 ✓ Ensuring node image (localhost/kindest/node:ocp-shim) 🖼
 ✓ Preparing nodes 📦
 ✓ Writing configuration 📜
 ✓ Starting control-plane 🕹️
 ✓ Configuring OCP API shim 🔧      <-- the new step
 ✓ Installing CNI 🔌
 ✓ Installing StorageClass 💾
```

**Note on image references**: With Podman, locally built images are prefixed with `localhost/`. Use `localhost/kindest/node:ocp-shim` to avoid Kind trying to pull from Docker Hub.

## Quick Start (rootless Podman)

```bash
make build
cp -r cmd/ocp-shim images/base/ocp-shim
docker build --build-arg GO_VERSION=1.26.2 -t kindest/base:ocp-shim ./images/base/
./bin/kind build node-image v1.33.1 --type release --base-image kindest/base:ocp-shim --image kindest/node:ocp-shim
KIND_EXPERIMENTAL_CONTAINERD_SNAPSHOTTER=fuse-overlayfs ./bin/kind create cluster --image localhost/kindest/node:ocp-shim --name ocp-sim
```

## Verification

### API server well-known endpoint

```bash
kubectl get --raw /.well-known/oauth-authorization-server | jq .
```

Expected output:

```json
{
  "issuer": "https://oauth-openshift.apps.ocp-sim.localhost:9443",
  "authorization_endpoint": "https://oauth-openshift.apps.ocp-sim.localhost:9443/oauth/authorize",
  "token_endpoint": "https://oauth-openshift.apps.ocp-sim.localhost:9443/oauth/token",
  "scopes_supported": ["user:check-access", "user:full", "user:info", "user:list-projects"],
  "response_types_supported": ["code", "token"],
  "grant_types_supported": ["authorization_code", "implicit"],
  "code_challenge_methods_supported": ["plain", "S256"]
}
```

### Normal API operations still work

```bash
kubectl get nodes
kubectl get pods -A
```

### Inspect the patched static pod

```bash
podman exec ocp-sim-control-plane cat /etc/kubernetes/manifests/kube-apiserver.yaml
```

You should see:
- The `kube-apiserver` container with `--secure-port=16443`
- An `ocp-shim` sidecar container listening on port 6443

### Check the shim binary exists

```bash
podman exec ocp-sim-control-plane ls -la /usr/local/bin/ocp-shim
```

### Check shim logs

```bash
podman exec ocp-sim-control-plane crictl logs $(podman exec ocp-sim-control-plane crictl ps --name ocp-shim -q)
```

Expected output:

```
ocp-shim: listening on :6443, proxying to https://localhost:16443
ocp-shim: client certificate verification enabled
ocp-shim: front-proxy client certificate configured
```

## Cleanup

```bash
./bin/kind delete cluster --name ocp-sim
```

## How the Shim Handles Authentication

The shim acts as a Kubernetes [authenticating proxy](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#authenticating-proxy):

1. Accepts incoming TLS connections, optionally with client certificates
2. Verifies client certs against the cluster CA (`/etc/kubernetes/pki/ca.crt`)
3. Extracts the identity (CN → `X-Remote-User`, O → `X-Remote-Group`)
4. Forwards the request to the real API server on port 16443, presenting the `front-proxy-client` certificate
5. The API server trusts `X-Remote-User`/`X-Remote-Group` headers because they come from a client cert in `--requestheader-allowed-names`

This means `kubectl` works normally — client certificate auth passes through transparently.

## Troubleshooting

### Cluster creation hangs at "Starting control-plane"

With rootless Podman, if you see overlayfs mount errors in the kubelet logs, you forgot the snapshotter env var:

```bash
KIND_EXPERIMENTAL_CONTAINERD_SNAPSHOTTER=fuse-overlayfs ./bin/kind create cluster ...
```

### API server doesn't come back after patching

The ocpshim action waits up to ~5 minutes with exponential backoff. If it times out:

```bash
podman exec ocp-sim-control-plane crictl ps -a
podman exec ocp-sim-control-plane journalctl -u kubelet --no-pager | tail -50
```

Common causes:
- Port conflict: something else already bound to 6443 or 16443
- TLS cert issues: check that `/etc/kubernetes/pki/apiserver.crt` and `apiserver.key` exist on the node

### ocp-shim sidecar is crash-looping

The ocp-shim binary lives on the node filesystem, not inside the kube-apiserver container image. It is mounted into the sidecar via a hostPath volume. If it can't be found:

```bash
podman exec ocp-sim-control-plane ls -la /usr/local/bin/ocp-shim
```

If missing, the base image wasn't built correctly. Re-run the build steps.

### well-known endpoint returns 404

The shim is not running. Check:

```bash
podman exec ocp-sim-control-plane crictl ps --name ocp-shim
```

If the container is not running, check its logs:

```bash
podman exec ocp-sim-control-plane crictl logs $(podman exec ocp-sim-control-plane crictl ps -a --name ocp-shim -q)
```

### Kind tries to pull image from Docker Hub

With Podman, locally built images are prefixed `localhost/`. Use:

```bash
--image localhost/kindest/node:ocp-shim
```

## What's Next (Part 2)

The well-known endpoint points to `oauth-openshift.apps.ocp-sim.localhost:9443`. For the full OAuth flow to work, you also need the **mock OAuth server** (Part 2 of the plan) running in the simulator, which handles `/oauth/authorize`, `/oauth/token`, and `/oauth/userinfo`.
