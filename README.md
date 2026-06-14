# argocd-proxy

An **ArgoCD Proxy** that speeds up the ArgoCD list-application API by serving
`GET /api/v1/applications` from an in-process, always-warm cache instead of
letting argocd-server enumerate and RBAC-check every application via casbin. All
other requests are reverse-proxied to argocd-server unchanged.

## Features

- **In-memory application store**: a Kubernetes informer keeps a live mirror of
  `Application` objects (trimmed JSON, indexed by project / destination cluster /
  destination namespace). No external datastore is required.
- **In-memory RBAC filtering**: resolves the caller's allowed object patterns
  from the ArgoCD RBAC ConfigMap and filters the store by project (and optional
  destination cluster/namespace) — dropping
  [casbin](https://github.com/casbin/casbin) from the read path.
- **Per-scope precompressed cache**: the assembled `{"items":[...]}` response is
  cached per RBAC scope, precompressed in **zstd** and **gzip**, and invalidated
  by a store version counter — so repeat requests are served with no
  re-assembly and no per-request compression.
- **Conditional requests**: responses carry an `ETag`; matching `If-None-Match`
  requests get `304 Not Modified` with no body.
- **Content negotiation**: serves `zstd`, `gzip`, or identity based on the
  client's `Accept-Encoding`.

## Use Cases

- **Scalable API performance**: ideal for environments with many applications,
  where argocd-server's per-request RBAC enforcement and serialization become the
  bottleneck.
- **Native ArgoCD Web UI**: a drop-in accelerator for the list endpoint; the
  live-update stream (`?watch=true`) and every non-list request pass through.

## Requirements

- **ArgoCD**: a working ArgoCD setup (the proxy reverse-proxies to argocd-server).
- **Kubernetes**: a cluster where ArgoCD is deployed. The proxy needs a
  ServiceAccount with `get`/`list`/`watch` on `applications.argoproj.io` and
  `get` on the ArgoCD RBAC ConfigMap.
- **Go**: a Go environment for building the proxy.

## Installation

1. Clone this repository:
   ```bash
   git clone git@github.com:hsiaoairplane/argocd-proxy.git
   cd argocd-proxy
   ```

2. Build the proxy:
   ```bash
   go build -o argocd-proxy .
   ```

3. Deploy to Kubernetes:
   - Create a ServiceAccount + (Cluster)Role granting `get,list,watch` on
     `applications.argoproj.io` and `get` on the RBAC ConfigMap.
   - Create a Deployment for the proxy, pointing `--proxy-backend` at
     argocd-server.

   Example deployment:
   ```yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: argocd-proxy
   spec:
     replicas: 1
     selector:
       matchLabels:
         app: argocd-proxy
     template:
       metadata:
         labels:
           app: argocd-proxy
       spec:
         serviceAccountName: argocd-proxy
         containers:
         - name: argocd-proxy
           image: <your-image>
           args:
           - --proxy-backend=http://argocd-server
           - --namespace=argocd
   ```

4. Run the proxy locally for testing (uses your current kubeconfig):
   ```bash
   ./argocd-proxy --proxy-backend=<argocd-server-url> --namespace=argocd
   ```

## Configuration

- **Flags**:
  - `--proxy-backend`: backend URL for the reverse proxy (default `http://localhost:8080`).
  - `--listen-addr`: address the proxy listens on (default `:8081`).
  - `--namespace`: namespace where the ArgoCD RBAC ConfigMap lives and where
    Applications are watched (default `argocd`).
  - `--rbac-configmap`: name of the ArgoCD RBAC ConfigMap (default `argocd-rbac-cm`).
  - `--resync-period`: informer resync period (default `30m`).
