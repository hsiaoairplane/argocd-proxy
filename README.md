# argocd-proxy

An **ArgoCD Proxy** enhances the performance of the ArgoCD list application API by integrating with Redis and performing in-memory RBAC filtering. This significantly improves the efficiency of application queries and reduces latency in large-scale environments.

## Features

- **Redis Cache Integration**: Reads application data from Redis instead of querying Kubernetes Application CRs.
- **In-Memory RBAC Filtering**: Drop the use of the [casbin](https://github.com/casbin/casbin) package but use in-memory filtering instead.
- **Improved Performance**: Optimized for faster response times and reduced resource consumption.
- **Seamless Integration**: Works in conjunction with [argocd-watcher](https://github.com/hsiaoairplane/argocd-watcher) to keep the Redis cache up-to-date.

## Use Cases

- **Scalable API Performance**: Ideal for environments with numerous applications, improving API responsiveness.
- **Real-Time Application Data**: Provides quick access to updated application information through Redis.

## Requirements

- **ArgoCD**: A working ArgoCD setup.
- **Redis**: A running Redis instance to store application data.
- **Kubernetes**: A Kubernetes cluster where ArgoCD is deployed.
- **Go**: Installed Go environment for building and running the proxy.

## Installation

1. Clone this repository:
   ```bash
   git clone git@github.com:hsiaoairplane/argocd-proxy.git
   cd argocd-proxy
   ```

2. Build the proxy:
   ```bash
   go build -o argocd-proxy *.go
   ```

3. Deploy to Kubernetes:
   - Ensure Redis is running and accessible.
   - Configure the proxy to connect to the Redis instance.
   - Create a Kubernetes deployment for the proxy.

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
         containers:
         - name: argocd-proxy
           image: <your-image>
           command: ["argocd-proxy"]
   ```

4. Run the proxy locally for testing:
   ```bash
   ./argocd-proxy --redis-address=<redis-address> --redis-db=<redis-db-index> --proxy-backend=<path-to-the-backend>
   ```

## Configuration

- **Flags**:
  - `--redis-address`: Redis server address.
  - `--redis-db`: Redis DB index.
  - `--proxy-backend`: Proxy backend address.
