# Design: faster application-list proxy for the native ArgoCD UI

**Date:** 2026-06-14
**Status:** Draft — pending review
**Component:** argocd-proxy

## Goal

Make `GET /api/v1/applications` (served by argocd-proxy from cached data) as fast
as possible for the **native ArgoCD Web UI**, beyond what the current
"read-from-Redis per request + end-to-end zstd" already achieves.

The proxy already bypasses argocd-server's casbin RBAC by scoping via Redis key
prefixes, which is the project's original goal and is proven to work. This design
targets the *next* bottleneck: the per-request work still done on the read path.

## Context & evidence

Benchmarked on k3s, 2000 `Application` CRs, in-cluster `fortio -stdclient -c 8`:

- Optimized proxy (stream raw bytes, no re-marshal): admin list-all **93.7 qps**
  vs argocd-server 29.9 qps; RBAC-restricted 100-app subset **909 qps** vs 173.
- **argocd-server already gzips** the list when the client sends
  `Accept-Encoding: gzip` (5.60 MB → **156 KB** on the wire). The proxy already
  applies **end-to-end zstd**, so wire size is comparable (~160 KB).
- JSON of similar applications compresses ~35:1.

Because the consumer is a **browser over WAN**, real perceived latency is
dominated by (a) wire bytes — already handled by zstd — and (b) per-request
server compute. With wire bytes minimized, the remaining lever is eliminating
per-request compute.

Per request the proxy still does: Redis `SCAN` + `MGET` of N keys → assemble
`{"items":[...]}` → zstd-compress. This design removes all three from the request
path and computes them only when the underlying data changes.

## Non-goals (separate tracks)

- **JWT signature verification / RBAC fidelity.** The proxy currently trusts the
  JWT payload without verifying the signature and implements a subset of
  argocd's RBAC. Important, but a separate correctness/security effort.
- **Field projection.** The native UI depends on full `Application` objects
  across versions, so we keep returning complete (managedFields-trimmed) objects.
- **The live-update stream.** The UI receives live changes via `?watch=true`,
  which is passed through to argocd-server unchanged. Only the initial/refresh
  list load is optimized here.

## Architecture

A **stateful** proxy that holds applications in memory and serves precomputed,
precompressed, ETagged per-scope list responses.

```
        k8s API (Applications)
              │  informer (LIST + WATCH)
              ▼
   ┌─────────────────────────┐
   │ in-memory app store      │  project → []trimmedAppBytes
   │ (indexed: project/ns/cl) │  + global version counter
   └─────────────────────────┘
              │ on change: bump version
              ▼
   ┌─────────────────────────┐
   │ per-scope response cache │  scopeKey → {version, etag, zstdBytes, gzipBytes}
   └─────────────────────────┘
              ▲
   request ───┘ resolve scope → cache hit → write precompressed bytes / 304
   (non-list requests pass through to argocd-server)
```

### Components

1. **In-memory application store.** A controller-runtime / client-go informer
   watches `Application` objects. Each object is stored as **pre-trimmed JSON
   bytes** (managedFields removed, exactly the value shape the proxy returns
   today). Maintained indexes: by `spec.project` (RBAC scoping), and by
   `spec.destination.namespace` and `spec.destination.server`/`name`
   (cluster/namespace filters). Add/Update/Delete handlers mutate the store and
   **bump a monotonic version counter** (and, later, per-project versions for
   finer invalidation).

   This removes Redis from the read path. The existing `argocd-watcher` + Redis
   may be retained for other consumers, but the proxy no longer reads from Redis
   per request. (Alternative if Redis must stay authoritative: the proxy syncs
   its in-memory store from Redis via full load + keyspace notifications instead
   of a k8s informer. The read path is identical either way.)

2. **Per-scope response cache.** Keyed by the request scope:
   `scopeKey = sortedAllowedProjects ‖ namespace ‖ cluster`. Value holds the
   fully-assembled `{"items":[...]}` body, **pre-compressed in both zstd and
   gzip**, an **ETag** (hash of the body), and the store version it was built at.
   Entries are built lazily on first miss and invalidated when the store version
   they were built at is stale.

3. **Request handler.**
   - Non-list or non-GET → pass through to argocd-server (unchanged).
   - List → resolve object patterns from the RBAC ConfigMap (existing
     `parsePolicyCSV` / `resolveObjectPatterns`), compute `scopeKey`.
   - If `If-None-Match` matches the current ETag → **304 Not Modified**, no body.
   - Else select the body variant matching the client's `Accept-Encoding`
     (`zstd` → `gzip` → identity), set `Content-Encoding` + `ETag` + `Vary:
     Accept-Encoding`, and write the precompressed bytes.
   - On cache miss: assemble from the in-memory index, compress (zstd is cheap
     even on-path), store in the cache, then write.

### Data flow

- **Update path** (informer event): mutate store → bump version. Cache entries
  become stale lazily (checked at read time) — no eager recompute, so bursts of
  changes don't thrash compression.
- **Read path** (cache hit, unchanged data): resolve scope → ETag match → 304, or
  → write precompressed bytes. No Redis, no assembly, no compression.

## Compression negotiation

Parse `Accept-Encoding`; serve `zstd` to clients that advertise it (Chrome 123+,
Firefox 126+), `gzip` otherwise (Safari and older), identity if neither. Both
encodings are precompressed and cached so negotiation costs nothing per request.
Always send `Vary: Accept-Encoding`.

## ETag scheme

ETag = strong hash (e.g. FNV/xxhash, hex) of the **uncompressed** assembled body,
computed once when the cache entry is built. Honor `If-None-Match`. This makes the
UI's repeat list loads (refresh, navigation) return empty 304s when nothing
changed — the cheapest possible response.

## Trade-offs

- **Stateful proxy.** Each replica independently watches and holds the full store
  + cache. No shared state needed, so horizontal scaling stays simple. Cost:
  memory (~5 KB/app → 10 MB at 2k apps, ~500 MB at 100k) and a cold-start LIST.
- **Eventual consistency.** The list reflects the store, which lags the API
  server by informer latency (sub-second typically). Acceptable for a list view;
  the live stream handles real-time updates.
- **Coarse invalidation first.** A single global version bumps on any change, so
  every cache entry rebuilds after any change. Fine for moderate change rates;
  per-project versioning is a later refinement if change rate is high.

## Phased implementation

1. **ETag + conditional GET** on the current Redis-backed handler. Smallest
   change, immediate win for UI reloads.
2. **In-memory store + per-scope precompressed cache** (zstd + gzip), informer-fed,
   removing Redis from the read path. The core of this design.
3. **namespace/cluster indexes** so those filters are index lookups instead of
   scanning values.

## Testing strategy

- Unit: scope-key construction; ETag stability/sensitivity; Accept-Encoding
  selection (zstd/gzip/identity); cache invalidation on version bump; envelope
  byte-preservation (extends existing `TestWriteApplicationList`).
- Integration: informer event → store mutation → cache invalidation → next read
  reflects change; `If-None-Match` → 304; concurrent reads during updates.
- Benchmark: re-run the k3s admin + RBAC-restricted scenarios; expect repeat-scope
  requests to drop to near memcpy cost and unchanged-data polls to 304.

## Decisions

1. **Drop Redis from the read path.** The proxy watches `Application` objects
   directly via a k8s informer and owns its in-memory store. Redis is no longer
   read per request. (The existing `argocd-watcher` + Redis can remain for other
   consumers but is not on this proxy's read path.)
2. **Global version invalidation first.** A single monotonic version counter
   bumps on any store change; cache entries rebuild lazily when stale.
   Per-project versioning is a later refinement if the change rate warrants it.
3. **`?watch=true` is out of scope** — passed through to argocd-server unchanged,
   along with all other non-list requests.
