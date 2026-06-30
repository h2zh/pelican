# Pelican / OSDF transfer-failure debugging multitool

`pelican_transfer_debug.py` automates the questions an operator asks by hand when
an object transfer fails somewhere in a Pelican federation (such as the Open
Science Data Federation, OSDF). It probes the connection between the system's
components from several angles, prints a results table, and offers a ranked
diagnosis of **where** the failure most likely lives: the object, its origin /
object store, a specific cache, the network between origin and cache, the token /
authorization, the TLS credentials of a service, or the local client.

In a healthy federation object data flows like:

```
cache miss:  client --> cache --> origin --> object store
cache hit:   client --> cache
```

When that flow breaks, this tool tries the same transfer from different angles to
tell those layers apart.

## Why these probes

Each probe answers one of the questions you would otherwise run by hand. The
table below maps the operator's questions to the probe that answers them.

| Question | Probe id | How it works |
| --- | --- | --- |
| Does the Director know an origin/namespace for this object, and what auth does it require? | `disc.director`, `disc.namespace`, `disc.origin` | Federation discovery + the Director's `/api/v1.0/director/object` and `/origin` endpoints. Reads the `X-Pelican-Namespace`, `X-Pelican-Authorization`, `X-Pelican-Token-Generation`, and `Link` headers. |
| Does my token (JWT) match what the Director thinks is correct authorization? | `token.match` | Decodes the JWT and checks issuer against the Director-advertised issuer(s), expiry/not-before, and that a `storage.read` scope covers the object path relative to the namespace base. |
| Are the TLS credentials of these services working? | `tls.*` | Opens a TLS session to the Director, both caches, and the origin; reports verification, hostname match, and time-to-expiry. |
| Does the object actually fail through the failed cache? (reproduce) | `xfer.failed_cache.object` | `pelican object get --cache <failed-cache>` with no fallback. |
| Can the failed cache pull a **different object store's** object (cache-miss / new-origin discovery)? | `xfer.failed_cache.control` | Same, for the control object. Success here means the cache can discover and network with a fresh origin — implicating the *first* origin. |
| Can the failed cache pull a different object from the **same** origin? | `xfer.failed_cache.backup` | Same, for the backup object. Distinguishes one broken object from an origin-wide problem. |
| Can I read the object **directly from the origin**, bypassing caches? | `xfer.direct.object` | `pelican object get --direct`. Success means origin + object store are healthy; suspect the cache or the origin↔cache network. |
| Can I read a different object directly from the same origin? | `xfer.direct.backup` | `--direct` for the backup object. |
| Can I read the same object through a **different (known-good) cache**? | `xfer.good_cache.object` | `--cache <known-good-cache>`. If this works but the failed cache does not, the fault is that cache. |
| Baseline: can the known-good cache pull the control object? | `xfer.good_cache.control` | Sanity check that the control path itself is sound. |

Transfers are run by shelling out to the real `pelican` (or `osdf`) client so
they exercise exactly the code path you use. Discovery, namespace/authorization,
and TLS introspection are done with direct HTTP/TLS so the tool can read the
structured detail the CLI hides.

> **Cache hit vs. miss.** Forcing a true hit/miss from a client is unreliable, so
> the tool focuses on the more decisive signals (direct-vs-cached, this-cache-vs-
> another-cache, this-origin-vs-another-origin). It reports each transfer's wall
> time, which is a rough hit/miss hint (a fast read of a resident object vs. a
> slow cold fetch). See the hit/miss notes under `--tips` for deeper checks.

## Install / requirements

Python 3 standard library only — no `pip install` required. PyYAML is used if
present, otherwise a small built-in parser handles the flat config. The
transfer probes require the `pelican` (or `osdf`) client on your `PATH`.

## Usage

```bash
# Full run
./pelican_transfer_debug.py -c config.yaml

# Only discovery / TLS / token probes (no client transfers)
./pelican_transfer_debug.py -c config.yaml --no-transfers

# Machine-readable output (for dashboards / further processing)
./pelican_transfer_debug.py -c config.yaml --json

# Just print the extra questions to ask while debugging
./pelican_transfer_debug.py --tips
```

Useful flags: `--timeout` (HTTP/TLS probe timeout), `--transfer-timeout`
(per-transfer timeout), `--tls-port` (default port for services given as a bare
host), `--ca-bundle` / `--insecure` (TLS verification controls), `--no-color`.

## Configuration

See [`config.example.yaml`](./config.example.yaml). Only `object` and
`failed_cache` are required, but the optional fields let the tool triangulate:

| Key | Required | Purpose |
| --- | --- | --- |
| `object` | yes | The object whose transfer failed. |
| `failed_cache` | yes | The cache that was attempted and failed. |
| `federation` | recommended | Discovery host/URL (e.g. `osg-htc.org`) used to find the Director. |
| `control_object` | recommended | An object from a **different** namespace/object store known to work. |
| `known_good_cache` | recommended | A cache known to be operating correctly. |
| `backup_object` | optional | A different object from the **same** namespace/origin. |
| `origin` | optional | Pin a specific origin instead of discovering it via the Director. |
| `token` | optional | JWT file for `object` / `backup_object` (omit for public reads). |
| `control_token` | optional | JWT file for `control_object` if it needs a different token. |
| `binary` | optional | Client binary to drive transfers (`pelican` by default; `osdf` for the OSDF build). |

## How the diagnosis is reached

The diagnosis engine combines probe outcomes into ranked findings. The core
deductions:

- **Failed cache** — the object reads directly from the origin and/or through a
  second cache, but not through the failed cache. If that cache can still pull a
  control object from another origin, suspect the object's cached copy or its
  link to this origin; if it cannot, the cache may be down or isolated.
- **The object** — even a direct origin read of the object fails, yet a
  different object from the same origin succeeds.
- **Origin / object store** — nothing from this namespace reads directly or via
  any cache, while a control object from a different origin works.
- **Origin↔cache network** — the origin serves the object directly and caches
  serve other origins, but no cache serves this object: suspect the path between
  this origin and the caches, a firewall, or missing advertisement.
- **Token / authorization** — the token fails the Director's advertised
  requirements (issuer/scope/expiry), and authenticated reads fail while a
  control read works.
- **Director / discovery** — the Director is unreachable or advertises no origin
  for the object (registration/advertisement issue or wrong path).
- **Local client / network** — every transfer fails, including a control object
  through a known-good cache; the problem is most likely local to your host.

## Additional questions to ask

The tool can only check what it can reach from your debugging host. Run
`./pelican_transfer_debug.py --tips` for a longer checklist covering Director
health and routing, origin/object-store backend state, cache disk/eviction and
JWKS freshness, token `aud`/clock-skew/JWKS reachability, origin↔cache
firewalling, DNS/ingress hops, and reproducibility (intermittent vs.
deterministic, your-site-only vs. federation-wide, `get` vs. `stat`).
