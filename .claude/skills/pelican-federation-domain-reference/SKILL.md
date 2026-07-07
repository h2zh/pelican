---
name: pelican-federation-domain-reference
description: >-
  Load this when you hit unfamiliar Pelican/OSDF jargon or protocol behavior: terms like
  origin, cache, director, registry, namespace, OSDF, Topology, cmsd, pfc/pss, xrdcl-pelican,
  authfile, scitokens.cfg, TPC, JWKS, WLCG/scitokens2 profiles, Lotman, broker; URL questions
  (pelican:// vs osdf:///, "schemeless Pelican URLs must be used with a federation discovery
  URL", /.well-known/pelican-configuration, query params like ?directread or ?pack); token
  errors ("the 'audience' claim is required", wlcg.ver, storage.read:/path, X-Pelican-Token-Generation);
  director redirect mechanics (307 + Link pri=, PROPFIND 207, Want-Digest); geo-sorting;
  the registry key-sign challenge; or broker connection reversal. Contains the full domain
  glossary and protocol reference for this repo, with every claim grounded in source files.
---

# Pelican Federation Domain Reference

The knowledge pack for the concepts and wire protocols this repo implements. Everything below
was verified against the source tree (main@289fd41b, 2026-07-05); file references use
`function-name in path` so you can re-find them after line drift.

## When to use this skill

- You encountered a domain term (origin, director, namespace, cmsd, pfc, authfile, lot,
  broker, TPC, Topology, OA4MP...) and need its precise meaning *in this codebase*.
- You are parsing/producing `pelican://` / `osdf://` URLs, federation discovery documents,
  or Pelican URL query parameters.
- You are creating or validating tokens (wlcg vs scitokens2 profile, scopes, audiences,
  issuer discovery, key rotation) or interpreting `X-Pelican-*` headers.
- You need to know what the Go code actually writes into XRootD's config files
  (xrootd.cfg, authfile, scitokens.cfg) and why.
- You are tracing a client↔director redirect, a geo-sort decision, a registry
  registration handshake, or a broker connection reversal.

**When NOT to use:**
- Debugging a live failure symptom → `pelican-debugging-playbook` (symptom→triage tables).
- WHY a design decision was made, serverAds locking invariants, trust model, launch
  ordering → `pelican-architecture-contract`.
- Config parameter mechanics (`param` API, precedence, add-a-param) → `pelican-config-and-flags`.
- Test idioms and build tags → `pelican-testing-and-qa`.
- XRootD/plugin version pins & build → `pelican-build-and-env`; bump *policy* → `pelican-change-control`.
- Ports, paths, systemd, running servers → `pelican-run-and-operate`.
- Incident history → `pelican-failure-archaeology`.

## 1. Glossary (alphabetical)

| Term | Meaning in this repo |
|---|---|
| **authfile** | XRootD's path-authorization file, consulted only *after* token (scitokens) authorization fails; Pelican generates and merges it in `EmitAuthfile` in xrootd/authorization.go (merge rules in the block comment above `authPrivileges` there). |
| **broker** | Pelican's connection-reversal service letting origins behind NAT/firewalls serve data: the origin long-polls the broker and dials *out* when a peer wants in (package `broker/`; §8). |
| **cache** | A server storing/serving copies of federation objects; implemented as XRootD in proxy-cache mode (pss+pfc, §4) or as the pure-Go `local_cache/`. |
| **CILogon** | The default OIDC provider for web-UI/OAuth logins; defaults point at cilogon.org (`setupOIDCProviderDefaults`-adjacent code in config/parameter_defaults.go, `OIDCProvider` consts in config/oidc_metadata.go). |
| **cmsd** | XRootD's Cluster Management Service daemon. Pelican runs it beside `xrootd` for origins when `Origin.EnableCmsd` is true (default **true**, docs/parameters.yaml) — it serves the *legacy* OSDF/Topology redirection path (`all.manager` → OSDF default `redirector.osgstorage.org:1213`), distinct from director routing. |
| **director** | The routing service: answers object requests with HTTP 307 + ranked `Link` headers pointing at caches/origins (package `director/`; §5, §6). Holds the in-memory `serverAds` cache — locking rules owned by `pelican-architecture-contract`. |
| **fed-in-a-box** | All services in one process for development: `pelican serve --module director,registry,origin,cache` (cmd/fed_serve.go; AGENTS.md "federation in a box"). |
| **federation** | A set of data services (director, registry, origins, caches, optional broker) discovered from a single hostname via `/.well-known/pelican-configuration` (§2). |
| **JWKS** | JSON Web Key Set (RFC 7517): the public-key document used everywhere for token verification; each server exports its keys at `/.well-known/issuer.jwks`, and the registry exports per-namespace JWKS (§3). |
| **lot / Lotman** | A "lot" is a managed allocation of cache storage (quota/lifetime group). LotMan is the C library managing lots; the cache loads `libXrdPurgeLotMan.so` as pfc purge plugin when `Cache.EnableLotman` is true (default false). Scopes `lot.create/read/modify/delete/reclaim` govern its API. |
| **MaxMind / GeoIP** | MaxMind's GeoLite2-City database maps IPs to coordinates for geo-sorting; auto-downloaded using a license key file at `Director.MaxMindKeyFile` (§6). |
| **namespace / prefix** | A federation path prefix (e.g. `/foo/bar`) registered in the registry with its owner's public key; origins export storage into namespaces, and the director matches requests to servers by longest prefix (§6, §7). |
| **OA4MP** | "OAuth for MyProxy" — a Java token issuer Pelican can embed for origins (`Origin.EnableIssuer`, default false): Pelican renders its Tomcat config and proxies to it (package `oa4mp/`). |
| **origin** | A server exporting backend storage (posix, s3, https, globus, xroot, posixv2, ssh) into federation namespaces. Data plane is XRootD for most backends; pure Go (`origin_serve/`) for posixv2/ssh. |
| **OSDF** | Open Science Data Federation — the flagship production Pelican federation (README.md); `osdf://` URLs hard-code its discovery host `osg-htc.org` (§2). |
| **OSG** | The OSG Consortium (formerly Open Science Grid), operator of OSDF and Topology. |
| **pfc** | XRootD's Proxy File Cache plugin (`libXrdPfc.so`) — the disk-caching layer of a Pelican cache; tuned via `pfc.*` directives (§4). |
| **pss** | XRootD's Proxy Storage Service plugin (`libXrdPss.so`) — makes XRootD a proxy for an upstream; in Pelican caches the upstream is the *whole federation* (§4). |
| **SciTokens** | The scitokens.org JWT profile for capability-based storage authorization; `scitokens2` is one of Pelican's two token-creation profiles (§3). scitokens-cpp is the XRootD plugin (`libXrdAccSciTokens.so`) enforcing them on the data path. |
| **scitokens.cfg** | The config file Pelican generates for XRootD's scitokens-cpp plugin: one `[Issuer ...]` section per accepted token issuer (§4). |
| **stash / stashcp** | Legacy OSDF branding: `stash://` is an alias for `osdf://` (pelican_url/parse.go), and a `pelican` binary renamed/prefixed `stashcp` runs in a compat "stashcp mode" (cmd/main_client.go, cmd/object_copy.go). |
| **Topology** | The legacy OSG registration site (`topology.opensciencegrid.org`, `Federation.TopologyUrl` osdf_default). OSDF servers still fetch authfiles from it (§4), and topology-sourced server ads are deprioritized by the director (§6). |
| **TPC** | Third-Party Copy: server-to-server transfer. Pelican implements WLCG *pull-mode*: WebDAV `COPY` to the destination with a `Source` header (§5). |
| **WLCG profile** | The Worldwide LHC Computing Grid's JWT token profile (`wlcg` in this repo): `storage.*` scopes, `wlcg.ver` claim, `https://wlcg.cern.ch/jwt/v1/any` audience (§3). |
| **XRootD** | The C++ data-server framework Pelican wraps: Go generates its config and supervises `xrootd`/`cmsd` daemons; the data protocol is HTTP via `libXrdHttp.so`, not the xroot protocol (§4). |
| **xrdcl-pelican** | C++ XrdCl client plugin (separate repo PelicanPlatform/xrdcl-pelican) that teaches XRootD to resolve `pelican://` URLs via a federation director; loaded by caches for their upstream (§4). Version pins → `pelican-build-and-env`. |
| **xrdhttp-pelican** | C++ XRootD HTTP plugin (`libXrdHttpPelican.so`, repo PelicanPlatform/xrdhttp-pelican) providing a control channel into the running xrootd — used to "transplant" refreshed authfile/scitokens.cfg when Pelican runs unprivileged (§4). |

## 2. URL schemes & federation discovery (`pelican_url/`)

Valid schemes: `pelican`, `osdf`, `stash` (`ValidSchemes` in pelican_url/parse.go).

| Form | Meaning |
|---|---|
| `pelican://<discovery-host>/<path>` | Federation host embedded in URL. Host is REQUIRED. |
| `osdf:///foo/bar` (triple slash) | No host; path is the federation path. Discovery host is hard-coded. |
| `osdf://foo/bar` (double slash) | User forgot a slash; `normalizeOSDFTripleSlash` in parse.go folds the "host" back into the path. Same for `stash://`. |
| `pelican:///foo/bar` | **INVALID** — a pelican URL with no host. `validatePelicanUrl` errors with a "did you mean 'pelican://foo/bar'?" suggestion. |
| `/foo/bar` (schemeless) | Only valid with an explicit discovery URL (client `-f <url>` or `Federation.DiscoveryUrl`); else error "schemeless Pelican URLs must be used with a federation discovery URL" (`Parse` in parse.go). |

HTCondor quirks (handled in `Parse` before scheme validation):
- **Scheme-embedded token names**: `mytoken+osdf://...` is accepted (`IsPelicanScheme` allows any `X+<scheme>` suffix); `GetTokenName`/`stripTokenFromUrl` recovers `mytoken` (everything before the last `+`).
- **Underscore→dot rewrite**: `correctUrlWithUnderscore` rewrites `_`→`.` in the scheme, because HTCondor cannot pass dots there — e.g. scheme `ligo_data` becomes `ligo.data` (see TestCorrectURLWithUnderscore in parse_test.go). Combined: `ligo_data+osdf://...` = "osdf URL, use token named ligo.data".

**Discovery** = `GET https://<host>/.well-known/pelican-configuration` (`DiscoverFederation` in pelican_url/discovery.go). The JSON fields (struct `FederationDiscovery`):

| JSON field | Content |
|---|---|
| `discovery_endpoint` | Canonical federation host URL |
| `director_endpoint` | Director base URL |
| `director_advertise_endpoints` | Optional list, for server-to-director advertising |
| `namespace_registration_endpoint` | Registry base URL |
| `jwks_uri` | Federation public keys |
| `broker_endpoint` | Broker URL (empty if none) |

- For `osdf://`/`stash://`, the discovery host is the package var `OsdfDiscoveryHost = "osg-htc.org"` in discovery.go (2026-07-05). Passing a different `-f` for an osdf URL only logs a warning and uses yours.
- The **director itself** serves `pelican-configuration`, `openid-configuration`, and `issuer.jwks` well-knowns (consts in director/discovery.go) — the federation hostname is usually just the director.
- **Resolution cache**: ttlcache with singleflight-suppressed loader; success TTL **30 min**, failure TTL **5 min** (`StartCache` + `failureTTL` in discovery.go).
- **Retry**: up to 3 attempts with 2 s sleep, only for timeouts. HTTP 4xx → non-retryable `SpecificationError` ("likely typo in discovery URL"); 5xx → retryable `TransferError` (`DiscoverFederation`).

**Query parameters** (`pelican_url/query.go`; client-side validation in `ValidateQueryParams`, director-side in `validateQueryParams` in director/director.go):

| Param | Effect | Value |
|---|---|---|
| `recursive` | Transfer a whole directory tree | valueless (values ignored with warning) |
| `pack` | Pack/unpack a tree as archive | one of `auto`, `tar`, `tar.gz`, `tar.xz`, `zip` (required) |
| `directread` | Director routes to the origin instead of caches (needs origin+namespace `DirectReads` capability) | valueless |
| `skipstat` | Director skips the object-existence stat query before redirecting | valueless |
| `prefercached` | Prefer cached copies; on the origin endpoint enables cache-to-cache chaining when `Director.CachesPullFromCaches` is on (`requiresCacheChaining` in director/director.go) | valueless |

Mutual exclusions (both enforced): `recursive`+`pack`, and `directread`+`prefercached`.

## 3. Token profiles, scopes, and issuers (`token/`, `token_scopes/`)

Two creation profiles (plus `none`): `ParseProfile` in token/token_create.go.

| | `wlcg` | `scitokens2` |
|---|---|---|
| Required claims | `sub`, `aud`, `wlcg.ver` | `aud`, `scope`, `ver` |
| Version claim / pattern | `wlcg.ver` matching `^1\.[0-9]+$` (default `1.0`) | `ver` matching `^scitokens:2\.[0-9]+$` (default `scitokens:2.0`) |
| "Any" audience | `https://wlcg.cern.ch/jwt/v1/any` | literal `ANY` |
| Groups claim | `wlcg.groups` | `groups` |
| Read / Write / Modify scope | `storage.read` / `storage.create` / `storage.modify` | `read` / `write` / `write` |
| Stage scope | `storage.stage` | `write` — **NOTE: the code comment on `Scitokens2Profile.StageScope` says "read" but the implementation returns `Scitokens_Write` (main@289fd41b). Trust the code; flag the comment if you touch it.** |

- **Scope grammar**: the `scope` claim is a space-delimited, case-sensitive string; a scope
  may carry a path suffix after `:`, e.g. `storage.read:/foo`. Only these scopes accept a
  path (`TokenScope.Path` in token_scopes/token_scopes.go): `storage.read`, `storage.create`,
  `storage.modify`, `storage.stage`, `read`, `write`, `share.access`.
- **Scopes are code-generated**: token_scopes/token_scopes.go is produced by
  generate/scope_generator.go from `docs/scopes.yaml` — edit the YAML, then `go generate ./...`
  (checklist owned by `pelican-config-and-flags`/`pelican-docs-and-writing`). Infra scopes
  include `pelican.advertise`, `broker.reverse/retrieve/callback`, `monitoring.scrape/query`,
  `lot.*`, `web_ui.access`, `server.admin`.
- **Issuer discovery**: append `/.well-known/openid-configuration` to the issuer URL
  (`GetIssuerMetadata` in config/issuer_metadata.go).
- **Director token-guidance headers** (parsers in server_structs/director.go):
  - `X-Pelican-Authorization: issuer=<url>[, issuer=<url>...]` — who can issue valid tokens.
  - `X-Pelican-Token-Generation: issuer=<url>, base-path=<path>, max-scope-depth=<int>, strategy=<OAuth2|Vault>` — how to acquire one.
  - The client **rejects `strategy=Vault`**: `AcquireToken` in client/acquire_token.go returns
    "vault credential generation strategy is not supported".
- **Key rotation**: every `.pem` **and `.jwk`** file in the directory given by top-level param
  `IssuerKeysDirectory` (default `${ConfigBase}/issuer-keys`) is loaded; ALL loaded keys verify
  tokens, and the **lowest-lexicographic filename** becomes the active signing key
  (`IssuerKeys.CurrentKey` comment + `loadPrivateKeysFromDirectory` logic in
  config/init_server_creds.go). The legacy `IssuerKey` file (`${ConfigBase}/issuer.jwk`,
  deprecated) is treated as one more member of that directory.
  **Documented discrepancy (2026-07-05): docs/parameters.yaml's `IssuerKeysDirectory` entry
  claims "the most recent modified private key" is active — the code selects by lexicographic
  filename order instead. The code wins.**
- Public halves are served at `/.well-known/issuer.jwks` on each server; the registry serves
  per-namespace JWKS at `/api/v1.0/registry/<prefix>/.well-known/issuer.jwks`
  (`getJwks`-adjacent handling in registry/registry.go).
- Note the param is top-level `IssuerKeysDirectory` (Go: `param.IssuerKeysDirectory`), *not*
  `Server.IssuerKeysDirectory`.

## 4. XRootD as Pelican uses it (`xrootd/`)

Pelican is a **config generator and supervisor** for XRootD. `ConfigXrootd` in
xrootd/xrootd_config.go renders the embedded templates `xrootd/resources/xrootd-origin.cfg`
and `xrootd-cache.cfg` into `<Origin|Cache RunLocation>/xrootd.cfg`, then
`ConfigureLaunchers`/`LaunchDaemons` in xrootd/launch.go exec the daemons.

Key facts (each visible in the templates):
- **HTTP is the data protocol**: `xrd.protocol http:<port> libXrdHttp.so` — Pelican never
  speaks the xroot protocol to clients.
- **Bearer-token bridge**: `http.header2cgi Authorization authz` converts the HTTP
  `Authorization` header into XRootD's `authz` CGI parameter so scitokens-cpp sees it. The
  cache template also bridges `X-Pelican-Timeout` → `pelican.timeout`.
- **cmsd default-on for origins**: `Origin.EnableCmsd` default true renders
  `all.manager {{Xrootd.ManagerHost}}+ {{Xrootd.ManagerPort}}` (OSDF defaults:
  `redirector.osgstorage.org`, port 1213) and launches a `cmsd` daemon next to `xrootd`
  (`ConfigureLaunchers`). This is legacy Topology-era routing, kept for OSDF compatibility.
- **Cache = pss + pfc**: `ofs.osslib libXrdPss.so` + `pss.cachelib libXrdPfc.so`, with
  `pfc.blocksize 128k`, prefetch, and `pfc.diskusage <low> <high>` watermarks. Critically,
  `pss.origin` is set to `pelican://<federation-discovery-host>` (`ensureCachePSSOrigin` in
  xrootd_config.go): the cache's upstream is the **entire federation**, not one origin. That
  URL is resolved inside XRootD by the **xrdcl-pelican** plugin, configured via
  `<RunLocation>/cache-client.plugins.d/pelican-plugin.conf` (`url = pelican://*` →
  `libXrdClPelican.so`; http/https → `libXrdClCurl.so`) and env `XRD_PLUGINCONFDIR`
  (see the plugin-conf constants in xrootd_config.go and env setup in launch.go).
- **Authfile merge rules** (block comment above `authPrivileges` in xrootd/authorization.go):
  the admin's authfile is merged with Pelican-generated entries; on conflict, an **origin
  keeps the admin's policy** (admins may override), a **cache keeps the generated policy**
  (caches MUST respect federation-discovered policy; a warning is logged). In OSDF mode,
  authfile content is additionally fetched from Topology
  (`getOSDFAuthFiles`, URL `<Federation.TopologyUrl>/<cache|origin>/Authfile?fqdn=...`),
  disabled per type by `Topology.DisableOriginX509`/`Topology.DisableCacheX509`.
- **scitokens.cfg** is rendered from `xrootd/resources/scitokens.cfg`: per-issuer
  `[Issuer <name>]` sections with `issuer`, `base_path`, and optional `restricted_path`,
  `map_subject`, `default_user`, `name_mapfile`, `username_claim`, `required_authorization`,
  `acceptable_authorization`. Pelican injects **synthetic issuers** for origins
  (`WriteOriginScitokensConfig` in authorization.go):
  1. `Built-in Monitoring` — only when `Origin.SelfTest`; issuer = the origin's own
     `Server.ExternalWebUrl`, base path `/pelican/monitoring` (`GenerateMonitoringIssuer`).
  2. `Federation-based Monitoring` — issuer = the **federation discovery endpoint**, base
     path `/pelican/monitoring` (`GenerateDirectorMonitoringIssuer`). This is what makes
     director-signed test tokens pass on the data path.
  3. `Federation` — **only when `Origin.DisableDirectClients=true`** (hidden param, default
     false): issuer = discovery endpoint over all export prefixes, so cache-forwarded
     federation tokens are accepted (`GenerateFederationIssuer`).
- **Unprivileged "transplant" path**: with `Server.DropPrivileges`, post-startup rewrites of
  authfile/scitokens.cfg cannot chown files, so they are copied into an xrootd-owned
  directory through the **xrdhttp-pelican** plugin's command API
  (`FileCopyToXrootdDir(..., 7, ...)` in `writeScitokensConfiguration`/`writeAuthfile`,
  env `XRDHTTP_PELICAN_SCITOKENS_GENERATED` in launch.go).
- Pelican pre-sets SQLite WAL mode for scitokens-cpp's cache DB (`enableSqliteWAL` in
  xrootd_config.go) to avoid locking stalls inside xrootd worker threads.

## 5. The director's HTTP dialect (client ↔ director ↔ servers)

Reference tables distilled from docs/pelican-http-headers.md and verified in code.

**Redirect mechanics** (`queryDirector` + `ParseDirectorInfo` in client/director.go):
- The client sends the object path to the director with a **no-redirect** HTTP client and
  reads headers itself. Success = **307** (`http.StatusTemporaryRedirect`).
- Servers are listed in metalink-style `Link` headers:
  `Link: <https://cache1:8443/path>; rel="duplicate"; pri=1, <https://cache2...>; pri=2` —
  the client parses `pri=` and sorts ascending (`parseServersFromDirectorResponse`).
- **Location fallback**: if no `Link` headers, a bare `Location` header becomes the sole
  object server (health-test redirects do this).
- **Verb routing** (`ShortcutMiddleware` in director/director.go): GET/HEAD → caches
  (default), `PUT`/`DELETE`/`COPY` → rewritten to `/api/v1.0/director/origin/<path>` and
  redirected to origins. `?directread` on a GET also forces origin routing.
- `/api/v1.0/director/origin/<path>` is the explicit "give me origins" endpoint — the client
  uses it directly in embedded-cache mode (`cacheMode` in `queryDirector`), and launchers
  poll it (with `?skipstat`) to confirm an origin is advertised.
- **PROPFIND is proxied, not redirected**: directors >7.9 answer PROPFIND (WebDAV listing)
  themselves with **207 Multi-Status**; the client treats 207 as terminal
  (comment in `queryDirector`). PROPFIND with `Depth: 0` = stat, else = listing.
- **Retries**: `Client.DirectorRetries` (default 5, 2026-07-05). The client retries on
  404/500/502 responses *not* bearing a `Server: pelican/...` header (assumed ingress proxy
  fronting a rebooting director) and on Pelican **429** (director rebooted, still
  repopulating server ads), with `3*(n+1)`s + jitter backoff (`queryDirector`, `fromPelican`).

**X-Pelican-\* headers** (parsers in server_structs/director.go; doc: docs/pelican-http-headers.md):

| Header | Direction | Format / semantics |
|---|---|---|
| `X-Pelican-Timeout` | client → server | Go duration (`9.5s`); query param `?pelican.timeout=` takes precedence |
| `X-Pelican-JobId` | both | UUID for request tracing; director generates one if absent |
| `X-Pelican-Debug` | client → director | `true` → director includes redirect-decision JSON in the 307 body |
| `X-Pelican-Coordinate` | client → director | `lat=<f>,long=<f>` self-declared location (from `GeoLocation` param) |
| `X-Pelican-Namespace` | director → client | `namespace=/foo, require-token=true[, collections-url=<url>]` |
| `X-Pelican-Authorization` | director → client | `issuer=<url>[, issuer=<url>]` |
| `X-Pelican-Token-Generation` | director → client | `issuer=..., base-path=..., max-scope-depth=N, strategy=OAuth2\|Vault` |
| `X-Pelican-Broker` | director → client | broker URL for the origin (only when origin advertises one) |
| `X-Transfer-Status: true` + `TE: trailers` | client → cache/origin | requests an `X-Transfer-Status` **HTTP trailer** `"<code>: <text>"` (e.g. `500: unexpected EOF`) so errors surface after the body started streaming |

**Checksums**: RFC 3230. Client sends `Want-Digest` on a HEAD and parses `Digest` response
headers (`fetchChecksum`-adjacent code near `ChecksumFromHttpDigest` in client/handle_http.go).
Client algorithms: `crc32c` (default), `md5`, `crc32`, `sha` (SHA-1). Origins advertise
computed types via `Origin.SupportedChecksumTypes` (md5, sha1, crc32, crc32c).

**Ranges**: `client.WithByteRange(start, end)` → standard `Range` header for partial reads.

**TPC**: WLCG *pull-mode* third-party copy — `copyHTTP` in client/handle_http_copy.go issues
a WebDAV `COPY` to the **destination** with a `Source` header naming the source URL; success
is **201**. A 200 means the destination xrootd lacks the TPC module (`libXrdHttpTPC.so`,
loaded when TPC is enabled — i.e. `Origin.DisableCopies` is false AND some export declares the
`Copies` capability; see `shouldEnableTPC` in `xrootd/xrootd_config.go`). Note `Origin.EnableTPC`
is a *derived* internal xrootd-config field, NOT a settable configuration parameter.

## 6. Geo-aware redirection (director sorting)

- **Database**: MaxMind GeoLite2-City, auto-downloaded from download.maxmind.com using the
  license key file at `Director.MaxMindKeyFile` (`downloadDB` in director/maxmind.go;
  extraction capped at 512 MB). Without a key, GeoIP is unavailable (director still runs).
- **Sort methods** (`Director.CacheSortMethod`, default `"distance"`; dispatch in
  `sortServerAds` in director/sort.go):
  - `distance` — spherical distance client↔server.
  - `distanceAndLoad` — **currently a placeholder that runs plain `DistanceSort`** (both the
    switch in sort.go and parameters.yaml say so, 2026-07-05).
  - `random` — random order.
  - `adaptive` — stochastic weights (distance + IO load + status + availability).
  - On sort error, fallback chain: current → `distance` → `random`.
- **THE random-US-coordinate fallback**: if the client IP cannot be resolved (and no
  override applies), the director assigns a random coordinate inside a contiguous-US
  bounding box — lat 30–50, long -125 to -65 (`assignRandBoundedCoord` + `usLatMin...` consts
  in director/sort_utilities.go) — cached **20 min** per IP in `clientIpRandAssignmentCache`
  (capacity 10,000, no touch-on-hit). Consequence: the first distance sort for such a client
  is effectively random, but stable for the next 20 minutes. `GeoIPOverrides` (config) pins
  IPs/CIDRs to fixed coordinates and takes precedence.
- **Result size**: only the top **6** servers are returned (`sourceServerAdsLimit` in sort.go).
- **Namespace matching**: longest-prefix match of the request path against namespace ads
  (`getLongestNSMatch`); trailing-slash normalization prevents `/foo` matching `/foobar`.
- **Topology deprioritization**: ads sourced from OSG Topology are moved to the end
  (`sortServerAdsByTopo` called in `getAdsForPath`), and a Pelican origin replaces a
  topology origin for the same prefix.

serverAds data-structure invariants (snapshot-only iteration etc.) → `pelican-architecture-contract`.

## 7. Registry key-sign challenge (namespace registration)

Registration proves possession of a private key — there are no user accounts in the loop.
Endpoint: `POST /api/v1.0/registry` (`cliRegisterNamespace` → `keySignChallenge` in
registry/registry.go). Two rounds, distinguished by which fields are present in the payload:

1. **Init** (client sends only `client_nonce`): `keySignChallengeInit` generates a
   `server_nonce`, builds `server_payload = client_nonce + server_nonce`, signs it with the
   registry's own key, and returns `{server_nonce, client_nonce, server_payload,
   server_signature}`.
2. **Commit** (client sends all six challenge fields + its pubkey JWKS + prefix):
   `keySignChallengeCommit` verifies **both** ECDSA signatures — the client's signature over
   `client_nonce + server_nonce` against the submitted pubkey, and the registry's own
   signature over `server_payload` (proving the challenge is one it issued) — then validates
   the prefix and creates the registration, storing the pubkey JWKS.

Additional gates during commit:
- **Reserved server prefixes**: origins/caches register their *identity* under
  `/origins/<host>` and `/caches/<host>` (`OriginPrefix`/`CachePrefix` consts in
  server_structs/xrootd_server.go). For these, a duplicate **site name** triggers
  `verifyServerOwnership`: the request's signature must verify against the already-registered
  server's keyset.
- **Key chaining** (`validateKeyChaining` in registry/registry_validation.go; gated by
  `Registry.RequireKeyChaining`, default true): registering `/foo/bar/baz` when `/foo/bar`
  exists (or `/foo` when `/foo/bar` exists) requires the incoming key to match a key already
  registered to the super/subspace. Skipped entirely for `/origins/...` and `/caches/...`.
- **Topology collision**: prefixes overlapping OSDF Topology namespaces are flagged for
  admin review rather than auto-approved.

The registry is the federation trust root; the director only trusts server keys via the
registry (details → `pelican-architecture-contract`).

## 8. Broker connection reversal (text sequence diagram)

Purpose: let an **origin behind NAT/firewall** serve data with zero inbound connectivity.
The broker usually runs inside the director process (`Director.EnableBroker`, default true).
The director advertises it to clients via `X-Pelican-Broker`; discovery JSON carries
`broker_endpoint`.

Actors: **Origin** (hidden service), **Requester** (a cache — or the director itself via
`BrokerDialer` in broker/dialer.go), **Broker**.

```
Origin                        Broker                         Requester
  |-- POST /api/v1.0/broker/retrieve  (long-poll, token scope broker.retrieve) -->|
  |                              |<-- POST /api/v1.0/broker/reverse --------------|
  |                              |    {request_id, private_key (one-time ECDSA),  |
  |                              |     callback_url = <requester>/api/v1.0/broker/callback,
  |                              |     origin, prefix}   (scope broker.reverse)   |
  |<-- long-poll answers with that reversalRequest --|                            |
  |                                                                               |
  |-- dials OUT: POST <callback_url> {request_id} (scope broker.callback,         |
  |   HTTP/1.1 forced — HTTP/2 cannot be hijacked) ----------------------------->|
  |                          Requester hijacks the server-side TCP socket of that |
  |                          inbound POST and replies with a ~10-min host cert:   |
  |                          the one-time public key signed by the requester's    |
  |                          local CA (Server.TLSCACertificateFile / TLSCAKey)    |
  |<------------------------------------------------------------------------------|
  |  Origin steals its outbound TCP socket (hijackConn), wraps it in a one-shot   |
  |  listener, and acts as TLS **server** using the one-time key + received cert. |
  |  Requester does a TLS **client** handshake over the hijacked socket, trusting |
  |  its own CA.  ==> TLS direction is REVERSED relative to TCP dial direction.   |
```

Code anchors: `retrieveRequest`/`reverseRequest`/`handleCallback` +
`RegisterBroker`/`RegisterBrokerCallback` in broker/server_apis.go;
`ConnectToService` (requester side: one-time key, reverse POST, hijack, cert minting) and
`doCallback` + `hijackConn` (origin side) in broker/client.go; queue plumbing in
broker/request_manager.go. Scopes: `broker.retrieve` (origin poll), `broker.reverse`
(requester), `broker.callback` (origin's dial-out). The one-time private key transits
through the broker inside the reversal request — the broker is trusted with it by design.
`BrokerDialer` drops in as a `net.Dialer` replacement so HTTP stacks use reversed
connections transparently.

## Provenance and maintenance

All facts verified 2026-07-05 against `main@289fd41b` by reading source and running the
listed commands (read-only; no live federation was contacted). Wire formats documented here
(discovery JSON fields, X-Pelican-* headers, scope strings, challenge payload fields) are
**frozen ABI** — add fields, never rename (policy → `pelican-change-control`).

Re-verification one-liners for volatile facts (run from repo root):

| Fact | Re-verify with |
|---|---|
| Valid schemes & discovery path | `grep -n 'OsdfScheme\|PelicanDiscoveryPath' pelican_url/parse.go` |
| OSDF discovery host `osg-htc.org` | `grep -n 'OsdfDiscoveryHost' pelican_url/discovery.go` |
| 30 min / 5 min discovery TTLs | `grep -n 'failureTTL\|30\*time.Minute' pelican_url/discovery.go` |
| Query params + exclusions | `grep -n 'Query\|Cannot have both' pelican_url/query.go` |
| Discovery JSON field names | `grep -n 'json:' pelican_url/discovery.go \| head` |
| wlcg/scitokens2 required claims & "any" audiences | `grep -n 'wlcgAny\|scitokensAny\|required fields' token/token_create.go` |
| Stage→write mapping (comment says read) | `sed -n '/Scitokens2Profile) StageScope/,/^}/p' token/token_create.go` |
| Path-bearing scopes | `sed -n '/func (s TokenScope) Path/,/^}/p' token_scopes/token_scopes.go` |
| Scopes generated from docs/scopes.yaml | `head -2 token_scopes/token_scopes.go` |
| Vault strategy rejected | `grep -n 'vault credential generation' client/acquire_token.go` |
| Signing key = lowest lexicographic filename | `sed -n '/CurrentKey/,+3p' config/init_server_creds.go` (compare with `grep -n 'recent modified' docs/parameters.yaml`) |
| `IssuerKeysDirectory` default | `grep -n 'name: IssuerKeysDirectory' -A8 docs/parameters.yaml` |
| `http.header2cgi`, `xrd.protocol http` | `grep -n 'header2cgi\|xrd.protocol' xrootd/resources/xrootd-*.cfg` |
| `Origin.EnableCmsd` default true | `grep -n 'name: Origin.EnableCmsd' -A6 docs/parameters.yaml` |
| cmsd manager OSDF defaults | `grep -n 'name: Xrootd.ManagerHost' -A7 docs/parameters.yaml` |
| pss.origin = pelican://\<federation\> | `sed -n '/func ensureCachePSSOrigin/,+30p' xrootd/xrootd_config.go` |
| xrdcl-pelican plugin conf | `grep -n 'libXrdClPelican\|XRD_PLUGINCONFDIR' xrootd/xrootd_config.go xrootd/launch.go` |
| Authfile merge rules | `sed -n '/Rules for parsing\/merging authfiles/,/explicit in the authfile/p' xrootd/authorization.go` |
| Synthetic scitokens issuers (incl. DisableDirectClients gate) | `grep -n 'func Generate.*Issuer' xrootd/authorization.go` |
| Transplant via xrdhttp-pelican | `grep -n 'FileCopyToXrootdDir\|xrdhttp-pelican' xrootd/authorization.go` |
| 307 + Link `pri=` + Location fallback | `grep -n 'pri\|Location' client/director.go \| head` |
| PROPFIND 207 proxying | `grep -n 'StatusMultiStatus' client/director.go` |
| PUT/DELETE/COPY → origin routing | `sed -n '/func ShortcutMiddleware/,+30p' director/director.go` |
| `Client.DirectorRetries` default 5 | `grep -n 'name: Client.DirectorRetries' -A9 docs/parameters.yaml` |
| Header semantics | `less docs/pelican-http-headers.md`; parsers: `grep -n 'XPelican.*HeaderName' server_structs/director.go` |
| Checksum algs, TPC COPY+Source | `grep -n 'ChecksumFromHttpDigest' client/handle_http.go; grep -n 'Source\|COPY' client/handle_http_copy.go \| head` |
| Sort methods; distanceAndLoad placeholder | `sed -n '/switch sortMethod/,+14p' director/sort.go` |
| Random-US fallback box + 20 min cache | `grep -n 'usLatMin\|20\*time.Minute\|20 \* time.Minute' director/sort_utilities.go` |
| Top-6 limit | `grep -n 'sourceServerAdsLimit' director/sort.go` |
| MaxMind download + key file | `grep -n 'maxMindURL\|MaxMindKeyFile' director/maxmind.go` |
| Key-sign challenge rounds | `sed -n '/func keySignChallenge(/,+20p' registry/registry.go` |
| Reserved /origins/ /caches/ prefixes | `grep -n 'OriginPrefix\|CachePrefix' server_structs/xrootd_server.go \| head -4` |
| Key chaining default true | `grep -n 'name: Registry.RequireKeyChaining' -A8 docs/parameters.yaml` |
| Broker routes + scopes | `grep -n 'api/v1.0/broker\|Broker_' broker/server_apis.go broker/client.go \| head` |
| One-time key + CA-signed 10-min cert | `sed -n '/func ConnectToService/,+130p' broker/client.go \| grep -n 'generatePrivateKey\|NotAfter\|caPrivateKey'` |
| `Director.EnableBroker` default true | `grep -n 'name: Director.EnableBroker' -A6 docs/parameters.yaml` |

Not executed (no live services touched): actual discovery GETs, MaxMind downloads, broker
reversals, registry registrations — all behavior above is derived from code reading, with
struct/parser code cross-checked against unit tests (client/director_test.go,
pelican_url/parse_test.go, server_structs/director_test.go).
