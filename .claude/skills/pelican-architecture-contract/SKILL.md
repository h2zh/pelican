---
name: pelican-architecture-contract
description: Load before changing Pelican server code, reviewing a PR that touches director/, launchers/, server_structs/, param/, config/, or registry/, or when you see symptoms like "director OOM", "deadlock in serverAds", "config value is empty", "ad expired / server disappeared from redirects", "renamed JSON field broke old caches", or "metrics cardinality exploded". Contains the actor map (which component talks to which, XRootD-vs-Go data-plane matrix), the registry-rooted trust model and advertisement lifecycle with exact intervals/TTLs, the numbered architectural invariants (I-1..I-10) every change must preserve, and the known-weak points with code anchors.
---

# Pelican Architecture Contract

The load-bearing design decisions of the Pelican repo, stated as testable invariants.
Facts verified 2026-07-05 against `main` @ `289fd41b`. All paths are repo-relative.

## When to use this skill

- You are about to modify anything under `director/`, `launchers/`, `server_structs/`,
  `param/`, `config/`, `registry/`, or `launcher_utils/`.
- You are reviewing a diff and need to check it against the invariants (section C).
- You need to know which component serves data (XRootD child process vs pure Go).
- You are debugging "server not in director redirects", "ad rejected", "advertisement
  token verification failed", or "namespace not approved".
- You are considering renaming a JSON field, a Prometheus metric, or an API route.
- You need the trust chain: who signs what, who verifies against whose keys.

**When NOT to use** (route to the sibling skill by name):

- Full incident narratives (what broke, when, which PR) → `pelican-failure-archaeology`
- Symptom-to-triage tables and discriminating experiments → `pelican-debugging-playbook`
- Param/viper mechanics in depth, precedence edge cases, add-a-param checklist → `pelican-config-and-flags`
- Test idioms (`ResetTestState`, `NewFedTest`, build tags) → `pelican-testing-and-qa`
- Race-proof recipes and shutdown-leak hunting → `pelican-concurrency-and-shutdown-proofs`
- Ports, filesystem layout, systemd, ops CLI → `pelican-run-and-operate`
- Jargon (token profiles, URL schemes, XRootD concepts) → `pelican-federation-domain-reference`
- The director-at-scale improvement campaign → `pelican-director-reliability-campaign`

---

## A. Actor map

Pelican is one Go binary. `pelican serve --module director,registry,origin,cache`
(`fedServeStart` in `cmd/fed_serve.go`) builds a `server_structs.ServerType` bitmask and
calls `LaunchModules` in `launchers/launcher.go`, which composes all requested services
onto **one gin engine, one TCP port, one shared viper config, one embedded Prometheus**
(guarded by `oncePrometheus`). Any two modules in one process share global state.

| Actor | Package(s) | Role | Talks to |
|---|---|---|---|
| Director | `director/` | Routes clients: HTTP 307 + `Link` headers ranking servers | Clients (redirects), origins/caches (receives ads, health-tests, stats), registry (approval + JWKS), other directors (HA ads) |
| Registry | `registry/` | Namespace ownership DB (SQLite/GORM); stores public keys | Origins/caches (key-sign challenge), director (JWKS + approval queries) |
| Origin | `origin/`, `origin_serve/`, `server_utils/origin*.go` | Exports backend storage into federation namespaces | Director (ads + heartbeats), clients/caches (data), broker (reverse conns) |
| Cache | `cache/` | Stores/serves copies; pulls from origins on miss | Director (ads + fed-token fetch), origins (upstream reads), clients (data) |
| Broker | `broker/` | Connection reversal for origins/caches behind NAT/firewalls | Origins long-poll `POST /api/v1.0/broker/retrieve`; requesters `POST .../reverse`; origin dials **out** to a callback (`RegisterBroker` in `broker/server_apis.go`, `ConnectToService` in `broker/client.go`) |
| Client | `client/`, `pelican_url/` | CLI + library; discovers federation, follows director | Discovery host (`/.well-known/pelican-configuration`, `pelican_url/parse.go`), director, caches/origins |
| Local cache | `local_cache/` | Pure-Go per-node cache over a Unix socket (`LocalCache.Socket`, default `${LocalCache.RunLocation}/cache.sock`) | Director/origins upstream; local clients via socket (`LaunchListener` in `local_cache/persistent_cache_api.go`) |
| Client agent | `client_agent/` | REST API over a Unix socket exposing client transfers as async jobs; own SQLite store + migrations; `pelican client-agent start`, `pelican job ...` (`cmd/client_agent_helpers.go`) | Local callers via socket; federation via the embedded client |

Notes that surprise newcomers:

- A director with `Director.EnableBroker` (default **true**) auto-enables the broker
  module in-process (`LaunchModules`, `launchers/launcher.go`) and dials other services
  through a `BrokerDialer` (`broker/dialer.go`).
- Directors advertise **to each other**: `POST /api/v1.0/director/registerDirector` plus
  `LaunchPeriodicAdvertise` in `director/director_advertise.go` (scope
  `pelican.director_advertise`, `docs/scopes.yaml`). This is the HA-director plane.
- The director returns at most 6 servers per redirect (`serverResLimit = 6`,
  `director/director.go`).

### Data-plane decision matrix (who actually serves bytes)

Decided by `useXRootD` in `OriginServe` / `OriginServeFinish`
(`launchers/origin_serve.go`): `useXRootD := storageType != "posixv2" && storageType != "ssh"`.

| Component + config | Data plane | Where |
|---|---|---|
| Origin, `Origin.StorageType` = `posix`, `s3`, `https`, `globus`, `xroot` | **XRootD child process** (Go generates config + supervises: `ConfigXrootd` in `xrootd/xrootd_config.go`, `LaunchDaemons` in `xrootd/launch.go`) | `xrootd/` |
| Origin, `Origin.StorageType` = `posixv2` or `ssh` | **Pure Go** — webdav-based handlers on the shared gin engine (`RegisterHandlers` in `origin_serve/handlers.go`; `origin_serve/backend.go` wraps `golang.org/x/net/webdav`); `ssh` additionally boots `ssh_posixv2/` (remote helper via SSH/broker) | `origin_serve/`, `ssh_posixv2/` |
| Cache, `Cache.EnableV2` = false (default) | **XRootD** in proxy-cache mode (pfc/pss); upstream is `pss.origin = pelican://<federation>` — the whole federation via the xrdcl-pelican plugin, not one origin | `cache/`, `xrootd/` |
| Cache, `Cache.EnableV2` = true | **Pure Go** persistent cache (BadgerDB; "experimental" per `docs/parameters.yaml`) — `CacheServe` in `launchers/cache_serve.go` | `local_cache/` |
| LocalCache module; client; client agent | Always pure Go | `local_cache/`, `client/`, `client_agent/` |

Consequence: "the data path is XRootD" is only true for the left column. Token
enforcement for XRootD paths happens inside XRootD's scitokens plugin from
Go-generated `scitokens.cfg`; for pure-Go paths it happens in Go. Details:
`pelican-federation-domain-reference`.

---

## B. Trust model and advertisement lifecycle

### The registry is the trust root

1. **Registration = proof of key possession.** A namespace (or a server identity under
   the reserved prefixes `/origins/<sitename>`, `/caches/<sitename>`) is claimed via a
   two-round nonce **key-sign challenge**: client nonce → registry returns its nonce +
   signature over both → client signs `clientNonce+serverNonce` → registry verifies both
   ECDSA signatures before creating the prefix and storing the public key
   (`keySignChallengeInit` / `keySignChallengeCommit` in `registry/registry.go`).
   No accounts; the key IS the identity.
2. **Registry serves per-namespace JWKS** at
   `/api/v1.0/registry/<prefix>/.well-known/issuer.jwks` (and an
   `openid-configuration` next to it) — `wildcardHandler` in `registry/registry.go`.
3. **Origins/caches self-sign their ads.** Each advertisement `POST` to the director
   (`/api/v1.0/director/registerOrigin` or `/registerCache`, routes in
   `director/director.go`) carries a WLCG JWT with **1-minute lifetime** and scope
   `pelican.advertise`, signed by the server's own issuer key
   (`GetAdvertisementTok` in `server_utils/server_utils.go`).
4. **The director verifies ads ONLY via the registry** — `verifyAdvertiseToken` in
   `director/origin_api.go`: (a) namespace issuer URL is the registry's
   `/api/v1.0/registry/<prefix>` endpoint (`GetNSIssuerURL` in
   `utils/registry_jwks/`); (b) `POST /api/v1.0/registry/checkNamespaceStatus`
   must return approved; (c) JWKS fetched via that issuer's openid-configuration and
   cached in the `namespaceKeys` ttlcache with TTL = `Director.AdvertisementTTL`;
   (d) signature verified against that keyset; (e) `pelican.advertise` scope required.
5. **Federation tokens: the director mints on behalf of the federation.** Caches call
   `GET /api/v1.0/director/getFedToken` (route in `director/director.go`); the director
   re-verifies the cache's advertise token, then `createFedTok`
   (`director/fed_token.go`) mints a WLCG token with issuer = the federation
   **discovery endpoint**, lifetime `Director.FedTokenLifetime` (default 15m), audience
   `ANY`, and `storage.read:<prefix>` scopes restricted to the prefixes the registry
   allows that cache. Origins accept these because Go injects a "Federation" issuer
   (the discovery endpoint) into the XRootD scitokens config
   (`xrootd/authorization.go`).

### Advertisement lifecycle — the exact numbers

| Quantity | Value | Where |
|---|---|---|
| Re-advertise interval | `Server.AdvertisementInterval`, default **1m** (hidden param) | `docs/parameters.yaml`; loop in `LaunchPeriodicAdvertise`, `launcher_utils/advertise.go` |
| Auto-clamp | interval forced down to **`Server.AdLifetime`/3** if larger (log warning) | `LaunchPeriodicAdvertise` in `launcher_utils/advertise.go`; same clamp for director-to-director ads in `director/director_advertise.go` |
| Ad lifetime | `Server.AdLifetime`, default **10m** (hidden); each ad's `expiry` = now + lifetime (15m fallback when config uninitialized, i.e. some unit tests) | `ServerBaseAd.Initialize` in `server_structs/director.go` |
| Director-side TTL | serverAds entry TTL = the ad's own `Expiration` if set, else `Director.AdvertisementTTL` default **15m** (plus a hardcoded 15m guard for zero-config tests) | `recordAd` in `director/cache_ads.go`; param in `docs/parameters.yaml` |
| JWKS cache at director | `namespaceKeys` TTL = `Director.AdvertisementTTL` (15m) | `verifyAdvertiseToken` in `director/origin_api.go` |
| Fed token lifetime | `Director.FedTokenLifetime`, default **15m** | `docs/parameters.yaml` |
| Advertise token lifetime | **1 minute**, hardcoded | `GetAdvertisementTok` in `server_utils/server_utils.go` |

**Dropout is silent at default log level.** Miss enough heartbeats and the ttlcache
entry expires; the eviction handler (`LaunchTTLCache` in `director/director_api.go`)
logs only at **Debug**, while the server default level is **info**
(`docs/parameters.yaml`, `Logging.Level` → `server_default: info`). The observable
signals are: the server vanishes from redirects, and the
`pelican_director_server_count` gauge decrements (`hookServerAdsCache` in
`director/director_api.go`). Each ad also carries a `now` field so the director can
detect clock skew between itself and the advertiser (`OriginAdvertiseV2` in
`server_structs/director.go`) — relevant to the JWT clock-skew incident class
(story: `pelican-failure-archaeology`).

---

## C. Invariants

Format: statement → why → evidence anchor → violating-change smell → incident.
Break one of these and you recreate a documented production failure.

### I-1. Never `Range` over `serverAds`; iterate a snapshot via `getServerAdsSnapshot()`

- **Why:** ttlcache's `Range` releases/re-acquires the cache's internal read lock per
  element and **leaks the lock if an entry is evicted or deleted mid-walk** — routine
  under registration churn + TTL expiry. One leaked reader wedges the write-preferring
  RWMutex; every reader and writer on the cache then blocks; goroutines pile up until
  the director is OOM-killed.
- **Evidence:** doc comments on the `serverAds` declaration and on
  `getServerAdsSnapshot` in `director/cache_ads.go` ("Do not use Range"); fix commit
  `eca4f46c` on main. `Items()` is the atomically-locked primitive; use it directly
  only when you need keys or Item wrappers.
- **Smell:** any new `.Range(` on `serverAds` (or on any ttlcache — see weak point W-8);
  a "performance" PR replacing the snapshot copy with in-place iteration.
- **Incident:** director OOM under registration churn, 2026 → `pelican-failure-archaeology`.

### I-2. Never hold `filteredServersMutex` across a `serverAds` access

- **Why:** the two subsystems have independent locks; nesting them creates an ABBA
  deadlock hazard and lets a serverAds stall propagate into the downtime/registration
  path (that propagation is what escalated the I-1 leak into an OOM).
- **Evidence:** comment in `updateDowntimeFromRegistry`, `director/cache_ads.go`:
  "Snapshot serverAds before locking filteredServersMutex... never hold
  filteredServersMutex across a serverAds access".
- **Smell:** a `serverAds.` call textually between `filteredServersMutex.Lock()` and its
  `Unlock()`; a helper taking the mutex then calling into ad-reading code.

### I-3. One `filteredServersMutex` deliberately guards four maps

- **Why:** `filteredServers`, `serverDowntimes`, `topologyDowntimes`,
  `federationDowntimes` are updated together as one consistent downtime view;
  per-map locks would allow readers to see torn state and would multiply lock-ordering
  hazards with I-2.
- **Evidence:** the var block + comment "Use a single mutex to protect four global
  maps" in `director/cache_ads.go`.
- **Smell:** adding a fifth downtime map with its own mutex; "finer-grained locking"
  refactors of this block.

### I-4. All config reads via `param`, never raw viper; any raw viper mutation must be followed by `param.Refresh()`

- **Why:** `param` getters read an **atomic cached struct**
  (`GetString` → accessor over `getOrCreateConfig()`, `param/parameters.go` —
  generated code), not viper. Typed `param.X.Set(...)` and `param.SetRaw`/`MultiSet`
  update both viper and the cache under `configMutex`; direct
  `viper.Set`/`MergeConfig`/`SetDefault` do not, so getters silently return
  stale/empty values. `param` also wraps `IsSet`/`UnmarshalKey` in the mutex to
  prevent viper's internal concurrent-map panics (`viperIsSet` in `param/param.go`).
- **Evidence:** `Refresh` doc comment in `param/param.go`; `MultiSet` in
  `param/param.go`; rule stated in `AGENTS.md` ("Do not use `viper` directly...").
- **Smell:** `viper.Get*` or `viper.Set` in any package other than `param`/`config`;
  a test that sets viper then wonders why the getter is empty. Full trap mechanics and
  the add-a-param checklist: `pelican-config-and-flags`.

### I-5. Config precedence is fixed, and web-UI overrides outrank everything

- **Why:** operators reason about "which value wins"; changing the order is a silent
  behavior change for every deployment (see also the prod-config rule in
  `pelican-change-control`).
- **Order (lowest→highest):** built-in defaults → primary config file
  (`<ConfigBase>/pelican.yaml`; `/etc/pelican` fallback for non-root) →
  `PELICAN_CONFIG_FILE` merge → `ConfigLocations` extra yamls → `PELICAN_*` env vars
  (`viper.AutomaticEnv`) → **web-UI overrides**, which use `viper.Set` and therefore
  outrank even env vars (`SetWebConfigOverride` in `config/config.go`, called from
  `InitServer`). A `SourceTracker` records per-key provenance
  (`initConfigInternalImpl` in `config/config.go`).
- **Smell:** reordering merge calls in `initConfigInternalImpl`; loading a config
  source with `viper.Set` (accidentally promoting it to highest precedence).

### I-6. Launch ordering in `LaunchModules` is load-bearing

All in `launchers/launcher.go`; each step exists because the next one consumes its output.

1. `config.InitServer` first; then routes registered in order **registry → broker →
   director** on the shared engine.
2. **TCP listener bound (`net.Listen`) before any origin/cache serve and hence before
   XRootD config generation** — `Server.WebPort` (default 8444) may be 0; the real
   bound port is written back via `config.UpdateConfigFromListener` and feeds the
   issuer URL baked into the XRootD config. Generate XRootD config first and tokens
   verify against a wrong issuer.
3. Fed-in-a-box (origin+cache in one process): the **origin must advertise and be
   resolvable through the director before the cache starts** — the launcher polls
   `GET /api/v1.0/director/origin/<prefix>?skipstat` expecting **307** for every
   export before calling `CacheServe`.
4. **Privileges are dropped only after XRootD launch** (`dropPrivileges` runs after
   all serves; XRootD needs root at startup to switch to the xrootd user).
5. `LaunchPeriodicAdvertise` (first ad, synchronous) runs **before** the cache's
   broker listener — the listener needs server metadata that the first advertisement
   populates in the DB (comment at the `cache.LaunchBrokerListener` call site).
- **Smell:** moving `net.Listen` later "for cleanliness"; starting the cache module
  without the origin-advertisement gate; launching broker listeners before the first ad.
- **Incident:** ordering bugs here historically surface as fed-test flakes and
  startup races → `pelican-failure-archaeology`.

### I-7. Wire formats are frozen ABI: add, never rename

Three frozen surfaces, one sanctioned evolution mechanism.

- **`server_structs` JSON.** Ads and capabilities flow between mixed-version
  directors/origins/caches. The JSON tags intentionally do NOT match Go names —
  `PublicReads` → `"PublicRead"`, `DirectReads` → `"FallBackRead"`, with the in-code
  comment "the json are kept in uppercase for backward compatibility"
  (`Capabilities` in `server_structs/director.go`). Renaming a key broke mixed-version
  federations **three separate times** (reverts chronicled in
  `pelican-failure-archaeology`).
- **Prometheus metric names/labels** (e.g. the `pelican_director_*` family in
  `metrics/director.go`). External operators alert on them, and label changes are
  capacity incidents (the 2024 cardinality blow-up forced two same-day reverts).
- **Director server APIs** (`/api/v1.0/director/registerOrigin`, `/registerCache`,
  `/registerDirector`, `/getFedToken`, ...). Old servers keep POSTing old routes.
- **The sanctioned way to evolve cross-version behavior:** the feature-negotiation
  registry `features/resources/feature-version-compatibility.yaml` (codegen via
  `generate/server_features_generator.go`). A feature declares
  `NotBeforePelican`/`NotAfterPelican` bounds per server type; ads carry
  `RequiredFeatures`; the director filters caches with
  `features.ServerSupportsFeature` (a Ternary — unknown versions are handled
  distinctly) via `cacheSupportsFeature`/`cacheMightSupportFeature` in
  `director/sort.go`. New behavior = new named feature with a version floor, **not**
  a mutated field.
- **Smell:** any diff touching a JSON tag, metric `Name:`, metric label set, or route
  string; "consistency" renames.

### I-8. One web port serves UI + API + metrics

- **Why:** everything registers on the single gin engine from `web_ui.GetEngine`
  (`web_ui/ui.go`, which `//go:embed`s the frontend): the Next.js UI under `/view`,
  all `/api/v1.0/...` routes, and Prometheus — `configureMetrics` in `web_ui/ui.go`
  attaches ginprometheus (the `/metrics` scrape endpoint, token-gated by
  `promMetricAuthHandler` in `web_ui/authorization.go`) and the embedded Prometheus
  query engine proxies at `/api/v1.0/prometheus/*`. Firewalling, TLS, and auth are
  reasoned about for exactly one port (`Server.WebPort`, default 8444).
- **Smell:** a second `net.Listen` for a new subsystem; serving metrics on a side port.
- Ports/endpoints inventory: `pelican-run-and-operate`.

### I-9. Fed tests run with `TLSSkipVerify=false`

- **Why:** skipping verification has **hidden real bugs** in the past; the test
  harness generates its own CA so there is no need to skip.
- **Evidence:** `fed_test_utils/fed.go`: "Do NOT skip TLS verification in tests. This
  has hidden *real bugs* in the past... If you think this should be changed, talk to
  the rest of the dev team first," followed by `param.TLSSkipVerify.Set(false)`.
- **Smell:** `TLSSkipVerify.Set(true)` anywhere under a fed test; "fixing" a cert
  error by disabling verification instead of fixing cert generation. Test-harness
  detail: `pelican-testing-and-qa`. Human reviewers enforce this harder than linters.

### I-10. The registry is the ONLY trust root for advertisements

- **Why:** the whole security model of section B collapses if the director ever
  verifies an ad against keys obtained from the advertiser itself (or any non-registry
  source) — an attacker could then advertise arbitrary servers into redirect responses.
- **Evidence:** `verifyAdvertiseToken` in `director/origin_api.go` derives the JWKS
  location exclusively from the registry endpoint (`GetNSIssuerURL` in
  `utils/registry_jwks/`) and additionally requires registry approval
  (`checkNamespaceStatus`).
- **Smell:** accepting a `jwks` or `jwks_uri` field from the ad payload; caching keys
  keyed by advertiser URL; skipping the approval check "for speed".

---

## D. Known-weak points (stated plainly)

These are live, acknowledged weaknesses. Do not build new code that deepens them; do
not "fix" them casually either — several are load-bearing compromises.

- **W-1 — Single-JWKS-key assumption at BOTH ends of registration.** The registry
  extracts exactly `clientJwks.Key(0)` and TODO-documents the single-key assumption
  (`validateJwks` in `registry/registry_validation.go`); the client refuses to register
  if the public JWKS has more than one key (`registerANamespace` in
  `cmd/registry_client.go`, mirrored TODO). Multi-key rotation at registration time is
  therefore unsupported end-to-end; the two TODOs reference each other and must be
  fixed together.
- **W-2 — `Generation` vs `Issuer` ambiguity in `NamespaceAdV2`.** Two overlapping
  structs describe token acquisition; the director reconstructs `base-path` by
  string-matching `Generation[0].CredentialIssuer` against `Issuer[].IssuerUrl`
  (`generateXTokenGenHeader` in `director/director.go`, long TODO citing GH #1540 —
  issue closed, TODO still in code as of 2026-07-05). The origin side admits it doesn't
  know the intended difference (TODO in `origin/advertise.go`). Touch either struct
  and you are in frozen-ABI territory (I-7) with unclear semantics.
- **W-3 — Shoveler shares the global viper.** `LaunchShoveler` sets the upstream
  library's config by writing `queue_directory` into Pelican's own global viper —
  in-code comment: "this param setting is a total HACK" (`metrics/shoveler.go`).
  Any viper-global refactor can break monitoring forwarding silently.
- **W-4 — `requiresCacheChaining` has never been enabled in production.** The
  cache-to-cache redirect path (`requiresCacheChaining` in `director/director.go`,
  gated on `Director.CachesPullFromCaches` + `?prefercached`) is TODO-marked "this
  feature has never been turned on in production". Its branches in `director/stat.go`
  and `director/sort.go` are effectively untested at scale.
- **W-5 — Key-rotation-to-director latency up to 15m.** The director caches each
  namespace's JWKS for `Director.AdvertisementTTL` (`namespaceKeys.Set(...)` in
  `verifyAdvertiseToken`, `director/origin_api.go`). After an origin rotates keys, its
  ads can be rejected (or stale keys honored) for up to 15 minutes. Derived from code,
  not measured live.
- **W-6 — `distanceAndLoad` sort is silently just `distance`.** The dispatch in
  `sortServerAds` (`director/sort.go`) maps `DistanceAndLoadType` to `DistanceSort{}`
  with the comment "currently a place holder". Operators selecting it get no load
  awareness and no warning.
- **W-7 — Client token acceptance checks `BasePaths[0]` only.** `tokenIsAcceptable`
  in `client/acquire_token.go` (TODO at the check) ignores additional issuers/base
  paths; namespaces with multiple base paths can mis-evaluate cached tokens.
- **W-8 — The upstream ttlcache `Range` lock-leak is unfixed.** `go.mod` pins
  `github.com/jellydator/ttlcache/v3 v3.3.0`; the leak behind I-1 lives in the
  library, so **any NEW `Range` call on any ttlcache in this repo can re-trip the
  director-OOM class**. UNVERIFIED whether it was ever reported/fixed upstream —
  check the jellydator/ttlcache issue tracker before relying on `Range` anywhere.
- **W-9 — Ad dropout is invisible in default logs** (Debug-only eviction logging;
  see section B). An operator's first symptom is missing redirects, not a log line.

---

## Provenance and maintenance

Facts verified **2026-07-05** against branch `main` @ `289fd41b`
(`git branch --show-current && git log -1 --format='%h'`). Run these from the repo
root to re-check the volatile facts cheaply; if a command's output no longer matches
the claim in this file, update the claim, not the command.

| Volatile fact | Re-verify with |
|---|---|
| Branch/commit baseline | `git log -1 --format='%h %s' && git branch --show-current` |
| `useXRootD` storage-type split (posixv2, ssh → Go) | `grep -n "useXRootD :=" launchers/origin_serve.go` |
| Cache Go path gate + default false | `grep -n -A8 '^name: Cache.EnableV2' docs/parameters.yaml && grep -n "usePersistentCache" launchers/cache_serve.go` |
| serverAds "no Range" rule + snapshot idiom | `grep -n "Do not use Range" director/cache_ads.go && grep -n "func getServerAdsSnapshot" director/cache_ads.go` |
| No live `Range` calls in director | `grep -rn "\.Range(" director/ --include='*.go' \| grep -v _test` (expect empty) |
| Four maps under one mutex | `sed -n '57,77p' director/cache_ads.go` |
| ABBA rule comment | `grep -n "never hold filteredServersMutex" director/cache_ads.go` |
| Fix commit for I-1/I-2 | `git log --oneline --grep 'serverAds cache under its own lock'` (expect `eca4f46c`) |
| Ad interval 1m / lifetime 10m / TTL 15m | `grep -n -A10 '^name: Server.AdvertisementInterval' docs/parameters.yaml; grep -n -A8 '^name: Server.AdLifetime' docs/parameters.yaml; grep -n -A5 '^name: Director.AdvertisementTTL' docs/parameters.yaml` |
| 1/3 clamp (both planes) | `grep -n 'GetDuration()/3\|expiryTime/3' launcher_utils/advertise.go director/director_advertise.go` |
| Ad expiry set from AdLifetime | `grep -n "Expiration = time.Now().Add(adLifetime)" server_structs/director.go` |
| Debug-only eviction logging | `grep -n 'is evicted' director/director_api.go` |
| Advertise-token scope + 1m lifetime | `grep -n -A15 'func GetAdvertisementTok' server_utils/server_utils.go \| grep -E 'Lifetime|Pelican_Advertise'` |
| Director verifies via registry JWKS + approval | `grep -n "GetNSIssuerURL\|checkNamespaceStatus\|namespaceKeys.Set" director/origin_api.go` |
| Fed token: issuer/lifetime/scopes | `sed -n '87,148p' director/fed_token.go; grep -n -A6 '^name: Director.FedTokenLifetime' docs/parameters.yaml` |
| Key-sign challenge functions | `grep -n "func keySignChallenge" registry/registry.go` |
| Capabilities frozen JSON tags | `grep -n -B2 -A8 'Capabilities struct' server_structs/director.go` |
| Feature negotiation mechanism | `ls features/resources/ && grep -n "func ServerSupportsFeature" features/feature_compatibility.go` |
| Launch ordering steps | `grep -n "net.Listen\|the XRootD configuration is written\|skipstat\|dropPrivileges\|AFTER LaunchPeriodicAdvertise" launchers/launcher.go` |
| Single engine + /metrics on it | `grep -n "func configureMetrics" web_ui/ui.go && grep -n "promMetricAuthHandler" web_ui/ui.go` |
| Web-UI override via viper.Set | `grep -n -A4 "func SetWebConfigOverride" config/config.go` |
| param Refresh contract | `sed -n '77,90p' param/param.go` |
| TLSSkipVerify=false in fed tests | `grep -n -B3 "TLSSkipVerify.Set(false)" fed_test_utils/fed.go` |
| W-1 single-key TODOs | `grep -n "single" registry/registry_validation.go cmd/registry_client.go` |
| W-2 Generation/Issuer TODOs (+ GH #1540 state) | `grep -n "1540" director/director.go; gh issue view 1540 -R PelicanPlatform/pelican --json state` |
| W-3 shoveler viper hack | `grep -n "total HACK" metrics/shoveler.go` |
| W-4 cache chaining unused | `grep -n "never been turned on" director/director.go` |
| W-6 distanceAndLoad placeholder | `grep -n "place holder" director/sort.go` |
| W-7 BasePaths[0] | `grep -n 'BasePaths\[0\]' client/acquire_token.go` |
| W-8 ttlcache pin | `grep ttlcache go.mod` (v3.3.0 as of 2026-07-05) |
| Param count drift indicator | `grep -c '^name:' docs/parameters.yaml` (447 on main as of 2026-07-05) |
| Director.EnableBroker default true | `grep -n -A6 '^name: Director.EnableBroker' docs/parameters.yaml` |
| serverResLimit = 6 | `grep -n "serverResLimit = " director/director.go` |
