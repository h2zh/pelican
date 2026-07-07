---
name: pelican-run-and-operate
description: Use when running, deploying, or operating Pelican services - starting an origin/cache/director/registry, spinning up a federation-in-a-box on a laptop, systemd/RPM/container deployment questions, "which port is that" (8444/8443/8442), health checks returning "Authentication required", /metrics returning 403, web UI activation code / first login, /etc/pelican config.d drop-ins, database backups, scheduling downtime, approving a namespace, cache eviction, or "XRootD binary not found in PATH" at startup. Contains verified command anatomy for the pelican vs pelican-server binaries, an executed fed-in-a-box quickstart (works on macOS without real XRootD), the production filesystem map, ports/endpoints tables with curl examples and real outputs, and the ops CLI reference.
---

# Pelican: Run and Operate

Runbook for launching, deploying, and administering Pelican services. Every command
here was executed against `main@289fd41b` on 2026-07-05/06 unless explicitly marked
"derived from code, not executed".

## When to use this skill

- You need to start any Pelican service (origin, cache, director, registry) locally or in production.
- You want a whole test federation on one machine ("federation in a box").
- You are debugging deployment questions: which binary, which port, which config file, which directory.
- A service endpoint returns 403/401 and you need to know the auth gating rule.
- You need day-to-day admin actions: approve a namespace, schedule downtime, back up the DB, evict cached objects, add an export, first web-UI login.
- Startup fails with `XRootD binary not found in PATH` or `unable to create runtime directory /pelican/...`.

**When NOT to use:**
- Building the binaries / toolchain problems → **pelican-build-and-env**
- What a parameter means, precedence, deprecation rules → **pelican-config-and-flags**
- Writing or running tests (NewFedTest, ResetTestState) → **pelican-testing-and-qa**
- Jargon (director, namespace, token profiles, discovery protocol) → **pelican-federation-domain-reference**
- Measuring a live server (profiling, metrics analysis, race hunting) → **pelican-diagnostics-and-tooling**
- Director-at-scale incidents (serverAds, OOM, HA) → **pelican-director-reliability-campaign** and **pelican-debugging-playbook**

## 1. Command anatomy: two binaries

GoReleaser builds two binaries from the same `./cmd` package with different build tags
(`.goreleaser.in.yml`, builds `pelican` and `pelican-server`):

| Binary | Build tags | Why separate |
|---|---|---|
| `pelican` | `forceposix,client` | End-user client. Small, no server deps; also shipped as the distroless container `client`. |
| `pelican-server` | `forceposix,server` | Server daemons + admin CLI. Server-only features (e.g. Lotman via runtime dlopen) and system requirements differ. Linux+darwin only. |

Command files in `cmd/` are gated by `//go:build client` or `//go:build server`
(a few are `client || server`), so **the two binaries expose different subcommands**.
Verified via `--help` on freshly built binaries:

| Command | `pelican` (client) | `pelican-server` |
|---|---|---|
| `object get/put/copy/ls/du/stat/sync/share/evict` | yes | no |
| `client-agent start/status/stop`, `job list/status/cancel` | yes | no |
| `plugin` (HTCondor), `credentials`, `token`, `namespace` | yes | mostly shared |
| `config get/dump/describe/summary` | yes | yes |
| `origin/cache/director/registry ... serve` | no | yes |
| `downtime create/list/update/delete` | no | yes |
| `cache evict/purge/introspect/chaos` | no | yes |
| `key create`, `apikey`, `generate password` | no | yes |
| `server database backup ...`, `server user/group`, `server set-logging-level` | no | yes |

Trap: in-repo help text and docs sometimes say `pelican cache evict` — in the split
production binaries that command lives on **pelican-server** (`cmd/cache_evict.go` is
`//go:build server`). A combined dev build (`go run -tags "client server"` is not used;
each binary is single-tag) does not exist; pick the right binary.

**argv[0] personality**: `GetPreferredPrefix` in `config/config.go` inspects the
executable name. Names starting with `osdf`/`stash` switch on the `osdf_default`
parameter values (e.g. `Federation.DiscoveryUrl: https://osg-htc.org`). The containers
and the `pelican-osdf-compat` RPM install `osdf`/`osdf-server`/`stashcp` symlinks for
exactly this reason. Also, exec names prefixed `stash_plugin`/`osdf_plugin`/
`pelican_xfer_plugin`/`pelican_plugin` dispatch straight into the HTCondor plugin main
(`cmd/main_client.go`).

**Public serve commands** (production): `pelican-server {origin|cache|director|registry} serve`.

**Hidden fed-in-a-box command** (testing-oriented, `Hidden: true` in `cmd/fed.go`):

```
pelican-server serve --module director,registry,origin,cache
```

Runs multiple modules in ONE process via `launchers.LaunchModules`. Flags: `--module`,
`--port` (Server.WebPort, default 8444), `--origin-port` (8443), `--cache-port` (8442).
Its long-help says web UIs are unsupported, but in practice the web engine and
activation-code flow do start (verified below).

**Flags vs YAML**: AGENTS.md ("Configuration" section) — server configuration should
prefer YAML files over command-line arguments (except when testing the CLI args
themselves). Full precedence rules: see **pelican-config-and-flags**.

**Hidden doc generator**: `pelican generate-docs [outdir]` is intercepted in
`cmd/main.go` before cobra (used by `go generate`). Trap (hit during verification):
it treats ANY second argument as the output directory — `pelican generate-docs --help`
happily creates a `--help/` directory full of .mdx files in your CWD. See
**pelican-docs-and-writing**.

## 2. Quickstart: federation-in-a-box on a laptop (verified on macOS, no real XRootD)

This exact sequence was executed successfully on macOS (darwin/arm64) on 2026-07-06:
director + registry + a pure-Go `posixv2` origin in one process, then an anonymous
client `object get` through the director. Working directory: repo root.

```bash
# 1. Build the server + client binaries (see pelican-build-and-env for toolchain)
WORK=/tmp/pelican-fedbox && mkdir -p $WORK/data $WORK/run $WORK/configbase $WORK/stubbin
go build -tags forceposix,server -o $WORK/pelican-server ./cmd
go build -tags forceposix,client -o $WORK/pelican ./cmd
echo "hello from pelican fed-in-a-box" > $WORK/data/hello.txt
```

**Trap 1 — XRootD version check fires even for the pure-Go backend.**
`launcher_utils.CheckDefaults` (function `CheckDefaults` in
`launcher_utils/xrootd_servers.go`) unconditionally calls `xrootd.CheckXrootdEnv` →
`CheckXrootdVersion` (in `xrootd/version.go`), which runs `xrootd -v`. Without XRootD
installed the origin module dies with:

```
Error: XRootD binary not found in PATH. Please install XRootD version 5.8.2 or later. See installation instructions at https://xrootd.org/
```

With `Origin.StorageType: posixv2` the binary is only *version-checked*, never
executed, so a dev-only stub satisfies the check:

```bash
cat > $WORK/stubbin/xrootd <<'EOF'
#!/bin/sh
# Dev-only stub so Pelican's startup version check passes on hosts without XRootD.
if [ "$1" = "-v" ]; then echo "v5.9.2"; exit 0; fi
echo "stub xrootd: not a real server" >&2; exit 1
EOF
chmod +x $WORK/stubbin/xrootd
```

NEVER use the stub with `posix`/`s3` storage or the cache module — those exec the real
daemon. On Linux, installing real XRootD >= 5.8.2 is the honest path.

**Trap 2 — runtime dir on hosts without `$XDG_RUNTIME_DIR` (macOS).** The non-root
default `Origin.RunLocation` is `$XDG_RUNTIME_DIR/pelican/origin`; when the variable is
unset this expands to `/pelican/origin` and startup fails with
`Error: unable to create runtime directory /pelican/origin: mkdir /pelican: read-only file system`.
(docs/parameters.yaml claims a temp-dir fallback; observed behavior on macOS was this
hard failure.) Fix: set `RuntimeDir` and `Origin.RunLocation` explicitly.

**Trap 3 — do NOT set `Federation.DiscoveryUrl` to yourself.** At startup the origin
resolves federation metadata *before* the in-process director listens; pointing
DiscoveryUrl at your own not-yet-open port fails with
`could not discover federation services ... connection refused`. When the director and
registry modules run in-process, `Federation.DirectorUrl`/`RegistryUrl` default to
`Server.ExternalWebUrl` automatically (comments in `launchers/launcher.go`,
`LaunchModules`) — just omit Federation entirely.

```bash
# 2. Config (fed.yaml). TLSSkipVerify is acceptable for a *manual laptop sandbox*
#    with self-signed certs. It is BANNED in committed fed tests -- see
#    pelican-testing-and-qa / pelican-change-control.
cat > $WORK/fed.yaml <<EOF
TLSSkipVerify: true
ConfigBase: $WORK/configbase
RuntimeDir: $WORK/run
Server:
  WebPort: 9444          # any free port; 8444 is the production default
Logging:
  Level: Info
Origin:
  StorageType: posixv2   # pure-Go data plane; no real XRootD process
  RunLocation: $WORK/run/origin
  Exports:
    - StoragePrefix: $WORK/data
      FederationPrefix: /demo
      # DirectReads is REQUIRED here: with no cache in the federation the
      # director otherwise answers 404 "No caches can fulfill this request
      # and no fallback origins with the 'DirectReads' capability found".
      Capabilities: ["Reads", "PublicReads", "Listings", "DirectReads"]
EOF

# 3. Launch (stub xrootd first on PATH)
PATH=$WORK/stubbin:$PATH $WORK/pelican-server --config $WORK/fed.yaml \
    serve --module director,registry,origin > $WORK/serve.log 2>&1 &
```

**Console milestones** (each line means the named piece is up; all observed):

| Log line (level=info unless noted) | Means |
|---|---|
| `Initializing the namespace registry's database...` + `goose: ...migrated database...` | registry DB + migrations done |
| `Initializing Director GeoIP database...` then level=error `Failed to download GeoIP database! ... (Director.MaxMindKeyFile)` | director up; geo-matchmaking disabled — **non-fatal**, fine for a sandbox |
| `Initializing POSIXv2 origin backend` | origin module chose the Go data plane |
| `Starting web engine...` | gin listening on Server.WebPort |
| `Database backup created: .../backups/pelican-db-backup-<ts>.bak` | automatic first backup |
| `Initialized WebDAV handler for /demo -> ... (storage: posixv2)` and `Registered HTTP handlers for prefix: /demo (route: /api/v1.0/origin/data/demo)` | posixv2 serves DATA on the web port, not Origin.Port |
| `Namespace /demo not registered; new registration will proceed` then `POST /api/v1.0/registry status=201` | origin self-registered in the registry |
| `POST /api/v1.0/director/registerOrigin status=200` | origin advertising to the director |
| level=warning `Director file transfer test cycle failed ... 404 ... test file upload` (repeating every ~15s) | expected artifact: the posixv2 sandbox doesn't export the `/pelican/monitoring` namespace the director's self-test writes to; harmless here |

With a real XRootD origin (`posix` storage on Linux) the extra milestone is
`Origin startup complete on port 8443` (portStartCallback in
`launchers/origin_serve.go` — derived from code, not executed here).

```bash
# 4. Verify the federation answers discovery (this is what clients resolve first)
curl -sk https://localhost:9444/.well-known/pelican-configuration
# {"discovery_endpoint":"https://<host>:9444","director_endpoint":"https://<host>:9444",
#  "namespace_registration_endpoint":"https://<host>:9444","jwks_uri":".../.well-known/issuer.jwks","broker_endpoint":""}

# 5. Client get THROUGH the director (verified end-to-end)
printf 'TLSSkipVerify: true\n' > $WORK/client.yaml
$WORK/pelican --config $WORK/client.yaml object get \
    pelican://localhost:9444/demo/hello.txt $WORK/got.txt
cat $WORK/got.txt      # -> hello from pelican fed-in-a-box
$WORK/pelican --config $WORK/client.yaml object ls pelican://localhost:9444/demo/
# -> hello.txt
```

**What does NOT work without real XRootD** (verified in code):
- `--module cache` at defaults: `CacheServe` (`launchers/cache_serve.go`) dispatches on `param.Cache_EnableV2` — false (the default) takes `cacheServeWithXRootD`, which calls `xrootd.ConfigXrootd` + `LaunchDaemons`, so a default cache needs Linux + XRootD >= 5.8.2 (`MinXrootdVersion` in `xrootd/version.go`). A pure-Go cache path DOES exist but is gated behind the hidden, experimental, default-false `Cache.EnableV2` (→ `cacheServeWithPersistentCache`, backed by `local_cache.PersistentCache`/BadgerDB); see **pelican-architecture-contract** for the data-plane matrix.
- `Origin.StorageType: posix|s3|globus|xroot`: XRootD is the data plane (`useXRootD` logic in `OriginServe`, `launchers/origin_serve.go`). Only `posixv2` and `ssh` use the Go/WebDAV data plane in `origin_serve/`.
- The full 4-module fed-in-a-box from CONTRIBUTE.md ("Run a Local Pelican Federation") is intended for the dev container, where real XRootD is installed. See **pelican-build-and-env** for the devcontainer route.

## 3. Production layout (pelican-server RPM + systemd/)

Source of truth: nfpm package `pelican-server` in `.goreleaser.in.yml` and the
`systemd/` directory.

- Binaries: `/usr/bin/pelican` (from the `pelican` RPM; `pelican-server` RPM requires `pelican >= 7.11.0`) and `/usr/bin/pelican-server`.
- RPM deps: `xrootd-server >= 1:5.8.2` (comment says keep in sync with `xrootd/version.go`), `xrootd-scitokens`, `xrootd-voms`, `xrdhttp-pelican >= 0.0.11`. XRootD bump POLICY: see **pelican-change-control**; pin locations: **pelican-build-and-env**.
- systemd units installed to `/usr/lib/systemd/system/`: `pelican-{origin,cache,director,registry}.service`. Each is:

```
ExecStart = /usr/bin/pelican-server --config /etc/pelican/pelican-<svc>.yaml <svc> serve
EnvironmentFile = -/etc/sysconfig/pelican-<svc>
Restart = on-failure / RestartSec = 20s
WorkingDirectory = /var/spool/pelican
```

- **OSDF variants** (`osdf-{origin,cache,director,registry}.service`, `osdf-*.yaml`, `10-osdf-defaults.yaml` presetting `Federation.DiscoveryUrl: https://osg-htc.org` and `/etc/pki/tls` cert paths, WorkingDirectory `/var/spool/osdf`) **exist in `systemd/` but are NOT packaged in this repo's RPM** — the `.goreleaser.in.yml` contents list ships only the `pelican-*` units. They are consumed by external OSG packaging (see **pelican-ecosystem-and-upstreams**).
- **Config entrypoint pattern**: each `/etc/pelican/pelican-<svc>.yaml` is marked `DO NOT EDIT THIS FILE! It will be overwritten upon RPM upgrade` and contains only:

```yaml
ConfigLocations:
  - "/usr/share/pelican/config.d"     # distro/site-management layer
  - "/etc/pelican/config.d"           # admin drop-ins (later dir wins; lexicographic within a dir)
Logging:
  LogLocation: /var/log/pelican/pelican-<svc>.log
```

  Admin changes go in `/etc/pelican/config.d/`. The RPM ships commented example
  drop-ins there (`type: config|noreplace`, so upgrades never clobber them):
  `10-federation.yaml` (set `Federation.DiscoveryUrl`, `Server.Hostname`),
  `20-origin-exports.yaml` (Origin.Exports skeleton), `60-origin-multiuser.yaml`,
  `90-debugging.yaml` (Debug + per-component XRootD trace levels).
- Naming matters: `pelican config --service <svc>` looks for
  `/etc/pelican/pelican-{service}.yaml`, falling back to `/etc/pelican/pelican.yaml`
  (`systemd/README.md`; path built in `cmd/config_printer/utils.go`).
- `scripts/preinstall.sh` (RPM preinstall) creates the system user: group+user
  `pelican`, home `/var/lib/pelican`, shell `/sbin/nologin`.
- Logrotate: `/etc/logrotate.d/pelican` (`systemd/pelican.logrotate`) —
  `/var/log/pelican/*.log`: `size 500M`, `rotate 10`, `copytruncate`, `compress`,
  `missingok`, `notifempty`.

## 4. Filesystem map

Running as **root** (production defaults, `root_default` in docs/parameters.yaml):

| Path | What lives there | Governing param |
|---|---|---|
| `/etc/pelican/` | ConfigBase: entrypoint yamls, `config.d/`, `server-web-activation-code` (one-time UI code), `issuer-keys/` (active signing key = the PEM with the **lowest lexicographic filename**, per `IssuerKeys.CurrentKey` in `config/init_server_creds.go`), `certificates/{tls.crt,tls.key,tlsca.pem,tlsca.key}` (self-signed generated on first start), `web-config.yaml` (UI-written overrides) | `ConfigBase` (root_default `/etc/pelican`) |
| `/var/lib/pelican/` | `pelican.sqlite` — the single GORM/goose server DB (`Server.DbLocation`); legacy per-service paths `origin.sqlite`/`cache.sqlite`/`registry.sqlite`/`director.sqlite` (Cache/Director/Registry variants are `deprecated: true` → Server.DbLocation); `backups/` (`Server.DatabaseBackup.Location`, encrypted, every `Server.DatabaseBackup.Frequency` = 24h); `monitoring/data` — embedded Prometheus TSDB (`Monitoring.DataLocation`) | multiple, see left |
| `/var/spool/pelican/` | systemd WorkingDirectory (and `shoveler/queue` under it) | unit files |
| `/var/log/pelican/` | `pelican-<svc>.log` (`Logging.LogLocation`), rotated per section 3 | `Logging.LogLocation` |
| `/run/pelican/` | RuntimeDir: address files, generated XRootD configs (`/run/pelican/xrootd/{origin,cache}`), `/run/pelican/localcache` | `RuntimeDir`, `Origin.RunLocation`, `Cache.RunLocation` |
| `/var/cache/pelican/maxmind/` | GeoLite2-City.mmdb (director) | `Director.GeoIPLocation` |

**PRODUCTION TRAP** (one line; mechanics owned by **pelican-config-and-flags**):
`Cache.StorageLocation` root-defaults to `/run/pelican/cache` — tmpfs, cleared on
reboot, small; parameters.yaml itself warns it must *never* be used for production
caches. Always set it to real disk.

Running as **non-root** (dev laptops): everything collapses under
`ConfigBase = ~/.config/pelican` (DB, backups, certs, issuer-keys, monitoring,
activation code — all `${ConfigBase}/...` defaults) and runtime dirs under
`$XDG_RUNTIME_DIR/pelican` (see Trap 2 above when that variable is unset).
Client config default: `$HOME/.config/pelican/pelican.yaml` (from `pelican --help`).

## 5. Ports and endpoints

| Port | Param | Serves |
|---|---|---|
| 8444 | `Server.WebPort` | Everything web: `/view/` UI, all `/api/v1.0/*`, `/metrics`, embedded Prometheus, `/.well-known/*` |
| 8443 | `Origin.Port` | XRootD origin data plane (posix/s3/globus/xroot). **Unused by posixv2/ssh origins** — their data flows through WebPort at `/api/v1.0/origin/data/<prefix>` |
| 8442 | `Cache.Port` | XRootD cache data plane |
| — | `Xrootd.Port` | Deprecated; use Origin.Port / Cache.Port |

Endpoints on the web port (all curl outputs below observed live):

```bash
# Liveness (never auth-gated):
curl -sk https://HOST:8444/api/v1.0/health
# {"message":"Web Engine Running. Time: 2026-07-06 04:19:02..."}

# Component health -- admin-auth-gated by default:
curl -sk https://HOST:8444/api/v1.0/metrics/health
# {"status":"error","msg":"Authentication required to perform this operation"}
# With Server.HealthMonitoringPublic: true (default false), same URL returns:
# {"status":"critical|warning|ok","components":{"director":{...},"federation":{"status":"ok",...},
#  "prometheus":{...},"registry":{...},"storage":{...},"web-ui":{...},"xrootd":...}}

# Prometheus scrape -- token-gated by Monitoring.MetricAuthorization (default true):
curl -sk https://HOST:8444/metrics
# 403 {"status":"error","msg":"Authentication is required but no token is present."}
# Accepted tokens: director-minted scraper tokens, the server's own, or a web-UI
# session cookie (checker in web_ui/authorization.go). The director scrapes member
# origins/caches this way automatically.

# Embedded Prometheus query API -- gated by Monitoring.PromQLAuthorization (default true):
curl -sk "https://HOST:8444/api/v1.0/prometheus/query?query=up"     # 403 without token
# (Grafana-compatible: /api/v1.0/prometheus/api/v1/* is path-rewritten, web_ui/prometheus.go)

# Director health-test object (what origins/caches fetch during director tests);
# path must match /pelican/monitoring/{selfTest,directorTest}/... with an RFC3339 timestamp:
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
curl -sk "https://DIRECTOR:8444/api/v1.0/director/healthTest/pelican/monitoring/selfTest/self-test-$TS.txt"
# This object was created by the Pelican director-test functionality

# The /.well-known trio (director serves all three; origins/registries serve the OIDC pair):
curl -sk https://DIRECTOR:8444/.well-known/pelican-configuration   # federation metadata (JSON above)
curl -sk https://HOST:8444/.well-known/openid-configuration        # {"issuer":...,"jwks_uri":...}
curl -sk https://HOST:8444/.well-known/issuer.jwks                 # {"keys":[{"alg":"ES256","crv":"P-256",...}]}
```

Protocol semantics of discovery/tokens: **pelican-federation-domain-reference**.

## 6. First login: web UI activation

1. On first start (no password bootstrapped, no configured admins —
   `shouldSkipActivationFlow` in `web_ui/ui.go`), the server writes a one-time
   6-digit code to `${ConfigBase}/server-web-activation-code`
   (`Server.UIActivationCodeFile`; `/etc/pelican/server-web-activation-code` as root)
   and also prints it to stdout when attached to a TTY. It regenerates periodically
   until setup completes, and the file is removed afterward.
2. Browse to `https://HOST:8444/view/` — unactivated servers 302-redirect to
   `/view/initialization/code/` (observed). Enter the code, then set the admin
   password (stored as htpasswd in `Server.UIPasswordFile`; POST
   `/api/v1.0/auth/initLogin` under the hood).
3. Non-interactive alternative: pre-create the password file with
   `pelican-server generate password` (verified: `generate password` subcommand,
   htpasswd output), or set OIDC-based admin identities.
4. Dev note: a from-source `go build` binary embeds only a placeholder UI
   (`web_ui/frontend/out/placeholder`); run `make web-build` first for the real UI.
   Release binaries/images always contain it.

## 7. Ops CLI reference (every command verified via --help; ▶ = also executed live)

`pelican-server` (admin/server side):

| Command | Notes |
|---|---|
| `origin serve`, `cache serve`, `director serve`, `registry serve` | the production daemons; per-service flags on each `--help` |
| ▶ `serve --module a,b,c` | hidden fed-in-a-box (section 2) |
| ▶ `downtime list -s https://HOST:8444` | prints table or "No downtime periods found matching the criteria."; `-t` token file optional — auto-generates an admin token when run on the server host with the same config |
| `downtime create/update/delete` | `create` is interactive (prompts for fields); same `-s`/`-t` flags |
| `cache evict [--immediate] /path/` | prefix or exact match; marks purge-first unless `--immediate`; also `cache purge` (trigger LRU), `cache introspect`, `cache chaos` (fault injection) |
| ▶ `server database backup create/list/info/verify/restore` | backups compressed+encrypted with issuer keys into `Server.DatabaseBackup.Location`; `list` verified: table of name/size/timestamp. Needs resolvable federation config — pass `--config` of the service (add `-f <discovery-url>` if the config lacks Federation.*) |
| `server set-logging-level` | temporary live log-level change — measurement details in **pelican-diagnostics-and-tooling** |
| `server user/group` | manage web-UI users/groups |
| `key create --private-key f.pem --public-key f.jwks` | ECDSA P-256 keypair; won't overwrite an existing private key |
| `apikey` | manage API keys for server operations |
| `generate password` | create the admin htpasswd file |

`pelican` (client side):

| Command | Notes |
|---|---|
| ▶ `object get/ls` | verified through the fed-in-a-box (section 2) |
| `object put/copy/sync/stat/du/share/evict` | `object evict` = local-cache eviction (distinct from server-side `cache evict`) |
| ▶ `config get/dump/describe/summary` | `config get Server.WebPort` → `server.webport: 8444`; `describe` prints type/default/root-default/docs; `--service <svc>` loads as that service |
| `client-agent start/status/stop`, `job list/status/cancel` | REST API over a Unix socket exposing transfers as async jobs — see `client_agent/README.md` |
| `plugin`, `credentials`, `token`, `namespace` | HTCondor plugin + token utilities |

## 8. Containers

- Registry: `hub.opensciencegrid.org/pelican_platform/<image>` (OSG Harbor). Images
  built by `.github/workflows/build-and-test.yml`: `client, cache, director, origin,
  registry, osdf-{cache,director,origin,registry}, pelican-dev, pelican-test`.
- Tag rules (workflow comment + tag logic, verified): PRs never push; pushes to
  `main` push only `pelican-dev`/`pelican-test` tagged **`latest-itb`**; semver tags
  push all release images tagged `vX.Y.Z`, plus `latest` only when the tag is the
  highest non-rc release.
- Server images: `ENTRYPOINT ["/entrypoint.sh", "pelican-server", "<svc>"]` +
  `CMD ["serve"]`; `entrypoint.sh` execs under **tini**. Binaries inside:
  `/usr/local/sbin/pelican-server`, `/usr/local/bin/pelican`, with `osdf-server`/`osdf`
  symlinks (argv[0] personality, section 1). The `osdf-*` images differ only by
  entrypoint selector `osdf-server`.
- Cert auto-trust: mount extra CAs at `/certs/*.crt` — entrypoint.sh copies them into
  `/etc/pki/ca-trust/source/anchors/` and runs `update-ca-trust extract` before exec.
- Frozen UIDs (`images/Dockerfile` ARG block): pelican=10941, xrootd=10940
  (comment: "XRootD's UID and GID here are effectively set in stone because of
  existing data in the wild that is owned by these IDs"), tomcat=10443. Never remap
  these on hosts with existing cache/origin data.
- `client` image is distroless (`gcr.io/distroless/static-debian13:nonroot`,
  `ENTRYPOINT ["/bin/pelican"]`) — no shell inside.
- Example (derived from entrypoint.sh usage text + Dockerfile CMD, not executed —
  no container runtime exercised in this verification):
  `docker run -p 8444:8444 hub.opensciencegrid.org/pelican_platform/director:latest-itb serve`

## 9. Day-to-day admin recipes

**Add an export to an origin** — edit `/etc/pelican/config.d/20-origin-exports.yaml`
(append a `- FederationPrefix/StoragePrefix/Capabilities` block under `Origin.Exports`),
then `systemctl restart pelican-origin`. Capability meanings + validation:
**pelican-config-and-flags**. Remember DirectReads if the federation has no cache
covering the namespace.

**Approve a namespace in the registry** — when `Registry.RequireOriginApproval` /
`RequireCacheApproval` is true (default false; `osdf_default` true), servers can
register but the director will not route traffic to them until approved. Admin
surface (verified in `registry/registry_ui.go` and the React UI):
`PATCH /api/v1.0/registry_ui/namespaces/:id/approve` (or `/deny`), admin-auth-gated;
in the web UI, pending registrations show as approve/deny cards under
`https://REGISTRY:8444/view/registry/`. Pending registrations that stop polling are
garbage-collected after `Registry.InactiveRegistrationTimeout` (20m).

**Schedule downtime** — `pelican-server downtime create -s https://ORIGIN:8444`
(interactive prompts; from the server host itself the admin token is auto-minted).
Verify with `downtime list -s ...`. Downtime propagates to the director so clients
stop being routed there.

**Take / restore a DB backup** — automatic every 24h (`Server.DatabaseBackup.Frequency`,
0 disables) into `/var/lib/pelican/backups`; manual:
`pelican-server --config /etc/pelican/pelican-<svc>.yaml server database backup create`
(then `list`, `verify`, `restore`). Backups are encrypted with the issuer keys —
losing `issuer-keys/` means losing the backups too; snapshot both together.

**Rotate issuer keys** — drop a new PEM into `IssuerKeysDirectory`
(`${ConfigBase}/issuer-keys`); the active signing key is the one with the
**lowest lexicographic filename**, while all others remain loaded for
verification. So to make a new key active, name it to sort first (e.g.
`00-newkey-<date>.pem`) — merely being newest does NOT activate it. One-liner
only — key/trust semantics and the `parameters.yaml`-vs-code wording discrepancy:
**pelican-federation-domain-reference** §3. Generate with `pelican-server key create`.

**Watch health** — `curl -sk https://HOST:8444/api/v1.0/metrics/health` with an admin
token (or set `Server.HealthMonitoringPublic: true`); component statuses are
`ok|warning|critical` with per-component messages (section 5 shows the shape).
`/api/v1.0/health` is the cheap unauthenticated liveness probe for load balancers.
Continuous measurement (Prometheus queries, scrape topology): **pelican-diagnostics-and-tooling**.

## Provenance and maintenance

All facts verified 2026-07-05/06 against `main@289fd41b` on macOS (darwin/arm64,
go1.25.0). The fed-in-a-box quickstart, curl outputs, and ▶-marked CLI commands were
executed; items marked "derived from code, not executed" were not. XRootD-requiring
paths (cache serve, posix/s3 origins, containers) were verified by code reading only
on this machine.

Re-verification commands (run from repo root):

| Volatile fact | Re-check with |
|---|---|
| Default ports 8444/8443/8442 | `grep -A5 '^name: Server.WebPort$\|^name: Origin.Port$\|^name: Cache.Port$' docs/parameters.yaml` |
| Two binaries + build tags | `grep -n 'binary:\|tags:' -A3 .goreleaser.in.yml \| head -30` |
| Command split (which subcommand on which binary) | `head -2 cmd/downtime.go cmd/cache_evict.go cmd/key.go cmd/object.go cmd/server.go` |
| Hidden serve --module command | `grep -n 'Hidden: true' cmd/fed.go` |
| posixv2/ssh bypass XRootD data plane | `grep -n 'useXRootD :=' launchers/origin_serve.go` |
| XRootD version check reached from CheckDefaults | `grep -n 'CheckXrootdEnv' launcher_utils/xrootd_servers.go xrootd/xrootd_config.go` |
| Min XRootD version 5.8.2 | `grep -n 'MinXrootdVersion' xrootd/version.go && grep -n 'xrootd-server >=' .goreleaser.in.yml` |
| systemd unit shape + WorkingDirectory | `cat systemd/pelican-origin.service` |
| OSDF units not in RPM | `grep -c 'osdf-.*\.service' .goreleaser.in.yml` (expect 0) vs `ls systemd/osdf-*.service` |
| ConfigLocations drop-in pattern | `cat systemd/pelican-origin.yaml` |
| Shipped config.d examples | `grep -n 'config.d' .goreleaser.in.yml` |
| Logrotate 500M x10 copytruncate | `cat systemd/pelican.logrotate` |
| preinstall creates pelican user | `cat scripts/preinstall.sh` |
| Filesystem root defaults | `grep -n 'root_default' docs/parameters.yaml` |
| Cache.StorageLocation trap warning | `grep -n -B2 'never_ be used for production caches' docs/parameters.yaml` |
| Health/metrics/prometheus gating params | `grep -A4 '^name: Server.HealthMonitoringPublic$\|^name: Monitoring.MetricAuthorization$\|^name: Monitoring.PromQLAuthorization$' docs/parameters.yaml` |
| Endpoint routes | `grep -n 'metrics/health\|healthTest' web_ui/ui.go; grep -n 'federationDiscoveryPath' director/discovery.go; grep -n '"/.well-known"' server_utils/oidc.go` |
| Activation code flow | `grep -n 'UIActivationCodeFile\|shouldSkipActivationFlow' web_ui/ui.go` |
| Registry approve API | `grep -n 'approve' registry/registry_ui.go` |
| Container images + tag rules | `sed -n '8,16p;53,66p' .github/workflows/build-and-test.yml` |
| Frozen UIDs 10941/10940 | `sed -n '44,60p' images/Dockerfile` |
| Entrypoint cert auto-trust + tini | `sed -n '23,31p' images/entrypoint.sh && grep -n tini images/entrypoint.sh` |
| CLI surfaces | rebuild both binaries (`go build -tags forceposix,{client,server} -o /tmp/p ./cmd`) and diff `--help` |
| argv[0] osdf personality | `grep -n -A12 'func GetPreferredPrefix' config/config.go` |
