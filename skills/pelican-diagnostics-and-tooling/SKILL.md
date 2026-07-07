---
name: pelican-diagnostics-and-tooling
description: >-
  How to MEASURE Pelican instead of eyeballing it. Load when you suspect a goroutine leak, memory growth, or OOM; when a test is flaky ("works locally, fails in CI", "fails nightly"); when you see "WARNING: DATA RACE"; when you need to run the race detector like CI does, profile CPU/heap via pprof, scrape or query Prometheus metrics on a token-gated server, change the log level at runtime without a restart, decode why XRootD transfer metrics are flat, check whether XRootD version pins drifted, or inspect the SQLite DBs and director API state. Contains verified commands with expected output and three tested scripts (goroutine_diff.sh, flaky_hunt.sh, check_xrootd_pins.sh).
---

# Pelican Diagnostics and Tooling — measure, don't eyeball

Every technique below was executed against `main@289fd41b` (2026-07-06) unless
marked "derived from code, not executed". Working directory: repo root, unless stated.

## When to use this skill

- You suspect a goroutine or fd leak (RSS climbing, OOM-killed director, `go_goroutines` rising).
- A test fails intermittently and you must decide: flaky, racy, or broken.
- You saw `WARNING: DATA RACE` in a nightly run, or need to run `-race` like CI does.
- You need CPU/heap/goroutine profiles, a `/metrics` scrape, or PromQL against a live (token-gated) server.
- You need debug logs from a production server *without* restarting it.
- XRootD transfer metrics are flat/zero and you need to find where the monitoring pipeline broke.
- You are checking XRootD/plugin version-pin sync, the server SQLite DB, the director's live server list, or GeoIP resolution.

**When NOT to use — route to siblings:**

- Root-causing a race/leak once you have the report or the growing stack → **pelican-concurrency-and-shutdown-proofs**.
- What happened in past incidents (the serverAds OOM story, etc.) → **pelican-failure-archaeology**.
- serverAds locking invariants and the wire-format freeze → **pelican-architecture-contract**.
- Writing tests, build-tag matrix, `ResetTestState`/`NewFedTest` idioms → **pelican-testing-and-qa**.
- The *policy* on metric renames/removals and XRootD version bumps → **pelican-change-control**.
- Ports, config file layout, systemd/containers → **pelican-run-and-operate**.
- Param precedence and the `param.Refresh()` trap → **pelican-config-and-flags**.
- Jargon (director, origin, cache, shoveler, JWKS...) → **pelican-federation-domain-reference**.

## Tool index — what question does each answer?

| Question | Tool | Section |
|---|---|---|
| Is this code racy? Did last night's race run fail? | `gotestsum ... -race`; `gh run list/view` | 1 |
| Where is CPU/memory going? Leaking goroutines? | pprof + `scripts/goroutine_diff.sh` | 2, 3 |
| Is this test flaky, racy, or broken? | `scripts/flaky_hunt.sh`; `analyze-junit-results` | 4 |
| Is the director healthy right now? | `/metrics` + director metric table | 5 |
| No debug output / too much output? | `Logging.Level` + runtime override API | 6 |
| Why are XRootD transfer metrics flat? | UDP-monitoring decision table | 7 |
| Pins drifted? What's in the DB / director state? | `scripts/check_xrootd_pins.sh`; `sqlite3`; director APIs | 8, 9 |

## 1. The race detector

### Why you have never seen `-race` on a PR

PRs do **not** run the race detector. `.github/workflows/test-linux-pr.yml`
calls the shared workflow without the flag:

```yaml
    uses: ./.github/workflows/test-linux.yml
    with:
      image: hub.opensciencegrid.org/pelican_platform/pelican-test:latest-itb
```

`race_detection` is an input of `test-linux.yml` with `default: false`. Only the
three *nightly* scheduled workflows (`test-linux-scheduled.yml`,
`test-macos-scheduled.yml`, `test-windows-scheduled.yml`, cron `0 7 * * *`) pass
`race_detection: true`. Consequence: **a shutdown/lifecycle race merged today
surfaces tomorrow at ~07:00 UTC at the earliest**, attributed to whatever unlucky
commit is at HEAD — historically the costliest bug class in this repo. If your
change touches goroutines, channels, shutdown paths, or shared maps: run `-race`
locally *before* pushing; nobody will do it for you.

### Exact local invocation (mirrors CI)

CI's command (from `test-linux.yml`, "Run go test" step; race legs use
`-timeout=30m -race` and drop coverage):

```bash
# Full CI mirror (slow — whole repo, one build-tag leg):
make web-build   # required once: web_ui embeds frontend/out/*
gotestsum --format pkgname-and-test-fails --hide-summary=output \
  --junitfile junit-pelican-server.xml -- \
  -p=4 -timeout=30m -race -tags=server ./...
```

Day-to-day, scope to the packages you touched
(`... -- -race -count=1 -timeout=10m -tags=server ./director/... ./launchers/...`).
Executed example (fast package, real output):

```
$ gotestsum --format pkgname-and-test-fails --hide-summary=output --junitfile junit-demo.xml -- -p=4 -timeout=5m -race -tags=server ./logging/
✓  logging (2.39s)

DONE 6 tests in 2.390s
```

Notes (all verified):

- `gotestsum` is not vendored; CI installs it with `go install gotest.tools/gotestsum@latest`. Plain `go test -race -tags=server ./pkg/` is an acceptable substitute. `-count=1` defeats the test cache; a cached "ok" proves nothing about races.
- Build tags gate almost everything: the CI matrix runs one `-tags=client` leg and one `-tags=server` leg. No tags = most tests silently skipped. See **pelican-testing-and-qa**.
- Packages that spin up a federation (`e2e_fed_tests/`, `fed_test_utils` importers) **fail, not skip,** without an XRootD binary >= 5.8.2 in PATH (`MinXrootdVersion` in function `CheckXrootdVersion`, `xrootd/version.go`). On a laptop without XRootD, exclude them or use the `pelican-test` container.

### GORACE options (standard Go runtime; not repo-specific)

```bash
GORACE="halt_on_error=1" go test -race ...    # stop at first race, nonzero exit
GORACE="log_path=/tmp/race" go test -race ... # one report file per PID: /tmp/race.<pid>
```

`halt_on_error=1` matters for flaky hunts: without it a race only warns and the
test may still "pass".

### Reading a race report (triage only)

Two stanzas — `Read at 0x... by goroutine N` / `Previous write at 0x... by
goroutine M` — each with a stack, then `Goroutine N (running) created at:` (the
spawn site). Triage: identify the shared object from the top frames, both spawn
sites, and whether one side is a shutdown path — in this repo it usually is.
Deep analysis: **pelican-concurrency-and-shutdown-proofs**.

### Checking nightly race results

```bash
gh run list -R PelicanPlatform/pelican --workflow test-linux-scheduled.yml --limit 5
```

Real output (2026-07-06):

```
completed  failure  Run Tests (Linux) [on schedule]  ...  main  schedule  28778615896  29m12s  2026-07-06T08:34:50Z
completed  failure  Run Tests (Linux) [on schedule]  ...  main  schedule  28734159213  1m50s   2026-07-05T08:02:28Z
```

Failures are the *norm*, not an alarm — hence the adjudication tooling in
section 4. Dig into one run (both commands executed):

```bash
gh run view 28778615896 -R PelicanPlatform/pelican --log-failed | grep -B2 -A25 'DATA RACE' | head -60
```

## 2. pprof on a live server

### Endpoint (verified live)

Pelican wires `net/http/pprof` behind gin in function `configurePprof`
(`web_ui/pprof.go`), enabled by **`Server.EnablePprof` (default `false`)**
— set it `true` in config to use any of this section. Routes, all under
`/api/v1.0/debug/pprof/` on the server web port (default 8444):

`/` (index), `/cmdline`, `/profile` (CPU), `/symbol`, `/trace`, `/allocs`,
`/block`, `/goroutine`, `/heap`, `/mutex`, `/threadcreate`.

**Auth**: the group is gated by `AuthHandler, AdminAuthHandler` — you need an
*admin* identity, via the web-UI login cookie or an `Authorization: Bearer` token.
Unauthenticated requests get
`{"status":"error","msg":"Authentication required to perform this operation"}` (verified).

### Minting a usable token (verified live)

On the server host (needs read access to the server's issuer key under
`<ConfigBase>/issuer-keys/`). NOTE: `origin` (and `registry`) subcommands live
only on the **`pelican-server`** binary — the `pelican` client build has no
`origin` command (see the two-binary split in **pelican-run-and-operate** §1):

```bash
TOKEN=$(pelican-server origin token create \
  --profile wlcg \
  --scope "web_ui.access monitoring.query monitoring.scrape" \
  --issuer https://<host>:8444 \
  --lifetime 3600 \
  --subject admin \
  --audience https://<host>:8444)
```

This exact shape (issuer/audience = `Server.ExternalWebUrl`, subject `admin`)
was verified live to pass `AuthHandler`+`AdminAuthHandler`, `/metrics` scrape
auth, and PromQL auth. CI uses the same pattern
(`.github/workflows/test-webui-e2e.yml`, "Generate admin bearer token" step).

### Verified profile commands

```bash
# Goroutine dump, human-readable (the leak-hunting workhorse):
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://<host>:8444/api/v1.0/debug/pprof/goroutine?debug=1" | head
```

Real output (live registry, `Server.EnablePprof: true`):

```
goroutine profile: total 50
3 @ 0x100df68b0 0x100dd4bd0 0x1013bd0a0 0x100dff2c4
#	0x1013bd09f	github.com/lestrrat-go/httprc.runFetchWorker+0x8f	/.../httprc@v1.0.6/fetcher.go:135
```

```bash
# Heap profile -> analyze offline:
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://<host>:8444/api/v1.0/debug/pprof/heap" -o heap.pb.gz
go tool pprof -top -nodecount=5 heap.pb.gz
```

Real output:

```
File: pelican-bin
Type: inuse_space
Showing nodes accounting for 12.81MB, 53.61% of 23.90MB total
      flat  flat%   sum%        cum   cum%
    3.16MB 13.21% 13.21%     3.16MB 13.21%  github.com/prometheus/prometheus/tsdb.newStripeSeries
```

Interpretation: a fresh server's heap is dominated by the embedded Prometheus
TSDB — healthy. Suspicious: unbounded growth in a Pelican package, or
`compress/flate`/logrus buffers growing between snapshots.

```bash
# 30s CPU profile (derived from code, not executed — same handler as stock pprof):
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://<host>:8444/api/v1.0/debug/pprof/profile?seconds=30" -o cpu.pb.gz
go tool pprof -http=:8081 cpu.pb.gz   # flamegraph in browser
```

### Known gap: block/mutex profiles are empty

The `/block` and `/mutex` routes exist, but **no non-test code calls
`runtime.SetBlockProfileRate` or `runtime.SetMutexProfileFraction`**
(verified by grep, 2026-07-06), so both endpoints return empty profiles on a live
server. For contention data use the test-time alternative, which sets the rates:

```bash
go test -tags=server -run TestX -blockprofile block.out -mutexprofile mutex.out ./director/
go test -tags=server -run TestX -cpuprofile cpu.out -memprofile mem.out ./director/
go tool pprof -top director.test block.out
```

Making the rates configurable on a live server is an open improvement candidate
(see **pelican-research-frontier**).

## 3. Goroutine-leak hunting

### The motivating failure class

2026-07-03, four leak fixes landed in one day (stories in
**pelican-failure-archaeology**): `1933a734` (every broker reverse connection
leaked a logrus `WriterLevel` pipe-scanner goroutine + 2 fds), `d3403f1a` (same
pattern in the web engine's HTTP `ErrorLog`), `63b834d8` (server DB handles not
closed on shutdown), `3b9e4af4` (one login rate-limit store — with background
goroutine — per launch). Shared shape: **a resource created per-connection or
per-launch whose cleanup was never wired to the shutdown path**. Dump-and-diff
finds every one of these.

### Method: dump-and-diff (`scripts/goroutine_diff.sh`)

```
PELICAN_TOKEN=$TOKEN ./.claude/skills/pelican-diagnostics-and-tooling/scripts/goroutine_diff.sh \
    https://<host>:8444 60
```

The script takes two `goroutine?debug=1` dumps N seconds apart, aggregates
goroutine counts by leaf function, and prints stacks whose count grew. Real output
(against a live, idle registry, 5s interval; `CURL_EXTRA=-k` because self-signed):

```
dump 1: goroutine profile: total 50
sleeping 5s ...
dump 2: goroutine profile: total 50

stacks that grew (delta / before -> after / leaf function):
  (none)

raw dumps kept: $TMPDIR/goroutine_diff.K5Iwum/dump1.txt $TMPDIR/goroutine_diff.K5Iwum/dump2.txt
```

Interpretation:

| Reading | Meaning |
|---|---|
| totals stable, no growers | healthy |
| `net/http.(*conn).serve` up, then back down on re-run | just concurrent requests — not a leak |
| one stack grows monotonically across 3+ runs under steady load | **leak**; the leaf function is your suspect. Root-cause via **pelican-concurrency-and-shutdown-proofs** |
| total grows but growers are `runFetchWorker`/`ttlcache` pools | bounded worker pools warming up; confirm they plateau |

Corroborate with metrics (no pprof needed, section 5 for auth):
`go_goroutines` and `process_open_fds` from `/metrics` are the cheap first look —
the WriterLevel leak class moves *both*. On a director, also watch
`pelican_director_map_items_total{name=...}` and
`pelican_director_ttl_cache{name="serverAds",...}` for internal-map growth.

### Test-time leak checking

For leaks reproducible in a test: baseline `runtime.NumGoroutine()` (or
`pprof.Lookup("goroutine")`), run the operation N times, then `require.Eventually`
the count returns to baseline — never `time.Sleep` (house rule, see
**pelican-testing-and-qa**). Worked proof recipes:
**pelican-concurrency-and-shutdown-proofs**.

## 4. Flaky-test adjudication

### Adjudicate one test: `scripts/flaky_hunt.sh`

```
./.claude/skills/pelican-diagnostics-and-tooling/scripts/flaky_hunt.sh <package> <test-regex> [iterations] [build-tags]
```

Runs the named test N times with `-race -count=1`, tallies failures, keeps failing
logs, flags any `WARNING: DATA RACE`. Executed example:

```
$ ./.claude/skills/pelican-diagnostics-and-tooling/scripts/flaky_hunt.sh ./logging 'TestLogLevelManager_AddChange' 3 server
Running TestLogLevelManager_AddChange in ./logging 3x with -race -tags=server
run  1: PASS
run  2: PASS
run  3: PASS
----------------------------------------
result: 0/3 runs failed
```

Verdict table:

| Result | Verdict | Next step |
|---|---|---|
| 0/N (N >= 20, ideally 50) | no evidence of flake at this N | if CI still fails, suspect environment (container users, XRootD present, ports) — see **pelican-testing-and-qa** |
| some fail, log has `DATA RACE` | race | **pelican-concurrency-and-shutdown-proofs** |
| some fail, timeout/ordering errors | classic flake | fix with `require.Eventually`; check for missing `ResetTestState` |
| N/N fail | not flaky — broken | debug directly |

Add `-parallel` pressure or `GOMAXPROCS=2` to shake out scheduling-dependent
flakes; races often need CPU starvation to fire.

### Adjudicate across CI history: `analyze-junit-results`

The nightly workflows' `analyze-runs` job downloads the last 14 runs' JUnit
artifacts and summarizes repeat offenders — the closest thing to a flaky-test
database this repo has (there is no in-repo allowlist). Run it locally against any
JUnit files produced by `gotestsum --junitfile`:

```bash
mkdir -p artifacts/run-1/junit-pelican-server-Linux
cp junit-*.xml artifacts/run-1/junit-pelican-server-Linux/
python3 .github/scripts/analyze-junit-results/analyze_junit_results.py
cat test-failure-analysis.md
```

Executed (one passing junit from section 1 plus one deliberately-failing demo
junit under `artifacts/run-2/junit-pelican-Linux/`) — real
`test-failure-analysis.md`:

```
### pelican

1 tests with failures:

- 1 failures: faildemo.TestAlwaysFails
```

Layout rules (verified in the script): it scans `artifacts/*/junit-*/**.xml`;
`junit-<matrix>-<OS>` becomes the section header; **matrix legs with zero failures
produce no section at all** — absence means clean, not missing data. To pull real
CI artifacts:
`bash .github/scripts/analyze-junit-results/download_junit_artifacts.sh "Run Tests (Linux) [on schedule]"`
(needs `GH_TOKEN` and `GITHUB_REPOSITORY=PelicanPlatform/pelican`; derived from
the script's header, executed only in CI).

## 5. Prometheus metrics

### Scraping `/metrics` (token-gated — verified live)

`Monitoring.MetricAuthorization` defaults to **true**: `/metrics` requires a token
with scope `monitoring.scrape` (handler `promMetricAuthHandler`,
`web_ui/authorization.go`). Without one you get
`{"status":"error","msg":"Authentication is required but no token is present."}` (verified).

```bash
curl -sk -H "Authorization: Bearer $TOKEN" https://<host>:8444/metrics | grep '^pelican_director'
```

### Querying the embedded Prometheus (verified live)

Every Pelican server embeds a full Prometheus TSDB scraping itself. Query API at
`/api/v1.0/prometheus/api/v1/query` (Grafana-compatible path rewriting is built
in), gated by `Monitoring.PromQLAuthorization` (default true, scope `monitoring.query`):

```bash
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://<host>:8444/api/v1.0/prometheus/api/v1/query?query=go_goroutines"
```

Real output:

```json
{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"go_goroutines","instance":"localhost:18444","job":"prometheus"},"value":[1783357822.103,"51"]}]}}
```

This means you can ask *historical* questions of a sick server
(`rate(...[1h])`, `max_over_time(go_goroutines[6h])`) without any external
monitoring stack.

### Director-health metrics that matter (names verified in `metrics/director.go`)

| Metric | Watch for |
|---|---|
| `pelican_director_server_count{server_type,from_topology}` | ad count. Sudden drop = heartbeats missed (servers silently fall out of redirects after TTL — default `Director.AdvertisementTTL` 15m) |
| `pelican_director_advertisements_received_total{status_code,...}` | non-2xx status_code rate = registration failures |
| `pelican_director_rejected_advertisements{hostname}` | which server the director is refusing, by name |
| `pelican_director_ttl_cache{name="serverAds",type=...}` | evictions/insertions churn on the serverAds cache (the OOM-class hotspot — invariants in **pelican-architecture-contract**) |
| `pelican_director_map_items_total{name}` | internal map growth (healthTestUtils, filteredServers, serverStatUtils...) |
| `pelican_director_stat_total{result}` / `pelican_director_stat_active` | origin stat query results: Timeout/UnknownErr climbing = origins unreachable |
| `pelican_director_server_statusweight` | EWMA health weight per server, feeds sorting |
| `gin_request_duration_seconds` (+ `gin_requests_total{code,url}`) | HTTP response times/error rates; URL cardinality is pre-aggregated by `mapPrometheusPath` in `web_ui/ui.go` |
| `pelican_component_health_status{...}` | per-component health enum (also as JSON at `/api/v1.0/metrics/health` — admin-gated unless `Server.HealthMonitoringPublic: true`, default false) |

### The duplicated-metric pairs and the `_toal` typo — DO NOT "FIX"

`metrics/` deliberately registers old+new names side by side (19 `TODO: Remove
this metric` markers on main, 2026-07-06), because dashboards in the field consume
the old names. Flagship example (`metrics/xrootd_metrics.go`):
`xrootd_transfer_readv_segments_count` (v7.16-era) **and**
`xrootd_transfer_readv_segments_toal` (yes, "toal" — a shipped typo, kept) **and**
`xrootd_transfer_readv_segments_total` (v7.25 fix) all exist, incremented together
at every call site. Deleting a pair member or fixing the typo is a **frozen-ABI
break**; the removal policy and its release-window rules are owned by
**pelican-change-control**. If you add a metric: new name only, never rename.

## 6. Logging control

### Static configuration

- `Logging.Level` — `trace|debug|info|warn|error|fatal|panic`, case-insensitive. Default `warn` (client) / `info` (server). The `-d` CLI flag = debug.
- `Logging.LogLocation` — file to write logs to; default none (stderr). In one process, **all modules and both XRootD daemons log into this single logrus stream**: XRootD stdout/stderr is forwarded line-by-line at INFO level with field `daemon=<name>` (function `ForwardCommandToLogger`, `daemon/launch_unix.go`). To see only XRootD: `grep 'daemon=xrootd'`.
- Early-log buffering: log lines emitted before config is parsed are held in a `BufferedLogHook` and flushed once sinks are decided (`FlushLogs`, `logging/logging.go`). Consequence: early lines can appear *after* later ones in the file, and a crash before flush can swallow them — check stderr too.

### Runtime override — no restart (verified live)

The temporary log-level manager (`logging/level_manager.go`) is driven by an HTTP
API under `/api/v1.0/logging/level`, admin-gated (routes registered in
`web_ui/ui.go`):

```bash
# What is the level right now?
curl -sk -H "Authorization: Bearer $TOKEN" https://<host>:8444/api/v1.0/logging/level
# -> {"currentLevel":"info","baseLevel":"info","activeChanges":[],"parameters":[]}

# Debug for 2 minutes, then auto-revert:
curl -sk -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"level":"debug","duration":120}' https://<host>:8444/api/v1.0/logging/level
# -> {"changeId":"b7c0d202-...","level":"debug","parameterName":"Logging.Level",
#     "endTime":"...","remainingSeconds":120}

# Revert early:
curl -sk -X DELETE -H "Authorization: Bearer $TOKEN" https://<host>:8444/api/v1.0/logging/level/<changeId>
```

All three verified live; the change auto-reverts at `endTime` (background
goroutine, 30s check interval). Body fields: `level` (required), `duration`
seconds (required, max 86400 = 24h), `parameterName` (optional, default
`"Logging.Level"`; may name an XRootD param below — the response then carries
`requiresRestart`/`effectiveAt`).

### XRootD component log levels — some force an XRootD restart

Per-component params exist under `Logging.Origin.*` and `Logging.Cache.*`.
The authoritative restart-required lists are in `logging/xrootd.go`
(maps `xrootdOriginLoggingAccessors` / `xrootdCacheLoggingAccessors`), verified 2026-07-06:

- Origin restart-required: `Logging.Origin.{Cms,Http,Ofs,Oss,Scitokens,Xrd,Xrootd}`
- Cache restart-required: `Logging.Cache.{Http,Ofs,Pfc,Pss,PssSetOpt,Scitokens,Xrd,Xrootd}`
- Exception: `Logging.Cache.Lotman` is deliberately NOT in the list (no XRootD restart).

Changing these regenerates `xrootd.cfg` and restarts the XRootD daemon —
a brief data-plane interruption. Plan accordingly on production caches.

## 7. XRootD-side observability (the UDP monitoring pipeline)

XRootD does not expose Prometheus metrics itself. It emits a **binary UDP
"detailed monitoring" stream**; Pelican listens on `127.0.0.1:<port>` (first free
port in `Monitoring.PortLower`..`Monitoring.PortHigher`, defaults 9930..9999) and
decodes packets into the `xrootd_*` Prometheus metrics (function
`ConfigureMonitoring` + `handlePacket`, `metrics/xrootd_metrics.go`).

Decision table when `xrootd_transfer_*` metrics are flat (all paths verified in code):

| Observation | Cause | Fix |
|---|---|---|
| `xrootd_monitoring_packets_received_total` climbing, transfer metrics flat | **counted-then-dropped trap**: with `Shoveler.Enable: false`, Pelican counts every packet but only *parses* it if `Xrootd.EnableLocalMonitoring` is true (hidden param, default true — tests disable it) | set `Xrootd.EnableLocalMonitoring: true` |
| packets counter also flat | XRootD isn't sending, or wrong port | check `xrootd.cfg` monitoring stanza in `<RunLocation>`, confirm the UDP port in startup logs |
| packets climbing, transfer metrics flat, log spam `Pelican failed to handle monitoring packet` | decode errors (version skew in the packet format) | capture the error text; compare XRootD version against pins (section 9) |
| `Shoveler.Enable: true` | the shoveler goroutine owns the UDP socket: it parses packets for Prometheus **and** forwards raw packets to the message bus (`Shoveler.MessageQueueProtocol`: amqp/stomp) and to `Shoveler.OutputDestinations` | check `shoveler_*` metrics and MQ credentials |

XRootD's own logs: there are no separate xrootd log files under Pelican
supervision — see section 6 (`daemon=<name>` field). Verbosity is controlled by
the `Logging.Origin.*` / `Logging.Cache.*` params above (restart caveat applies).

## 8. Misc verified tooling

### `pelican config` — see what the server actually resolved

```bash
pelican config summary   # only params differing from defaults (great first triage step)
pelican config get Server.EnablePprof Logging.Level   # prints lowercased keys: server.enablepprof: true
pelican config dump      # everything
pelican config describe Director.AdvertisementTTL     # param docs offline
```

All verified. Useful flags: `-s <service>` loads defaults as that service;
`--with-discovery` resolves federation URLs (otherwise no network calls); `--json`.
See **pelican-config-and-flags** for precedence rules.

### SQLite inspection (verified live)

The unified server DB is `Server.DbLocation` (default `${ConfigBase}/pelican.sqlite`,
root default `/var/lib/pelican/pelican.sqlite`). Always open read-only on a live server:

```bash
sqlite3 'file:/var/lib/pelican/pelican.sqlite?mode=ro' .tables
```

Real output (fresh registry): `api_keys aup_documents collections ... downtimes
goose_db_version registrations registry_goose_db_version server_master_keys
servers service_names services topology users ...` — schema comes from goose
migrations in `database/universal_migrations/` (always) plus
`database/registry_migrations/` or `database/origin_migrations/` (per server
type), each tracked in its own `*goose_db_version` table. Note
`registry/migrations/` is orphaned dead code — do not read schema from it.
Interesting tables for diagnosis: `servers`+`services` (who registered),
`downtimes`, `api_keys`.

### Director inspection endpoints (code-verified in `director/director_ui.go` and `director/director.go`)

```
GET /api/v1.0/director_ui/servers                     # all live server ads (no auth)
GET /api/v1.0/director_ui/servers/:name               # one ad
GET /api/v1.0/director_ui/servers/:name/namespaces
GET /api/v1.0/director_ui/servers/:name/downtimes
GET /api/v1.0/director/listNamespaces                 # namespace ads
GET /api/v1.0/director/namespaces/prefix/*path        # which namespace serves this path
GET /api/v1.0/director/directors                      # HA: other directors this one knows
```

`director_ui/servers` is the ground truth for "does the director currently know
about origin X" — faster and more precise than eyeballing the web UI.

### GeoIP debugging: `scripts/geoquery.py` (in the repo's `scripts/`, not this skill)

```bash
pip install geoip2
python3 scripts/geoquery.py -i 128.104.100.1 \
  -d /var/cache/pelican/maxmind/GeoLite2-City.mmdb   # root-default DB path
```

Prints city/country/lat/lon/accuracy-radius or "not resolvable" — answers "why did
the director send this client to the wrong cache". Non-root DB path:
`${ConfigBase}/maxmind/GeoLite2-City.mmdb` (param `Director.GeoIPLocation`).
Failure counters: `pelican_director_maxmind_{server,client}_errors_total`.
Not executed here (no local .mmdb); usage derived from the script's argparse,
read in full.

## 9. Shipped scripts

All three live in `.claude/skills/pelican-diagnostics-and-tooling/scripts/`, are
read-only with respect to the repo and any live service, and were each executed
against `main@289fd41b`. Sections 3 and 4 show `goroutine_diff.sh` and
`flaky_hunt.sh` with their real output and interpretation tables.

### `check_xrootd_pins.sh` — did the XRootD stack pins drift?

The XRootD version and its plugin versions are hand-duplicated across four files
(the Dockerfile even says "If you update this version, you must also update
github_scripts/osx_install.sh"). This script extracts and cross-checks all of
them. Run from the repo root; exit 0 = consistent, 1 = mismatch.

```
$ ./.claude/skills/pelican-diagnostics-and-tooling/scripts/check_xrootd_pins.sh
PIN                          FILE                   VALUE
XRootD build version         images/Dockerfile      5.9.2
XRootD build version         osx_install.sh         5.9.2 (tag: v5.9.2-pelican)
xrdcl-pelican                images/Dockerfile      1.7.1
xrdcl-pelican                osx_install.sh         1.7.1
xrdhttp-pelican              images/Dockerfile      0.0.11
xrdhttp-pelican              osx_install.sh         0.0.11
xrootd-s3-http               images/Dockerfile      0.6.7
xrootd-s3-http               osx_install.sh         0.6.7
xrootd-lotman                images/Dockerfile      0.1.0
xrootd-multiuser             images/Dockerfile      2.2.1
scitokens-cpp (source tag)   osx_install.sh         v1.4.1
Min XRootD (runtime floor)   xrootd/version.go      5.8.2
Min XRootD (RPM floor)       .goreleaser.in.yml     5.8.2
OK: all cross-file pins consistent
```

That table IS the pin inventory of main on 2026-07-06 (the macOS build uses the
`PelicanPlatform/xrootd` fork tag `v5.9.2-pelican`, normalized before comparison).
Interpretation: Dockerfile-vs-osx mismatch = Linux CI and macOS CI test different
XRootD builds. version.go-vs-goreleaser mismatch = the RPM installs where the
binary refuses to start (or vice versa). `MinXrootdVersion` (5.8.2) is a *floor*,
expected to lag the pinned build (5.9.2) — reported as INFO, not a mismatch.
Known doc drift: the `MinXrootdVersion` comment in `xrootd/version.go` cites
".goreleaser.yml (two locations: RPM and DEB)"; on main the file is
`.goreleaser.in.yml` and only the RPM override carries the floor (verified
2026-07-06). **Never change a pin just because this script flagged it — read
pelican-change-control first**; pin bumps are a gated change class (v7.25.x
deliberately downgraded 5.9.2→5.9.1, commit `fe785866`).

## Provenance and maintenance

All facts verified 2026-07-06 against `main@289fd41b` (upstream sync of
2026-07-04). Live-endpoint outputs were captured from a scratch
`pelican-server registry serve` instance built from that commit (macOS arm64, go1.25.0,
gotestsum v1.13.0). Re-verification one-liners for the volatile facts:

| Fact | Re-verify with |
|---|---|
| PRs don't run `-race`; nightly does | `grep -rn race_detection .github/workflows/` |
| CI gotestsum flags | `grep -A14 'Run "go test"' .github/workflows/test-linux.yml` |
| pprof routes + auth | `grep -n 'debug/pprof\|AdminAuthHandler' web_ui/pprof.go` (function `configurePprof`) |
| `Server.EnablePprof` default false | `pelican config describe Server.EnablePprof` |
| block/mutex profiles empty (no rate set) | `grep -rn 'SetBlockProfileRate\|SetMutexProfileFraction' --include='*.go' . \| grep -v _test` (expect: nothing) |
| 2026-07-03 leak-fix commits | `git log --oneline -i --grep='WriterLevel\|rate-limit store\|DB handles' main` |
| `/metrics` + PromQL auth defaults true | `grep -A5 'name: Monitoring.MetricAuthorization' docs/parameters.yaml` (and PromQLAuthorization) |
| director metric names | `grep -n 'Name: "pelican_director' metrics/director.go` |
| duplicated-metric TODO count (19) | `grep -rn 'TODO: Remove th' --include='*.go' . \| wc -l` |
| `_toal` typo metric still present | `grep -n 'segments_toal' metrics/xrootd_metrics.go` |
| logging API routes | `grep -n '/logging' web_ui/ui.go` |
| XRootD restart-required log params | `grep -n 'param.Logging_' logging/xrootd.go` |
| counted-then-dropped UDP trap | `grep -n 'enableHandlePacket' metrics/xrootd_metrics.go` |
| monitoring UDP port range 9930–9999 | `grep -A4 'name: Monitoring.PortLower' docs/parameters.yaml` |
| XRootD/plugin pins (5.9.2 / 1.7.1 / 0.0.11 / 0.6.7 / 5.8.2) | `./.claude/skills/pelican-diagnostics-and-tooling/scripts/check_xrootd_pins.sh` |
| junit analyzer I/O contract | `head -40 .github/scripts/analyze-junit-results/analyze_junit_results.py` |
| director inspection endpoints | `grep -n 'directorWebAPI.GET\|directorAPIV1.GET' director/director_ui.go director/director.go` |
| DB tables | `sqlite3 'file:<db>?mode=ro' .tables` on any fresh server |
| nightly run status | `gh run list -R PelicanPlatform/pelican --workflow test-linux-scheduled.yml --limit 5` |

Line numbers drift; every code reference above is paired with a function or
symbol name — search for the symbol if the line moved.
