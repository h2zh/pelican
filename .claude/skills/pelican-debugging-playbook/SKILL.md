---
name: pelican-debugging-playbook
description: >
  Symptom-to-triage decision table for the Pelican repo. Load this when you hit any of:
  a param getter returning empty/zero/stale config values; "build constraints exclude all
  Go files" or go test running fewer tests than expected; "XRootD binary not found in PATH";
  a red CI check (Check Go Generate, Check Rebase on Main, PR Validation/labelling, Check for
  Large Objects); a blank web UI or 404 under /view/; director returning 404/405/429 or "no
  servers were found for the requested path"; 401/403 on a transfer; a server silently missing
  from redirects; "database is locked" SQLite errors; XRootD dying at launch; a nightly race
  detector or flaky-test failure; wrong version from git describe; or gh CLI acting on the
  wrong repo. Contains discriminating experiments with exact commands and expected output
  both ways.
---

# Pelican Debugging Playbook

Symptom-first triage for the Pelican repository. Each row of the master table names a
discriminating check; each section gives copy-pasteable commands with the output you
should see in BOTH outcomes. All commands run from the repo root unless stated otherwise.
Facts verified 2026-07-05/06 against `main@289fd41b` (see Provenance).

## When to use this skill

Load this skill when you see any of these symptoms or phrases:

- `param.X.GetString()` / `GetInt()` / `GetDuration()` returns empty, zero, or a stale value
- `go test` reports `build constraints exclude all Go files`, or runs fewer tests than CI does
- `XRootD binary not found in PATH. Please install XRootD version 5.8.2 or later`
- CI red on: `Check Go Generate`, `Check Rebase on Main`, `PR Validation`, `Check for Large Objects`
- Web UI is blank, or `/view/` chains to an HTTP 404
- Director responds 404 `No sources found for the requested path`, 405 `none support the request`,
  429 `director just restarted, try again shortly`, or 404 `Are you sure it exists?`
- 401/403 on `pelican object get/put` or raw HTTP transfer
- An origin or cache stopped appearing in director redirects with no error anywhere
- `database is locked` / `SQLITE_BUSY` from any Pelican SQLite database
- XRootD daemon exits immediately at origin/cache startup
- Nightly `-race` CI failure, or a test that fails only sometimes
- A binary or `git describe` reports an ancient version (e.g. `v7.19.4-*`)
- `gh` CLI shows the wrong PRs/issues (fork instead of upstream)

**When NOT to use this skill** — route instead to:

- Deep mechanics of the param/viper system, precedence, add-a-param → **pelican-config-and-flags**
- serverAds locking invariants, launch ordering, wire-format freeze → **pelican-architecture-contract**
- The full story of a past incident (what happened, which commits) → **pelican-failure-archaeology**
- Writing or fixing tests, build-tag matrix, `NewFedTest`/`ResetTestState` idioms → **pelican-testing-and-qa**
- Proving/fixing a race, goroutine leak, or shutdown bug → **pelican-concurrency-and-shutdown-proofs**
- Measurement tooling: profiling, race detector invocation, flaky hunting scripts → **pelican-diagnostics-and-tooling**
- Ports/paths/systemd/production ops → **pelican-run-and-operate**
- Jargon (token profiles, authfile, scitokens.cfg, discovery, broker) → **pelican-federation-domain-reference**
- Director-at-scale campaign work (serverAds OOM class, HA) → **pelican-director-reliability-campaign**
- XRootD version-bump policy, backports, PR gates → **pelican-change-control**

## Master triage table

| # | Symptom | First discriminating check | If A → | If B → | Depth owner |
|---|---------|---------------------------|--------|--------|-------------|
| 1 | param getter returns empty/stale value | Did any code call `viper.Set`/`MergeConfig` without `param.Refresh()`? Compare `viper.GetString(key)` vs `param.X.GetString()` | Values differ → stale snapshot; call `param.Refresh()` or use `param.X.Set()` (§1) | Values agree but both wrong → config precedence issue | pelican-config-and-flags |
| 2 | go test runs fewer tests / `build constraints exclude all Go files` | Are you passing `-tags`? Run `go test -tags "client server" ./cmd/ -list '.*' \| grep -c '^Test'` vs your invocation | Counts differ → build tags (§2) | Counts equal → test filter (`-run`) or platform tag (`!windows`, lotman) | pelican-testing-and-qa |
| 3 | Fed test fails `XRootD binary not found in PATH` | `which xrootd` | Not found → install XRootD ≥ 5.8.2 or avoid fed-test packages locally (§3) | Found but still fails → `xrootd -v` < 5.8.2, upgrade | pelican-build-and-env |
| 4 | CI check red | Which check name? | Decoder table §4 has exact fix per check | Test failure inside test-linux → reproduce locally with tags (§2) | pelican-testing-and-qa |
| 5 | Web UI blank / `/view/` 404s | Was `make web-build` run before `go build`? Check `ls web_ui/frontend/out/` | Only `placeholder` present → rebuild (§5) | Real files present → browser console / basePath issue | pelican-run-and-operate |
| 6 | Director 404/405/429 for an object | `curl -sk -w '\nHTTP=%{http_code}\n' <director>/api/v1.0/director/object/<path>` and read the `msg` | Walk the chain: ad present? namespace approved? ad expired? (§6) | 429 within 5 min of director start → wait, retry (§6) | pelican-architecture-contract |
| 7 | 401/403 on transfer | 401 from director with `WWW-Authenticate: Bearer error="invalid_token"` vs 403 from origin/cache | 401 director → token expired/clock skew; decode token (§7) | 403 server → scope/path/issuer mismatch; read scitokens.cfg + authfile (§7) | pelican-federation-domain-reference |
| 8 | Server silently dropped from redirects | `curl -sk <director>/api/v1.0/director_ui/servers` — is the ad there? | Missing → ad expired (10 m lifetime, 1 m heartbeat) or rejected; check origin logs + metrics (§8) | Present but `"filtered": true` → downtime/filter | pelican-architecture-contract |
| 9 | `database is locked` / `SQLITE_BUSY` | Which SQLite file? Pelican's own DBs use WAL via `_pragma=` DSN; scitokens-cpp cache is WAL-flipped at launch | Pelican DB → check DSN uses `SQLiteDSN()` helper (§9) | scitokens-cpp cache on old branch → WAL flip missing (§9) | pelican-failure-archaeology |
| 10 | XRootD won't start / dies at launch | Read `<RunLocation>/xrootd.cfg` + the `daemon=xrootd` log lines | Version error → `xrootd -v` vs 5.8.2 min (§10) | Port bind / cert path errors → §10 | pelican-run-and-operate |
| 11 | Nightly race failure / flaky test | Is it a `WARNING: DATA RACE` or an ordering flake? | Race → **pelican-concurrency-and-shutdown-proofs** | Flake → **pelican-diagnostics-and-tooling** (flaky hunting) | those two |
| 12 | Version reports `v7.19.4-*` on a current tree | `git describe --tags` on `main` | Expected: release tags live on release branches, never merged to main (§11) | On a release branch it describes correctly | pelican-build-and-env |
| 13 | gh CLI shows wrong PRs/issues | `git remote -v` — `origin` is typically a personal fork | Always pass `-R PelicanPlatform/pelican` (§11) | — | pelican-ecosystem-and-upstreams |

## §1 Param getter returns empty/stale value

Mechanics (one line; full story in **pelican-config-and-flags**): `param.X.GetXxx()` getters
read an atomic cached `Config` snapshot, NOT live viper. Any raw viper mutation
(`viper.Set`, `MergeConfig`, `ReadConfig`, ...) is invisible until `param.Refresh()`
rebuilds the snapshot (see the doc comment on function `Refresh` in `param/param.go`).

Discriminate (no new file needed): log both values at the failure point —

```go
t.Logf("viper=%q param=%v",
    viper.GetString("Director.AdvertisementTTL"),
    param.Director_AdvertisementTTL.GetDuration())
```

If viper holds the value but the `param` getter returns zero/empty, it is the stale-snapshot
bug: a raw `viper.Set`/`MergeConfig` ran without a following `param.Refresh()`. The full
standalone runnable proof (a temp `_test.go` you create, run, and delete) is single-owned in
**pelican-config-and-flags** §4.

Caveat: in a fresh process the FIRST getter call builds the snapshot from viper lazily
(function `getOrCreateConfig` in `param/param.go`), so a `viper.Set` done before any
getter appears to "work" — which is why this bug hides in tests that pass individually
and fail in a package run.

Fixes, in order of preference:

1. Use the typed setter: `param.Director_AdvertisementTTL.Set(42 * time.Minute)` — every
   Param type has `Set()` which routes through `MultiSet` (viper + snapshot atomically).
2. If you must mutate viper directly (config-file merge, test setup): follow with
   `param.Refresh()`.
3. In tests, `server_utils.ResetTestState()` resets everything (see **pelican-testing-and-qa**).

If viper AND the getter agree but the value is wrong → it's precedence (env var, web-UI
override via `viper.Set` outranking your config file) → **pelican-config-and-flags**.
`pelican config get <name> -v` prints per-key provenance (§12).

## §2 go test ran fewer tests than expected / build-tag gating

On main (2026-07-06) all `client`/`server` build tags live in `cmd/` (99 files); the rest
of the tree is gated only by platform tags (`!windows`, `linux && !ppc64le` for lotman).
CI runs two passes: `-tags=client` and `-tags=server` (`.github/workflows/test-linux.yml`).
Note: the tag split does NOT exist on the `v7.25.x` release branch — there `go test ./cmd/`
works untagged.

Discriminating experiment (executed 2026-07-06, main tree, macOS arm64):

```
$ go test ./cmd/                          # no tags — LOUD failure
package github.com/pelicanplatform/pelican/cmd: build constraints exclude all Go files in .../cmd
FAIL    github.com/pelicanplatform/pelican/cmd [setup failed]

$ go test -tags client ./cmd/ -list '.*' | grep -c '^Test'
67
$ go test -tags server ./cmd/ -list '.*' | grep -c '^Test'
36
$ go test -tags "client server" ./cmd/ -list '.*' | grep -c '^Test'
87                                        # the superset — what you want locally
```

Decision:

- `build constraints exclude all Go files` on `./cmd` → add tags. Widest local run:
  `go test -tags "client server" ./...` (documented in AGENTS.md "Test Commands").
- Passing but count lower than CI → you ran ONE tag; the other tag's `cmd/` tests were
  silently excluded (no FAIL, no skip message — the files simply don't exist to the compiler).
- Tests missing on macOS → platform tags: lotman is `linux && !ppc64le`; 113 files are
  `!windows` (counts drift; re-verify per Provenance). See **pelican-testing-and-qa**.

## §3 Fed test fails: XRootD binary not found in PATH

Any test that spins a federation via `fed_test_utils.NewFedTest` (function `NewFedTest`
in `fed_test_utils/fed.go`) launches a real XRootD. Without the binary the test FAILS —
it does not skip. Executed 2026-07-06 on a Mac with no xrootd (fails in ~5 s):

```
$ go test -tags server ./e2e_fed_tests/ -run TestDirectorMetadataHosting
    Error:  Received unexpected error:
            XRootD binary not found in PATH. Please install XRootD version 5.8.2 or later. See installation instructions at https://xrootd.org/
            github.com/pelicanplatform/pelican/xrootd.CheckXrootdVersion
FAIL    github.com/pelicanplatform/pelican/e2e_fed_tests    0.793s
```

Source: function `CheckXrootdVersion` in `xrootd/version.go`; `MinXrootdVersion = "5.8.2"`
(same file, must stay in sync with `.goreleaser.in.yml` — bump policy is owned by
**pelican-change-control**; install paths by **pelican-build-and-env**).

Packages that import `fed_test_utils` and therefore need XRootD (main, 2026-07-06):
`e2e_fed_tests` (30 files), `local_cache` (7), `cmd` (6), `director` (3), `client_agent` (3),
`client` (3), `origin_serve` (2), `origin` (2), `xrootd`, `metrics`, `client_agent/apiclient`,
`cache` (1 each). Options:

- Install XRootD ≥ 5.8.2 (Linux: distro/OSG packages; macOS: build from source via
  `github_scripts/osx_install.sh` — slow) — see **pelican-build-and-env**.
- Or use the `pelican-dev:latest-itb` dev container (`.devcontainer/devcontainer.json`).
- Or skip those packages locally and let CI run them; only a handful of tests skip
  gracefully via `exec.LookPath("xrootd")` (e.g. in `cmd/object_get_test.go`).

## §4 CI failure decoder

| Red check | What it actually runs | Exact fix |
|---|---|---|
| **Check Go Generate** (`check-go-generate.yml`) | `go generate ./...` then fails if `git diff` non-empty | Run `make generate` (or `go generate ./...` from repo root), commit the changed **tracked** outputs: `param/parameters.go`, `param/parameters_struct.go`, `config/parameter_defaults.go`, `token_scopes/token_scopes.go`, `error_codes/error_codes.go`, `features/features.go`, and `docs/app/commands-reference/**` (CLI docs regenerate when flags change). `docs/parameters.json` & `web_ui/frontend/public/data/parameters.json` are gitignored — do not commit. |
| **Check Rebase on Main** (`check-rebase-on-main.yml`) | `git merge-base --is-ancestor origin/main HEAD` | Merge commits from main are NOT enough. From your branch: `git fetch upstream && git rebase upstream/main && git push --force-with-lease origin <branch>` |
| **PR Validation** (`enforce-PR-labelling.yml`) | Fails if PR has zero labels OR zero `closingIssuesReferences` | Add ≥ 1 label AND link an issue: put `Fixes #N` / `Closes #N` in the PR body, or connect via the sidebar. Plain `#N` mentions do not count. |
| **Check for Large Objects** (`check-large-objects.yml`) | Scans `base..head` for blobs > 1 MB | The blob must leave the COMMIT HISTORY, not just the tip: `git rebase -i` to drop/edit the offending commit, then force-push. Deleting the file in a new commit still fails. |
| **validate-parameters** (`validate-parameters.yml`) | `python3 .github/scripts/validate-parameters/main.py` against `docs/parameters.yaml` | That Makefile target from AGENTS.md does not exist — run the python script from repo root. Full local-run recipe (venv + PyYAML) and the AGENTS.md discrepancy: **pelican-config-and-flags** §9.5. |
| **test-linux-pr** fails on container-dependent change | PR tests run inside `pelican-test:latest-itb` built from **main**, not your PR | If your PR changes container contents (XRootD version, test users), it is tested against the OLD image until merged. Split into two PRs (image first) per CONTRIBUTE.md; policy in **pelican-change-control**. |

Race-detector note: PR CI never runs `-race`; only the nightly scheduled workflows do
(`test-*-scheduled.yml`, cron `0 7 * * *`, `race_detection: true`). A clean PR does not
mean race-free — see **pelican-concurrency-and-shutdown-proofs**.

## §5 Web UI is blank / placeholder page

The Go binary embeds `web_ui/frontend/out/*` (`//go:embed` in `web_ui/ui.go`). The repo
tracks a single `web_ui/frontend/out/placeholder` file so `go build` succeeds on a fresh
clone — producing a binary with NO real UI. Compile succeeds; the symptom is at runtime.

Observed live (2026-07-06, server built without web-build):

```
$ curl -sk -w 'HTTP=%{http_code}\n' https://localhost:19710/view/
<a href="/view/initialization/code/">Found</a>.
HTTP=302
$ curl -skL -o /dev/null -w 'HTTP=%{http_code}\n' https://localhost:19710/view/initialization/code/
HTTP=404          # <-- missing embedded UI
```

Fix (repo root; needs Node 20 / npm):

```
make web-build     # npm ci && npm run build → web_ui/frontend/out/
go build -tags server ./cmd/    # rebuild AFTER web-build so the embed picks it up
```

Healthy check: `ls web_ui/frontend/out/index.html` exists before `go build`.

## §6 Director returns 404 / no servers for object

Definitions: an "ad" (advertisement) is the JSON registration an origin/cache POSTs to the
director; a "namespace" is a federation path prefix owned via the registry. Full glossary:
**pelican-federation-domain-reference**.

First, classify by the exact response (all shapes verified — first two captured live
2026-07-06, latter two derived from function `processSortedAdsErr` in `director/director.go`):

```
$ curl -sk -w '\nHTTP=%{http_code}\n' https://<director>/api/v1.0/director/object/demo/hello.txt
```

| HTTP | `msg` contains | Meaning | Next step |
|---|---|---|---|
| 429 | `director just restarted, try again shortly` | Director up < 5 min (function `inStartupSequence` in `director/director.go`) and no ad yet matches | Wait/retry; if persists past 5 min it becomes a real 404 |
| 404 | `No sources found for the requested path: no origins found for the requested namespace` | No origin ad matches any prefix of the path | Steps 1–3 below |
| 405 | `Discovered sources for the namespace, but none support the request` | Ads exist but capability mismatch (e.g. PUT to read-only, no `DirectReads`) | Check `capabilities` in the ad (step 1) |
| 404 | `No sources reported possession of the object ... Are you sure it exists?` | Namespace matched; origins stat'ed; object absent | Object path typo, or object really missing at origin |
| 404 | `No caches can fulfill this request and no fallback origins with the 'DirectReads' capability` | Caches all gone and origin forbids direct reads | Check cache ads; `Origin.EnableDirectReads` |

**Step 1 — is the ad present?** (public endpoint, no auth):

```
$ curl -sk https://<director>/api/v1.0/director_ui/servers
[]                      # <-- nothing advertised (captured live)
```

Healthy output is a JSON array of objects shaped like (fields from `listServerResponse`
in `director/director_ui.go`):

```json
[{"name":"my-origin","type":"Origin","url":"https://my-origin:8443",
  "webUrl":"https://my-origin:8444","healthStatus":"...","filtered":false,
  "filteredType":"","fromTopology":false,
  "namespacePrefixes":["/demo"],"capabilities":{"PublicReads":true,"DirectReads":true,"...":"..."}}]
```

- Ad missing → step 2. Ad present with `"filtered": true` → downtime/filter (§8).
- Ad present, namespace listed, still 404 → longest-prefix gotcha below.
- Also useful: `curl -sk https://<director>/api/v1.0/director/listNamespaces` for the
  namespace-level view.

**Step 2 — is the namespace registered and approved?** Against the registry:

```
$ curl -sk https://<registry>/api/v1.0/registry           # list all registrations
[]                                                        # captured live: empty registry
$ curl -sk -X POST -H 'Content-Type: application/json' \
    -d '{"prefix":"/demo"}' https://<registry>/api/v1.0/registry/checkNamespaceStatus
{"status":"error","msg":"The namespace /demo does not exist in the registry"}   # HTTP 400
```

Healthy: `{"approved":true}` HTTP 200. `{"approved":false}` → pending admin approval
(when `Registry.RequireOriginApproval`/`RequireCacheApproval` is on); the director then
rejects the ad with HTTP 403 `{"approval_error": true, "error": "... was not approved by an
administrator ..."}` (see registration handling in `director/director.go`), and the origin
logs `XRootD server advertise failed ...` (function `doAdvertise` in `launcher_utils/advertise.go`).

**Step 3 — did the ad expire?** TTL mechanics (verified in code):

- Servers stamp each ad with `Expiration = now + Server.AdLifetime` (default **10m**,
  hidden param; method `Initialize` on `ServerBaseAd` in `server_structs/director.go`).
- The director caches the ad until that expiration; if an ad carries none it falls back to
  `Director.AdvertisementTTL` (default **15m**; function `recordAd` in `director/cache_ads.go`).
- Servers re-advertise every `Server.AdvertisementInterval` (default **1m**), auto-clamped
  to ≤ 1/3 of AdLifetime (function `LaunchPeriodicAdvertise` in `launcher_utils/advertise.go`).
- So: heartbeats stop → the server vanishes from redirects after ≤ 10 min, with NO error
  on the director side. Confirm on the origin/cache side per §8.

**Longest-prefix matching gotchas** (function `getAdsForPath` in `director/sort.go`):

- Prefixes are compared with a trailing `/` appended, so `/foo` does not match `/foobar`.
- The LONGEST matching prefix wins exclusively. If `/demo/sub` is exported read-only by
  origin B, a PUT to `/demo/sub/x` gets 405 even though origin A exports writable `/demo`.
- Filtered/downtime servers are skipped BEFORE matching — a namespace served only by a
  filtered server behaves as unregistered (404, not "in downtime").
- At equal prefix length, Pelican origins beat Topology(OSG)-sourced origins.

Healthy final answer is HTTP 307 with `Location` plus a ranked
`Link: <https://cache1/...>; rel="duplicate"; pri=1; depth=N, ...` header.

**Local reproduction sandbox** (director+registry only — no XRootD needed; this is how the
curl outputs above were captured; runs fine on macOS):

```
go build -tags server -o /tmp/pelican-server ./cmd
SANDBOX=$(mktemp -d)
PELICAN_CONFIGBASE=$SANDBOX PELICAN_SERVER_HOSTNAME=localhost \
PELICAN_SERVER_WEBPORT=19710 PELICAN_FEDERATION_DISCOVERYURL=https://localhost:19710 \
PELICAN_TLSSKIPVERIFY=true /tmp/pelican-server serve --module director,registry \
  &> $SANDBOX/serve.log &
# liveness (public):
curl -sk https://localhost:19710/api/v1.0/health
# {"message":"Web Engine Running. Time: ..."}
```

(TLSSkipVerify here is a throwaway local sandbox; committed tests must never set it — rule
owned by **pelican-testing-and-qa**.) MaxMind absence is non-fatal: you'll see
`Failed to download GeoIP database! Will not be available` and geo-sorting degrades.
A full fed-in-a-box (`--module director,registry,origin,cache`) additionally needs XRootD.

## §7 401/403 on transfer — token triage chain

Definitions of profiles/scopes/authfile/scitokens.cfg: **pelican-federation-domain-reference**.

**Step 0 — who rejected you?**

- **401 from the DIRECTOR** with header `WWW-Authenticate: Bearer error="invalid_token",
  error_description="token has expired"` → the director pre-checks bearer-token expiry with
  a ~10 s grace for clock skew (function `validateClientToken` in `director/director.go`).
  Your token is expired, `exp≤iat` malformed, or your clock is skewed.
- **403/401 from the ORIGIN/CACHE data port** → XRootD's scitokens plugin rejected the
  token: wrong issuer, wrong scope, wrong path, or namespace requires a token you didn't send.

**Step 1 — decode the token** (no in-repo verifier: `pelican-server origin token verify`
EXISTS but returns `Token verification not yet implemented` — function `verifyToken` in
`cmd/origin_token.go`, main 2026-07-06). Use base64 (executed):

```
$ echo "$TOKEN" | cut -d. -f2 | python3 -c "import sys,base64,json; s=sys.stdin.read().strip(); print(json.dumps(json.loads(base64.urlsafe_b64decode(s+'='*(-len(s)%4))),indent=1))"
{ "aud": ["test"], "exp": 1783359429, "iat": 1783358229,
  "iss": "https://localhost:19710", "scope": "storage.read:/", "sub": "debug", "wlcg.ver": "1.0" }
```

Check, in order: `exp` in the future? `iss` = the issuer the namespace expects? `scope`
grants the verb (`storage.read`/`storage.create`/`storage.modify` for WLCG profile;
`read`/`write` for scitokens2)? Scope PATHS are relative to the namespace prefix — a token
for object `/demo/data/f.txt` in namespace `/demo` needs `storage.read:/data/f.txt`
(or a parent like `storage.read:/`), NOT `storage.read:/demo/...`.

**Step 2 — what does the namespace require?** The director tells you in redirect headers:

```
$ curl -skI https://<director>/api/v1.0/director/object/<path>
X-Pelican-Namespace: namespace=/demo, require-token=true, collections-url=...
X-Pelican-Authorization: issuer=https://...     (when auth required)
X-Pelican-Token-Generation: ...                 (token-issuance metadata)
```

`require-token=false` + your 403 → you hit the wrong server URL or the ad's capabilities
changed. `require-token=true` → compare `issuer=` against your token's `iss`.

**Step 3 — what did the server actually load?** On the origin/cache host, the Go process
generates XRootD's auth config into RunLocation (§10 for paths):

- `authfile-{origin,cache}-generated` — unauthenticated ACLs (public namespaces)
  (function `EmitAuthfile` in `xrootd/authorization.go`)
- `scitokens-{origin,cache}-generated.cfg` — per-issuer config for token validation
  (function `EmitScitokensConfig` in `xrootd/authorization.go`)

If your issuer/prefix is missing there, the origin's exports/issuer config is wrong — not
the client's token.

**Step 4 — mint a known-good token to bisect** (executed 2026-07-06):

```
# with the origin's signing key (server binary, on the origin host or sandbox):
$ pelican-server origin token create --issuer https://<issuer> --audience <aud> \
    --subject debug --scope storage.read:/ 
eyJhbGciOiJFUzI1NiIsImtpZCI6...
# or client-side, issuer auto-discovered via the director:
$ pelican token create --read pelican://<federation>/<namespace>/<path>
```

If the minted token works and the original doesn't, diff the two decoded payloads.

## §8 Server silently dropped from redirects

There is no error anywhere by design — expiry is silent (§6 step 3 for TTL math). Confirm
and localize:

1. **Director view**: `curl -sk https://<director>/api/v1.0/director_ui/servers` — ad gone
   entirely, or present with `"filtered": true` / a `filteredType` (downtime)?
2. **Origin/cache view**: grep its log for the heartbeat:
   - healthy: `XRootD server advertise successful` (debug level)
   - failing: `XRootD server advertise failed (duration ...): <why>` (warning) — the reason
     (403 approval, TLS, DNS, clock skew on the ad JWT) is in `<why>`; component health
     flips to critical (function `doAdvertise` in `launcher_utils/advertise.go`).
3. **Metrics** (director, `/metrics`, requires token unless `Monitoring.MetricAuthorization=false`;
   metric names frozen — see **pelican-architecture-contract**):
   - `pelican_director_server_count{server_type=...,from_topology=...}` — gauge of live ads
   - `pelican_director_advertisements_received_total{server_name=...,status_code=...}` —
     rejected ads show non-2xx `status_code`
   - `pelican_director_rejected_advertisements` — rejection counter
4. Interval sanity: if someone set `Server.AdvertisementInterval` > 1/3 of
   `Server.AdLifetime`, Pelican clamps it down and logs
   `The advertise interval ... is set to above 1/3 of the ad lifetime. Decreasing it to ...`.
   If instead AdLifetime was shrunk below ~3× the interval without that log appearing
   (e.g. set via web UI at runtime), ads can expire between heartbeats — flapping presence.

## §9 SQLite `database is locked` / SQLITE_BUSY

One-liner history (full incident narrative: **pelican-failure-archaeology**): Pelican's
SQLite DSN once used mattn-style `_journal_mode=WAL` params which the actual driver
(glebarez → modernc.org/sqlite) SILENTLY IGNORES — DBs ran in rollback-journal mode and
writers blocked readers. Fixed by commit `f214d11e` ("Use correct DSN parser form"):
`_pragma=journal_mode(WAL)` etc.; retries added in `d715eb78`; the separate scitokens-cpp
JWKS cache is WAL-flipped pre-launch by `4ccd3c73` (function `enableSqliteWAL` in
`xrootd/xrootd_config.go`).

Triage:

- Opening a Pelican DB in new code? Use `database/utils.SQLiteDSN(path)` — never hand-roll
  the DSN. Current pragmas: `busy_timeout(5000)`, `journal_mode(WAL)`, `foreign_keys(1)`
  (function `SQLiteDSN` in `database/utils/utils.go`).
- Seeing it at runtime? Check which file: `pelican.sqlite` (server DB), the client-agent DB
  (`~/.pelican/client-agent.db`), or `$XDG_CACHE_HOME/scitokens/scitokens_cpp.sqllite`
  (XRootD's, note the `sqllite` spelling). For the last one on branches older than the WAL
  flip (pre-2026-07 main), the symptom is spurious `Failed to deserialize SciToken: Unknown
  error` under load.
- Long-running external readers (sqlite3 shell left open) hold WAL read marks — close them.

## §10 XRootD won't start / dies at launch

Pelican generates XRootD's config, then supervises the daemon; XRootD's own output is
forwarded into Pelican's log tagged `daemon=<name>` at INFO level (function
`ForwardCommandToLogger` in `daemon/launch_unix.go`). So the XRootD death reason IS in the
Pelican log — filter for it: `grep 'daemon=' <log>`.

**Where the generated config lands** — RunLocation:

| Server | Param | Default (root) | Default (non-root) |
|---|---|---|---|
| Origin | `Origin.RunLocation` | `/run/pelican/xrootd/origin` | `$XDG_RUNTIME_DIR/pelican/origin` (temp dir if unset) |
| Cache | `Cache.RunLocation` | `/run/pelican/xrootd/cache` | `$XDG_RUNTIME_DIR/pelican/cache` |

(`Xrootd.RunLocation` is deprecated but still honored.) Contents worth reading when
diagnosing: `xrootd.cfg` (the rendered config — start here), `scitokens-*-generated.cfg`,
`authfile-*-generated`, `copied-tls-creds.crt`, `ca-bundle.crt`, `xrootd.pid`.
To layer custom XRootD directives use `Xrootd.ConfigFile` (absolute path, appended via
XRootD's `continue` mechanism) — do not edit the generated file; it's rewritten.

Checklist:

1. **Version gate**: launch calls function `CheckXrootdVersion` (via `CheckXrootdEnv` in
   `xrootd/xrootd_config.go`) → error `Please install XRootD version 5.8.2 or later` or a
   too-old version message. `xrootd -v` to confirm. NEVER casually change the pin — policy
   in **pelican-change-control**.
2. **Port conflicts**: data port is `Origin.Port` (default **8443**) or `Cache.Port`
   (default **8442**) — both `0` = random; web port `Server.WebPort` (default **8444**).
   Pelican's own bind failure looks
   like `Error: listen tcp 0.0.0.0:8444: bind: address already in use` (captured live);
   XRootD's port failure appears in `daemon=xrootd` lines. `lsof -nP -iTCP:8443 -sTCP:LISTEN`
   to find the holder.
3. **Unprivileged transplant path**: with `Server.DropPrivileges`, only the FIRST config
   write happens as root; later regenerations (cert renewal, scitokens refresh) are pushed
   into the xrootd-owned directory through the xrdhttp-pelican plugin ("transplant", see
   comments in function `writeScitokensConfiguration` in `xrootd/authorization.go` and
   `copyXrootdCertificates` in `xrootd/xrootd_config.go`). Symptom of breakage: config
   changes apply after a full restart but not live.
4. **XRootD component verbosity**: `Logging.Origin.{Xrootd,Scitokens,Http,Ofs,Oss,Cms,Xrd}`
   and `Logging.Cache.{Http,Ofs,Pfc,Pss,PssSetOpt,Scitokens,Xrd,Xrootd}` params. Changing these
   REQUIRES an XRootD restart (authoritative list in `logging/xrootd.go`). Exception:
   `Logging.Cache.Lotman` is deliberately EXCLUDED (comment in `logging/xrootd.go`) — changing
   it does NOT force an XRootD restart.

## §11 Cross-cutting traps (each verified; stories live with their owners)

- **Closed-issue TODOs lie.** A 2026-07 sweep found 12 of 13 issue numbers cited in code
  comments are CLOSED while the annotated code is unchanged (only #3107 OPEN). Spot-verified
  2026-07-06: #1391 CLOSED 2025-10-02, yet its TODO and both `healthTestUtils`/`statUtils`
  maps remain in `director/director.go`. Never treat "issue closed" as "code fixed".
- **`dist/` contents are stale build artifacts.** Not cleaned automatically; may contain a
  months-old snapshot from a different branch (check `dist/metadata.json` → `"tag"`). Trust
  only what you just built.
- **`git describe` on main reports ancient versions.** Release tags are applied on release
  branches that never merge back: `git describe --tags main` → `v7.19.4-1894-g289fd41b`
  (verified 2026-07-06). Snapshot builds from main therefore self-report `7.19.4-next`.
  On a release branch (e.g. `v7.25.x`) it describes correctly. See **pelican-build-and-env**.
- **gh defaults to the wrong remote.** In typical clones `origin` is a personal fork;
  ALWAYS pass `-R PelicanPlatform/pelican` to `gh` (`gh pr list -R PelicanPlatform/pelican`).
- **Race detector runs nightly only** (§4 note). A green PR proves nothing about races.
- **Prometheus metric names and director API JSON fields are frozen ABI** — when debugging
  leads you to "fix" a metric name (even the `_toal` typo) or rename a JSON field: don't.
  Contract in **pelican-architecture-contract**.

## §12 Raising log verbosity, finding logs, dumping effective config

**Static log level** (all components): `Logging.Level` — `trace|debug|info|warn|error|fatal|panic`
(server default `info`, client default `warn`). Set via config file, or env
`PELICAN_LOGGING_LEVEL=debug`, or client flag `-d/--debug`. Logs go to stderr/stdout unless
`Logging.LogLocation` (a filename) is set; under systemd use `journalctl` (units in
**pelican-run-and-operate**). XRootD child output is folded into the same stream tagged
`daemon=<name>` (§10).

**Temporary runtime log level** (no restart, auto-reverts; main 2026; managed by
`logging/level_manager.go`):

```
pelican-server server set-logging-level debug 5m -s https://<server>:8444 [-t /path/to/admin-token]
# scoped variant for XRootD params (this one queues until XRootD restarts):
pelican-server server set-logging-level debug 2m -s https://<origin>:8444 --param Logging.Origin.Xrootd
```

This POSTs to `POST /api/v1.0/logging/level` (admin token; also `GET` to list active
changes and `DELETE /api/v1.0/logging/level/<changeId>` — registered in `web_ui/ui.go`).
Response includes `changeId`, `endTime`, and `requiresRestart` (true for `Logging.*.Xrootd`-class
params, per `logging/xrootd.go`).

**Dump effective config with provenance** (all executed 2026-07-06):

```
$ pelican config dump                 # every param, YAML (or -o json)
$ pelican config summary              # only params differing from defaults
$ pelican config get Logging.Level -v # value + per-key source
logging.level: "error"
    # source: env PELICAN_LOGGING_LEVEL
$ pelican config describe Server.WebPort   # docs for one param
```

Sources shown by `-v`: config-file path, `env <VAR>`, `web-config <path>`, `default`,
`dynamic`. NOTE: `config get -v` provenance (SourceTracker) exists on main only, not on the
`v7.25.x` release branch. Env var naming rule: `Section.Param` → `PELICAN_SECTION_PARAM`.

**Health endpoints** (captured live): `GET /api/v1.0/health` — public liveness
(`{"message":"Web Engine Running. ..."}`); `GET /api/v1.0/metrics/health` — component
health, admin-only unless `Server.HealthMonitoringPublic=true` (default false); unauthenticated
→ `{"status":"error","msg":"Authentication required to perform this operation"}` HTTP 401.

## Provenance and maintenance

Facts verified 2026-07-05/06 against `main@289fd41b` (checkout extracted read-only via
`git archive main`; executed outputs produced on macOS arm64, go1.25.0, no XRootD installed;
live curl outputs from a locally launched `pelican-server serve --module director,registry`).
Where the `v7.25.x` release branch differs it is noted inline (build tags, SourceTracker).

Re-verification one-liners for every volatile fact:

| Volatile fact | Re-verify with (repo root) |
|---|---|
| cmd/ is the only client/server-tagged dir; counts 67/36/87 | `git grep -l 'go:build.*\b\(client\|server\)\b' -- '*.go' \| xargs -n1 dirname \| sort -u` and the three `-list` commands in §2 |
| `MinXrootdVersion = "5.8.2"` | `grep -n 'MinXrootdVersion =' xrootd/version.go` |
| XRootD-not-found error string | `grep -n 'not found in PATH' xrootd/version.go` |
| Fed-test packages needing XRootD (12 dirs) | `git grep -l fed_test_utils -- '*_test.go' \| xargs -n1 dirname \| sort \| uniq -c` |
| Generated-and-committed file list (§4 row 1) | `git ls-files param/parameters.go param/parameters_struct.go config/parameter_defaults.go token_scopes/token_scopes.go error_codes/error_codes.go features/features.go \| wc -l` → 6 |
| `make validate-parameters` still missing | `grep -c validate Makefile` (expect no target) vs AGENTS.md `grep -n validate-parameters AGENTS.md` |
| Director routes (`/object`, `/origin`, `director_ui/servers`, `listNamespaces`) | `grep -nE 'GET\(|POST\(' director/director.go director/director_ui.go` |
| Registry routes (`/api/v1.0/registry`, `checkNamespaceStatus`) | `grep -nE 'registryAPI\.(GET\|POST)' registry/registry.go` |
| Error taxonomy strings (429/404/405) | `grep -n 'director just restarted\|No sources found\|none support the request\|reported possession' director/director.go` |
| Defaults: AdLifetime 10m / AdvertisementInterval 1m / AdvertisementTTL 15m / WebPort 8444 / Origin.Port 8443 | `grep -A6 '^name: Server.AdLifetime' docs/parameters.yaml` (etc. per param) |
| Heartbeat clamp to 1/3 lifetime | `grep -n 'AdLifetime.GetDuration()/3' launcher_utils/advertise.go` |
| Director metrics names (§8) | `grep -n 'Name: "pelican_director' metrics/director.go` |
| SQLite DSN pragmas | `grep -n '_pragma' database/utils/utils.go` |
| WAL commits still in history | `git log --oneline --grep='SQLITE_BUSY\|DSN parser\|WAL' \| head` (expect `f214d11e`, `d715eb78`, `4ccd3c73`) |
| RunLocation defaults | `grep -A9 '^name: Origin.RunLocation' docs/parameters.yaml` |
| RunLocation file names | `grep -n 'authfile-\|scitokens-.*-generated\|copied-tls-creds' xrootd/authorization.go xrootd/launch.go` |
| `origin token verify` still unimplemented | `grep -n 'not yet implemented' cmd/origin_token.go` |
| set-logging-level cmd + `/api/v1.0/logging/level` | `grep -n 'set-logging-level' cmd/logging_set_level.go; grep -n 'logging' web_ui/ui.go \| grep level` |
| `config get -v` provenance main-only | `git grep -c SourceTracker main -- config/ ; git grep -c SourceTracker v7.25.x -- config/` (second returns nothing) |
| Race detector nightly-only | `grep -n race_detection .github/workflows/*.yml` (only scheduled files set `true`) |
| Closed-TODO spot checks | `gh issue view 1391 -R PelicanPlatform/pelican --json state`; `gh issue view 3107 -R PelicanPlatform/pelican --json state` |
| `git describe` trap | `git describe --tags main` (expect `v7.19.4-*` until tags policy changes) |
| Web UI placeholder-only embed | `git ls-files web_ui/frontend/out` → `placeholder` |
| X-Pelican-* headers | `grep -n 'X-Pelican-Namespace\|X-Pelican-Authorization\|X-Pelican-Token-Generation' director/director.go` |
