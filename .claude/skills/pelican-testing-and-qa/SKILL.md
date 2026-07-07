---
name: pelican-testing-and-qa
description: Load when writing, running, or debugging tests in the Pelican repo — symptoms include "go test ./... passes but CI fails", "build constraints exclude all Go files", "XRootD binary not found in PATH", tests that pass locally but break in CI, adding a unit/fed/e2e/frontend test, reviewer pushback on time.Sleep or TLSSkipVerify, ResetTestState/NewFedTest usage, gotestsum/junit CI questions, or race-detector failures that only appear in the nightly run. Contains the build-tag matrix, environment matrix (laptop vs container), isolation idioms, fed_test_utils.NewFedTest anatomy, the full CI workflow table, the PR evidence bar, and verified copy-paste test skeletons.
---

# Pelican Testing and QA

All commands in this document run from the repository root unless stated otherwise.
"Fed test" = a test that spins up a full in-process Pelican federation (origin + cache + director + registry + broker) via `fed_test_utils.NewFedTest`. For federation concepts and jargon, see pelican-federation-domain-reference.

## When to use this skill

- You are about to run tests and need to know which tags/platform they require.
- `go test ./...` passes but you suspect (correctly) that it skipped things.
- A test fails with `XRootD binary not found in PATH`.
- You are adding a test (unit, fed, e2e, frontend) and need the correct file placement, tags header, and skeleton.
- You need to know exactly what CI will run against your PR, and why the race detector did not run.
- A reviewer rejected `time.Sleep`, `TLSSkipVerify`, or a missing `ResetTestState` and you need the sanctioned pattern.
- You need the evidence bar to prove a bug fix.

When NOT to use:

- Measuring flakiness, profiling, or race-hunting techniques → pelican-diagnostics-and-tooling.
- PR gating policy, backports, XRootD version-bump policy → pelican-change-control.
- Toolchain install, goreleaser, `make web-build` environment problems → pelican-build-and-env.
- Parameter system (`param.X.Set`, viper precedence, add-a-param) → pelican-config-and-flags.
- serverAds locking / launch-order invariants your test may be probing → pelican-architecture-contract.
- Proof recipes for shutdown/goroutine races → pelican-concurrency-and-shutdown-proofs.
- Running servers for real (ports, config layout, systemd) → pelican-run-and-operate.

## 1. Build-tag matrix: `go test ./...` silently skips tests

Go build tags (`//go:build client`, `//go:build server`) gate which files compile. As of 2026-07-05, **every** `client`/`server`-tagged Go file lives in `cmd/` (99 files, including 21 `_test.go` files). AGENTS.md says "many packages" use these tags; ground truth is they are concentrated in `cmd/`, but the consequence is the same: without tags, the whole `cmd` package — 87 tests — vanishes.

The silent-skip mechanism, demonstrated (executed 2026-07-05):

```
$ go test -list '.*' ./cmd/
# github.com/pelicanplatform/pelican/cmd
package github.com/pelicanplatform/pelican/cmd: build constraints exclude all Go files in .../cmd
FAIL    github.com/pelicanplatform/pelican/cmd [setup failed]
```

Explicit path → hard error. But the wildcard hides it:

```
$ go list ./... | grep 'pelican/cmd$'
(no output — cmd is silently dropped; only cmd/config_printer appears)
```

So `go test ./...` reports all-green while running zero `cmd` tests. Test counts by tag set (executed 2026-07-05):

| Command | `cmd` tests compiled |
|---|---|
| `go test -list '.*' ./cmd/` (no tags) | 0 (build error; silently skipped under `./...`) |
| `go test -tags client -list '.*' ./cmd/` | 67 |
| `go test -tags server -list '.*' ./cmd/` | 36 |
| `go test -tags "client server" -list '.*' ./cmd/` | 87 |

(client + server counts overlap because some files are `//go:build client || server`.)

**Rules:**

- Widest local run (superset of both CI legs, per AGENTS.md): `go test -tags "client server" ./...`
- CI runs two separate legs: `-tags=client` and `-tags=server` (never combined) — see §7.
- Packages outside `cmd/` compile identically under both legs; the legs differ only in `cmd/` and in OS tags.
- OS tags also gate tests: 93 test files are `//go:build !windows`; 6 are `linux`-only; 14 are `linux && !ppc64le` (all of `lotman/`).

## 2. Environment matrix: what runs where

| Test class | Plain laptop (no XRootD) | macOS + `github_scripts/osx_install.sh` | pelican-test / pelican-dev container only |
|---|---|---|---|
| Pure unit tests (most packages) | yes | yes | yes |
| `cmd/` tests (with tags) | mostly (a few `t.Skip` when `xrootd` not in PATH, e.g. `TestObjectGetDirectFlag` in `cmd/object_get_test.go`) | yes | yes |
| Fed tests (`NewFedTest`, ~60 files across 13 packages) | **FAIL, not skip** (see below) | yes | yes |
| Multiuser tests (`SkipUnlessTestUsers`: users alice/bob/carol/dave, group `pelican_shared`) | linux: skip; macOS: never compiles (callers are `//go:build linux`) | never compiles on macOS | yes |
| Privileged tests (`SkipUnlessPrivileged`: CAP_SETUID/SETGID in effective set — container runs as root) | linux non-root: skip; macOS: never compiles | never compiles on macOS | yes |
| HTCondor plugin tests (`condor_master` in PATH) | skip | skip | yes (condor installed in image) |
| `lotman/` tests (`//go:build linux && !ppc64le`) | never compiles on macOS | never compiles on macOS | yes |
| Windows | client-tagged tests only; 93 `!windows` test files excluded | n/a | n/a |

- `osx_install.sh` builds XRootD (from the PelicanPlatform/xrootd fork) and scitokens-cpp from source, with CMake pinned to 3.31.8. Details and pin locations → pelican-build-and-env.
- The pelican-test image (`images/Dockerfile`, `pelican-test` stage) installs gcc/git/make, installs HTCondor (then force-removes the pelican RPMs condor drags in), creates users alice/bob/carol/dave, and creates group `pelican_shared` with alice a member and bob deliberately not.
- Graceful skips exist only where authors added them (63 `t.Skip` call sites: missing sshd, rclone, condor_master, xattr support, test users).

**Fed tests FAIL, not skip, without XRootD.** Exact behavior, executed 2026-07-05 on a Mac with no `xrootd` in PATH:

```
$ go test -tags server ./e2e_fed_tests/ -run TestDirectorMetadataHosting -count=1
...
    Error:  Received unexpected error:
            XRootD binary not found in PATH. Please install XRootD version 5.8.2 or later. See installation instructions at https://xrootd.org/
...
FAIL    github.com/pelicanplatform/pelican/e2e_fed_tests    0.913s
```

The error comes from `CheckXrootdVersion` in `xrootd/version.go` (`MinXrootdVersion = "5.8.2"`), called during `launchers.LaunchModules`. If you see this error: you are on a machine without XRootD → either install it (pelican-build-and-env) or run only non-fed packages. Do NOT "fix" it by adding a skip to `fed_test_utils` — CI relies on these failing loudly.

Packages that import `fed_test_utils` (all require XRootD; counts = files, 2026-07-05): e2e_fed_tests (30), local_cache (7), cmd (6), director (3), client_agent (3), client (3), origin_serve (2), origin (2), xrootd (1), metrics (1), cache (1), client_agent/apiclient (1), fed_test_utils itself (1).

## 3. The isolation idiom: ResetTestState + test_utils

Pelican keeps substantial process-global state (viper config, param callbacks, origin exports, logging hooks, a global DB handle). Tests that skip cleanup poison every later test in the package. The canonical prologue — used at the top of nearly every stateful test:

```go
t.Cleanup(test_utils.SetupTestLogging(t))
server_utils.ResetTestState()
t.Cleanup(server_utils.ResetTestState)
```

Reset at start (defend against a previous test's leftovers) AND at cleanup (don't be the leaker). ~835 occurrences of `ResetTestState` across 126 `_test.go` files (2026-07-05). Some older tests use `defer server_utils.ResetTestState()` instead of `t.Cleanup` — equivalent.

Function `ResetTestState` in `server_utils/server_utils.go` resets: viper config (`config.ResetConfig`), param callbacks (`param.ClearCallbacks`), registered reset hooks for xrootd/posixv2/ssh-backend/broker/pelican-url/web-UI state, origin exports, log flushing and the temporary log-level manager, the cached server base-ad (`sync.Once`), director endpoints, and shuts down the shared database.

### test_utils helpers (package `test_utils`, file `test_utils/utils.go` unless noted)

| Helper | One-line usage |
|---|---|
| `TestContext(context.Background(), t)` | Returns `(ctx, cancel, egrp)` — a context bound to the test deadline plus an errgroup stored in the context under `config.EgrpKey`; the standard way to give launched goroutines a lifecycle. |
| `GenerateJWK()` | Returns an RSA private `jwk.Key`, its public `jwk.Set`, and the JWKS JSON string — for signing test tokens. |
| `GenerateJWKS()` | Returns a JWKS JSON string for a fresh ECDSA P-256 key. |
| `RegistryMockup(t, prefix)` | `httptest.Server` dummy registry that answers only jwks_uri location lookups for one prefix; auto-closed via `t.Cleanup`. |
| `InitClient(t, map[param.Param]any{...})` | Resets config, points `ConfigBase` at `t.TempDir()`, applies typed param settings, then `config.InitClient()` — the client-test bootstrap. |
| `GetUniqueAvailablePorts(n)` | Returns n unique free ports. Documented race: the port can be taken between return and your bind. Prefer port 0 auto-assign where possible. |
| `MockFederationRoot(t, fInfo, kSet)` | Stands up a mock federation discovery endpoint + keys. **Caution: internally sets `TLSSkipVerify(true)`** — fine for unit tests against httptest self-signed certs; never combine mentally with the fed-test TLS rule in §4. |
| `MockIssuer(t, kSet)` | Mock token issuer serving `/.well-known/openid-configuration` and `/.well-known/issuer.jwks`; returns its URL. |
| `SetupTestLogging(t)` | Captures logrus output per-test (emitted only on failure); returns a cleanup func — canonical call is `t.Cleanup(test_utils.SetupTestLogging(t))`. `SetupGlobalTestLogging()` is the `TestMain` variant. |
| `WriteBigBuffer(t, fp, sizeMB)` | Writes ≥ sizeMB MB of filler to an `io.WriteCloser` (and closes it); returns bytes written. For transfer tests. |
| `ChownToDaemon(t, paths...)` | Chowns paths to the XRootD daemon user; no-op when not root. |
| `GetTmpStoragePrefixDir(t)` | Temp dir with 0777 perms so the XRootD daemon user can read/write an origin export. |
| `SkipUnlessPrivileged(t)` (`test_utils/skip_privileged_linux.go`, linux-only) | Skips unless the process has CAP_SETUID and CAP_SETGID — gate for multiuser origin tests. |
| `SkipUnlessTestUsers(t, "alice", ...)` (same file) | Skips unless the named accounts resolve — gate for tests needing the container's alice/bob/carol/dave. |

### mock/ package

Package `mock` (`mock/mockups.go`) provides httptest mockups of **external** OSDF services — `MockOSDFDiscovery` (hard-coded osg-htc.org discovery JSON) and a topology mockup backed by embedded `mock/resources/topology-namespace.json` — so unit tests never touch the live federation. Use it whenever a test would otherwise resolve `osg-htc.org`.

## 4. fed_test_utils.NewFedTest anatomy

Function `NewFedTest` in `fed_test_utils/fed.go` builds a complete in-process federation. What it does, in order:

1. `director.ResetState()`; applies your origin YAML (or the embedded `fed_test_utils/resources/default.yaml`).
2. **TEST_POSIXV2 swap**: if env `TEST_POSIXV2=1`, rewrites `posix` → `posixv2` in the origin config (two-step replace to avoid `posixv2v2`). Not set anywhere in CI (verified 2026-07-05) — it is a manual local knob for exercising the pure-Go origin data plane.
3. `test_utils.TestContext` + a nested shutdown context for director advertise/discovery.
4. Temp dir for everything; **cleanup order is load-bearing** — quoted verbatim from fed.go:

   > Explicitly run tmpPath cleanup AFTER cancel and egrp are done -- otherwise we end up with a race condition where removing tmpPath might happen while the server is still using it, resulting in "error: unlinkat \<tmpPath\>: directory not empty"

   The `t.Cleanup` body is: `cancel()` → `egrp.Wait()` → `os.RemoveAll(tmpPath)` → `server_utils.ResetTestState()`. Preserve this order in anything you write that mimics it.
5. Enables modules: Broker, Cache, Origin, Director, Registry, LocalCache. (An in-code TODO notes cache startup isn't sequenced for immediate downloads; unit tests use the origin path.)
6. Sets ~40 params: all ports 0 (OS-assigned), every SQLite DB (registry/director/origin/cache/server) in `t.TempDir()`, web UI disabled, XRootD log levels pinned low so back-to-back fed tests don't flood output, `Xrootd.ShutdownTimeout=0` so restarts don't stall tests.
7. **TLS verification stays ON** — quoted verbatim from fed.go:

   > Do NOT skip TLS verification in tests.  This has hidden *real bugs* in the past and there should be no need since we generate CA certs when needed.  If you think this should be changed, talk to the rest of the dev team first.

   `param.TLSSkipVerify.Set(false)` is explicit. Reviewers reject fed tests that flip it. (Unit tests using httptest self-signed servers are a different situation; see §3 MockFederationRoot.)
8. **Director start time faked 6 minutes into the past** (`director.SetStartupTime(time.Now().Add(-6*time.Minute))`) — a freshly started director returns HTTP 429 for unknown prefixes during its startup grace window; without this, every fed test would begin with 429s.
9. Writes hello_world.txt into each export's storage dir, runs your optional `originSetup` hooks (files that must exist before XRootD starts), stands up an httptest federation-discovery server using the generated CA cert (not httptest's self-signed one), then `launchers.LaunchModules`, waits on `/api/v1.0/health`, and mints a WLCG read token into `ft.Token`.

Returned `FedTest` fields: `Ctx`, `Egrp`, `Exports` (with real `StoragePrefix` temp paths), `Token`, `Pids` (XRootD child PIDs), `AdvertiseCancel`.

How to write a new fed test → recipe in §10.2.

## 5. The no-sleep rule

AGENTS.md (Testing, item under "Code Style and Conventions") — quoted verbatim:

> Tests should *avoid* arbitrary sleeps (`time.Sleep` calls will be rejected) for a condition to occur as they lead to unreliable tests Instead, use `require.Eventually` or similar to wait for a specific condition to become true.

This is **review-enforced, not linted**: `.golangci.yaml` enables only `misspell` beyond defaults (staticcheck explicitly disabled) and has no sleep-forbidding rule. Human reviewers enforce it harder than any linter would. ~98 `time.Sleep` matches remain in `_test.go` files (2026-07-05) — grandfathered legacy; do not add to them.

The pattern — poll a condition with a deadline and interval, always with a failure message. Real examples (all present at main@289fd41b):

- `director/director_advertise_test.go` — wait for a peer director ad to appear, then disappear after shutdown:

```go
require.Eventually(t, func() bool {
    for _, ad := range server_utils.GetDirectorAds() {
        if ad.AdvertiseUrl == ts.URL {
            return true
        }
    }
    return false
}, 10*time.Second, 50*time.Millisecond,
    "fake director should appear in directorEndpoints after initial contact")
```

- `e2e_fed_tests/cache_stats_test.go` — wait for XRootD to create a stats file, then for a Prometheus metric to move:

```go
assert.Eventually(t, func() bool {
    _, err := os.Stat(statsFile)
    return err == nil
}, 20*time.Second, 1*time.Second, "Stats file was never created by XRootD plugin")
```

- `e2e_fed_tests/persistent_cache_site_local_test.go` — note its comment that the closure "runs on a separate goroutine": don't call `require.*` (which calls `t.FailNow`) *inside* an Eventually closure; return false and let the outer Eventually fail.

Choosing timeouts: copy the neighborhood convention (10–20s deadline, 50ms–1s poll for fed tests). A generous deadline costs nothing on success; a tight one buys flakes.

## 6. e2e_fed_tests/ and the bash e2e scripts

**Why a separate package** — `e2e_fed_tests/README.md`, verbatim:

> It has been created as its own package to avoid the potential for circular dependencies, and as such no functions here should ever be exported.

and, on go-vs-bash:

> The `github_scripts` directory contains a similar set of CI tests, but it's easier to write rigorous tests in go than it is to write them in bash.

The circular-import problem: `fed_test_utils` imports director/cache/origin, so those packages' own tests cannot import it for cross-component scenarios; `e2e_fed_tests` (package name `fed_tests`, 31 files: 30 `!windows` + 1 `linux`) can.

**Shared binary**: `e2e_fed_tests/main_test.go` builds one `pelican` binary for the whole package via `sync.Once` (`buildOnce`), running `go build -tags client,server -buildvcs=false -o <tmp>/pelican ../cmd`. Tests that need a CLI call the package-private `getPelicanBinary(t)`. These tests run inside the same 15m-per-package CI timeout as everything else.

**Bash e2e** (`github_scripts/`, run only on the CI `pelican-server` Linux leg, after goreleaser builds real binaries): `citests.sh`, `get_put_test.sh`, `stat_test.sh`, `version_test.sh`, `site_local_cache_test.sh`, `cache_availability_test.sh`.

**Network-dependency warning**: `citests.sh` downloads `osdf:///pelicanplatform/test/hello-world.txt` through the **live OSDF federation** (via stashcp/stash_plugin compat paths). If OSDF or that test object is unavailable, this CI step fails with no code change on your side. If only `citests.sh` fails on your PR while go tests pass, check OSDF health before debugging your diff — and see pelican-ecosystem-and-upstreams for where to look/report.

## 7. CI matrix

All test workflows live in `.github/workflows/`. Verified 2026-07-05.

| Workflow | Trigger | Runner / container | What it runs |
|---|---|---|---|
| `test-linux-pr.yml` | `pull_request`, dispatch | ubuntu-latest **inside `hub.opensciencegrid.org/pelican_platform/pelican-test:latest-itb`** | calls `test-linux.yml`, no race |
| `build-and-test.yml` (test job) | push to main, tags `v7+`/`-rc.N`, dispatch | same, but the **freshly built** `pelican-test:TAG` | builds 11 container images, then calls `test-linux.yml` |
| `test-linux.yml` | `workflow_call` only | container from input | two legs: `pelican` (`-tags=client`) and `pelican-server` (`-tags=server`); server leg also runs the §6 bash e2e scripts after a goreleaser snapshot build |
| `test-linux-scheduled.yml` | cron `0 7 * * *` daily | `pelican-test:latest-itb` | `race_detection: true`; then junit flaky analysis |
| `test-macos.yml` | PR, push main/tags, dispatch, call | macos-latest (runs `github_scripts/osx_install.sh` first) | same two legs as Linux, same gotestsum flags |
| `test-macos-scheduled.yml` | cron `0 7 * * *` | macos-latest | race + junit analysis |
| `test-windows.yml` | PR, push main/tags, dispatch, call | windows-latest | **client leg only** (one matrix entry); web UI "build" is a fake — Makefile creates an empty `web_ui/frontend/out/index.html` on Windows |
| `test-windows-scheduled.yml` | cron `0 7 * * *` | windows-latest | race + junit analysis |
| `test-webui-e2e.yml` | PR, push main | `pelican-dev:latest-itb` container | builds `pelican-server`, starts `serve --module ...`, mints an admin token, runs `npx playwright test --project=<service>`. **Only `origin` and `cache` matrix legs are live; `registry` and `director` legs are commented out in the file** (registry "runs alone", director "needs a registry" per the comments) — parked, reason not recorded in-repo. |
| `check-go-generate.yml` | PR/push | ubuntu | `go generate ./...` then fails on non-empty `git diff` — the check that catches forgotten codegen after touching `docs/parameters.yaml` (see pelican-config-and-flags) |

Other PR gates (labels + linked issue, rebase-on-main, golangci-lint v2 + pre-commit, large objects, CodeQL) are policy — see pelican-change-control. One local trap worth knowing here: in `.pre-commit-config.yaml`, the golangci-lint and npm-format hooks are `stages: [pre-push, manual]`, so a plain `git commit` does **not** run them.

**Exact test command** (identical structure on Linux/macOS/Windows; from `test-linux.yml`):

```
make web-build
gotestsum \
  --format pkgname-and-test-fails \
  --hide-summary=output \
  --junitfile junit-<leg>.xml \
  -- \
  -p=4 \
  -timeout=15m \            # 30m when race_detection
  -coverpkg=./... -covermode=count -coverprofile=...   # DROPPED when race_detection
  -tags=<client|server> \
  ./...
```

`-p=4` = four packages in parallel. Per-package timeout 15m (30m under race). Coverage total is posted to the step summary on PRs only.

### Race detection is NIGHTLY ONLY — what that means for you

No PR workflow passes `race_detection: true`; only the three `*-scheduled.yml` workflows do (07:00 UTC daily, `-race`, 30m timeout, coverage dropped). Consequence, and the costliest historical failure class in this repo: **your PR can land a data race or shutdown-ordering bug, CI goes green, and the nightly run flags it hours-to-days later — you get pinged after merge.** Shutdown/goroutine-lifecycle races have repeatedly been caught only by the nightly (incident stories → pelican-failure-archaeology).

Pre-empt it. Before pushing anything that touches goroutines, channels, shutdown paths, or shared maps, run the race detector locally on the touched packages (verified working command, macOS, 2026-07-05):

```
go test -race -count=1 -tags "client server" ./<touched-pkg>/ ./<other-touched-pkg>/
```

Expected output on success: `ok  github.com/pelicanplatform/pelican/<pkg>  1.2s`. On a race: `WARNING: DATA RACE` with two stack traces, and the package fails. Note the pelican-test image installs gcc specifically because the race detector needs cgo (comment in `images/Dockerfile`). Deeper race-hunting technique → pelican-diagnostics-and-tooling.

### The latest-itb container trap

PR tests run inside `pelican-test:latest-itb` — the image built from **main**, not from your PR (a PR cannot push images; no registry credentials). AGENTS.md documents it: "tests run in dev container built from main branch". So a PR that changes container contents (XRootD version, test users, installed packages) is tested against the **old** container and can only pass after a separate image-updating PR merges first. CONTRIBUTE.md ("Pull Requests that Modify Pelican's Dependencies") mandates splitting such changes into two PRs. Process details → pelican-change-control.

### JUnit flaky analysis

Every leg uploads `junit-<leg>.xml`. The scheduled workflows' `analyze-runs` job downloads recent artifacts (`.github/scripts/analyze-junit-results/download_junit_artifacts.sh`) and runs `.github/scripts/analyze-junit-results/analyze_junit_results.py`, appending `test-failure-analysis.md` (a cross-run failure/flake summary) to the workflow step summary. There is no in-repo known-flaky allowlist (verified 2026-07-05); triage is manual. Flaky-hunting methodology → pelican-diagnostics-and-tooling.

## 8. Frontend tests

Working directory: `web_ui/frontend`.

- **Jest unit tests**: `npm test` (script = `jest`, config `jest.config.js`, ts-jest + jsdom, e2e/ excluded). As of 2026-07-05 there is exactly **one** jest test file (`test/index.test.ts`, byte-formatting helpers) and **no CI workflow runs `npm test`** (verified: no jest/npm-test reference in `.github/workflows/`). It is a local-only check — run it if you touch `helpers/` or components it covers.
- **Playwright e2e**: `npx playwright test --project=<origin|cache|director|registry>`. Projects are generated in `playwright.config.ts` from `TARGET_<SERVICE>_URL` / `TARGET_<SERVICE>_TOKEN` env vars (default `https://localhost:8444`), matching specs at `e2e/<service>/**/*.spec.ts`. Spec dirs exist for `origin/` and `cache/` only (plus `shared_pages/`, `shared_tests/`, `mocks/`). `E2E_EXTERNAL=1` targets live instances and auto-skips `@mutating` tests. Helper scripts: `npm run playwright:save-auth` (codegen with saved auth), `npm run playwright:generate`.
- CI leg: `test-webui-e2e.yml` (§7) — origin and cache only.

## 9. The evidence bar for a PR

CONTRIBUTE.md, verbatim: PRs should "Add unit or integration tests for fixed or changed functionality (if a test suite already exists)." AGENTS.md PR guidelines repeat it: "Add tests for new functionality or bug fixes." A feature or fix PR without tests will be bounced by reviewers.

**What reviewers reject** (review-enforced; the linter will NOT catch any of these — `.golangci.yaml` runs only defaults + misspell, staticcheck disabled):

| Rejected | Required instead |
|---|---|
| `time.Sleep` to wait for a condition | `require.Eventually` / `assert.Eventually` with deadline + poll interval + message (§5) |
| `TLSSkipVerify(true)` in fed tests | Nothing — NewFedTest generates real CA certs; the fed.go comment (§4) says talk to the team first |
| Missing `ResetTestState` start/cleanup pair — state bleed into other tests | The §3 three-line prologue |
| Arbitrary tight timeouts that "usually" pass | Generous deadline, short poll interval, copied from neighboring tests |
| Hard-coded ports | Port 0 auto-assign, or `GetUniqueAvailablePorts` if you must know the number |
| Tests hitting live external services | `mock/` package or `test_utils.MockFederationRoot`/`MockIssuer`/`RegistryMockup` |

**How to prove a fix** (the accepted sequence; methodology rationale → pelican-research-methodology):

1. Write the failing test FIRST on unpatched code; record the failure output.
2. Apply the fix; the test passes. Condition-based waiting only.
3. Race-clean the touched packages: `go test -race -count=1 -tags "client server" ./<pkg>/` (§7).
4. Run the widest relevant local pass: `go test -tags "client server" ./<pkg>/...` — and remember which environments you could NOT cover (§2) so you watch those CI legs.
5. For flake fixes, evidence = N consecutive passes under `-count=N` and `-race`; techniques → pelican-diagnostics-and-tooling.

## 10. Recipes

### 10.1 Add a unit test

Placement: alongside the source, `<file>_test.go`, same package. Add `//go:build !windows` only if it genuinely can't run on Windows (it excludes the test from the Windows CI leg). Skeleton — **executed and passing on macOS, 2026-07-05**:

```go
//go:build !windows

package mypackage

import (
    "testing"
    "time"

    "github.com/stretchr/testify/require"

    "github.com/pelicanplatform/pelican/param"
    "github.com/pelicanplatform/pelican/server_utils"
    "github.com/pelicanplatform/pelican/test_utils"
)

func TestMyFeature(t *testing.T) {
    t.Cleanup(test_utils.SetupTestLogging(t))
    server_utils.ResetTestState()
    t.Cleanup(server_utils.ResetTestState)

    require.NoError(t, param.ConfigBase.Set(t.TempDir()))

    done := make(chan struct{})
    go func() { close(done) }()

    require.Eventually(t, func() bool {
        select {
        case <-done:
            return true
        default:
            return false
        }
    }, 10*time.Second, 50*time.Millisecond, "worker never finished")
}
```

Run: `go test -count=1 ./mypackage/` (add tags if the package needs them — today only `cmd/` does). Import grouping (stdlib / external / pelican, blank-line separated) is enforced by goimports with `local-prefixes: github.com/pelicanplatform/pelican`.

### 10.2 Add a fed test

Placement decision: cross-component behavior or needs the CLI binary → `e2e_fed_tests/` (package `fed_tests`); single-component behavior that needs a running federation → that component's own package (e.g. `director/`). Header: `//go:build !windows` (all 30 existing e2e fed files have it). Skeleton — **compiles clean (`go vet`), and when executed on a no-XRootD Mac fails with exactly the §2 error; runs for real only where XRootD is installed** (2026-07-05):

```go
//go:build !windows

package fed_tests

import (
    "os"
    "path/filepath"
    "testing"

    "github.com/stretchr/testify/require"

    "github.com/pelicanplatform/pelican/client"
    "github.com/pelicanplatform/pelican/fed_test_utils"
    "github.com/pelicanplatform/pelican/param"
    "github.com/pelicanplatform/pelican/server_utils"
    "github.com/pelicanplatform/pelican/test_utils"
)

func TestMyFedFeature(t *testing.T) {
    t.Cleanup(test_utils.SetupTestLogging(t))
    server_utils.ResetTestState()
    t.Cleanup(server_utils.ResetTestState)

    originConfig := `
Origin:
  StorageType: "posix"
  Exports:
    - StoragePrefix: /<SHOULD BE OVERRIDDEN>
      FederationPrefix: /test-namespace
      Capabilities: ["PublicReads", "Reads", "DirectReads", "Listings"]
`
    fed := fed_test_utils.NewFedTest(t, originConfig)

    storageDir := fed.Exports[0].StoragePrefix
    require.NoError(t, os.WriteFile(filepath.Join(storageDir, "data.txt"), []byte("payload"), 0644))

    discoveryHost := param.Federation_DiscoveryUrl.GetString()
    pelicanUrl := "pelican://" + discoveryHost[len("https://"):] + fed.Exports[0].FederationPrefix + "/data.txt"
    dest := filepath.Join(t.TempDir(), "out.txt")
    _, err := client.DoCopy(fed.Ctx, pelicanUrl, dest, false)
    require.NoError(t, err)

    got, err := os.ReadFile(dest)
    require.NoError(t, err)
    require.Equal(t, []byte("payload"), got)
}
```

Notes: `/<SHOULD BE OVERRIDDEN>` is the literal placeholder convention — NewFedTest replaces it with a temp dir. Files needed *before* XRootD starts go in an `originSetup` hook (third argument). Run: `go test -tags server ./e2e_fed_tests/ -run TestMyFedFeature -count=1` (in the dev container or a machine with XRootD ≥ 5.8.2).

### 10.3 Add a bash e2e test

Only for scenarios needing the real released binaries (goreleaser artifacts) or HTCondor plugin integration — otherwise prefer a Go test in `e2e_fed_tests/` (README rationale, §6). Add `github_scripts/<name>_test.sh` modeled on `get_put_test.sh`, then wire a step into `test-linux.yml` under `if: matrix.binary_name == 'pelican-server'`. Shellcheck runs in pre-commit (`--severity=warning`). Avoid live-OSDF dependencies (§6's citests.sh is the cautionary tale).

### 10.4 Add a frontend test

- Jest: `web_ui/frontend/<anywhere-outside-e2e>/*.test.ts(x)`; run `cd web_ui/frontend && npm test`. Remember: not run in CI (§8) — say so in your PR if it's your only evidence.
- Playwright: `web_ui/frontend/e2e/<service>/<name>.spec.ts`; run `cd web_ui/frontend && npx playwright test --project=<service>` against a locally running server (pelican-run-and-operate for standup). Only origin/cache specs run in CI.

## Provenance and maintenance

All facts verified 2026-07-05 against main@289fd41b, on macOS (darwin/arm64, no XRootD installed) — fed-test failure output was **executed**, not derived; both §10 skeletons were compiled and the unit one executed to a pass. Container-only behaviors (multiuser, condor, privileged) are verified from `images/Dockerfile` and workflow sources, not by execution.

Re-verification one-liners for volatile facts (run from repo root):

| Fact (as of 2026-07-05) | Re-verify with |
|---|---|
| client/server tags exist only in `cmd/` (99 files) | `grep -rlE '^//go:build.*(client\|server)' --include='*.go' . \| xargs -n1 dirname \| sort \| uniq -c` |
| cmd test counts 0 / 67 / 36 / 87 by tag set | `go test -tags "client server" -list '.*' ./cmd/ \| grep -c '^Test'` (vary tags) |
| `./...` silently drops `cmd` without tags | `go list ./... \| grep 'pelican/cmd$'` (expect no output) |
| ResetTestState: ~835 uses in 126 test files | `grep -rn ResetTestState --include='*_test.go' . \| wc -l` |
| 93 `!windows` test files | `grep -rln '//go:build !windows' --include='*_test.go' . \| wc -l` |
| MinXrootdVersion = 5.8.2 | `grep -n 'MinXrootdVersion =' xrootd/version.go` |
| Fed-test-without-XRootD exact error | `go test -tags server ./e2e_fed_tests/ -run TestDirectorMetadataHosting -count=1` on a no-XRootD box |
| fed.go TLSSkipVerify + cleanup-order comments | `grep -n 'hidden \*real bugs\*\|unlinkat' fed_test_utils/fed.go` |
| TEST_POSIXV2 not set in CI | `grep -rn TEST_POSIXV2 .github/` (expect no output) |
| Race = nightly only, 07:00 UTC, 30m, no coverage | `grep -rn 'race_detection\|cron' .github/workflows/*scheduled*.yml .github/workflows/test-linux-pr.yml` |
| gotestsum flags (`-p=4`, 15m/30m) | `sed -n 88,110p .github/workflows/test-linux.yml` |
| PR container = `pelican-test:latest-itb` | `grep -n latest-itb .github/workflows/test-linux-pr.yml` |
| Playwright registry/director legs commented out | `sed -n 85,97p .github/workflows/test-webui-e2e.yml` |
| Jest not run in CI; one jest test file | `grep -rn 'npm test\|jest' .github/workflows/` and `find web_ui/frontend -name '*.test.*' -not -path '*/node_modules/*'` |
| staticcheck disabled; only misspell extra | `grep -n -A4 'linters:' .golangci.yaml` |
| e2e_fed_tests = 31 files (30 !windows, 1 linux) | `grep -h '^//go:build' e2e_fed_tests/*.go \| sort \| uniq -c` |
| Test users alice/bob/carol/dave + pelican_shared (bob excluded) | `grep -n 'alice\|pelican_shared' images/Dockerfile` |
| ~98 legacy time.Sleep, ~119 require.Eventually in tests | `grep -rn 'time.Sleep' --include='*_test.go' . \| wc -l` |
| citests.sh hits live OSDF | `grep -n 'osdf:///pelicanplatform' github_scripts/citests.sh` |
| lotman linux && !ppc64le | `head -1 lotman/lotman.go lotman/api_defaults.go` |

Documented discrepancy: AGENTS.md's phrase "Many packages use `client` and `server` build tags to gate tests" overstates — every such tag currently lives in `cmd/`. The operational advice it gives (always pass tags) remains correct.

OPEN QUESTIONS (unanswerable from the repo): who rebuilds `pelican-test:latest-itb` and on what cadence when a PR needs a newer container; whether anyone routinely triages the nightly flaky-analysis summary (no in-repo allowlist exists); why the Playwright registry/director legs are parked.
