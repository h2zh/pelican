---
name: pelican-concurrency-and-shutdown-proofs
description: >-
  Proof recipes for Pelican's costliest failure class — goroutine leaks, data races, shutdown-ordering bugs, lock-order (ABBA) deadlocks, and sync.Once staleness, which surface only in the NIGHTLY race-detector CI (PRs never run -race). Load this when you see "WARNING: DATA RACE", "race detected during execution of test", a goroutine-count or FD leak, a hang in egrp.Wait, a SIGSEGV/panic during shutdown, "close of closed channel", "sql: database is closed", "unlinkat ... directory not empty" in test cleanup, a wedged/OOM director, or when adjudicating whether a failing test is flaky or a real bug. Contains numbered proof methods with exact commands, worked examples from real repo commits, and a prevention checklist for any new goroutine/channel/resource.
---

# Pelican Concurrency and Shutdown Proofs

First-principles methods for PROVING (not eyeballing) a goroutine leak, data race,
shutdown-ordering bug, lock-order deadlock, or stale-`sync.Once` bug in this repo.
Each recipe: when to use → numbered method → worked example from real history →
acceptance criterion. Facts verified 2026-07-05/06 against `main@289fd41b`.

Why this skill exists: the race detector runs **only in the nightly scheduled CI**
(`test-linux-scheduled.yml`/`test-macos-scheduled.yml` pass `race_detection: true`;
PR workflows never do — commit `eb40bf5a`, 2026-03-23, citing 2–3x overhead). A PR
introducing one of these bugs passes PR CI and breaks the nightly a day later; a
whole cluster was found exactly that way and fixed 2026-07-03/04 (quoted below).

## When to use this skill

- A nightly run shows `WARNING: DATA RACE` / `race detected during execution of test`.
- A test hangs at cleanup (stuck in `egrp.Wait`) or fails with `unlinkat <tmpdir>: directory not empty`.
- SIGSEGV / nil-pointer panic during or after shutdown (e.g. in `gorm.(*DB).getInstance`).
- `panic: close of closed channel` or `panic: send on closed channel`.
- Goroutine or FD counts grow across test iterations or server relaunches.
- A director (or any long-lived server) wedges or is OOM-killed while goroutines pile up.
- You must decide: is this failing test flaky infrastructure or a real bug?
- You are reviewing/writing code that spawns a goroutine, makes a channel, opens a
  handle, or caches through `sync.Once` (prevention checklist, Recipe 7).

When NOT to use — route instead to:
- Symptom-to-triage for other failure modes (HTTP errors, auth, transfers) → **pelican-debugging-playbook**.
- The full incident narratives behind the worked examples → **pelican-failure-archaeology**.
- serverAds locking invariants and launch-ordering contracts as standing rules → **pelican-architecture-contract**.
- How to write/run tests generally (build tags, `NewFedTest`, `ResetTestState` idioms) → **pelican-testing-and-qa**.
- Profiling, metrics, log-level tooling, and the N-run flaky-hunting script → **pelican-diagnostics-and-tooling**.
- PR gates and review policy (what reviewers reject) → **pelican-change-control**.

## Reading the codebase's concurrency idioms (shared vocabulary)

All commands below run from the repo root. Definitions of federation jargon
(director, origin, cache, ads) → **pelican-federation-domain-reference**.

| Idiom | Where | What it means when you read it |
|---|---|---|
| `ctx.Value(config.EgrpKey).(*errgroup.Group)` | created in `Execute` (`cmd/root.go`); retrieved in `LaunchModules` (`launchers/launcher.go`) | ONE process-wide errgroup owns all long-lived goroutines; `Execute` does `egrp.Wait()` before exit. Anything not registered is invisible to shutdown. |
| `test_utils.TestContext(ctx, t)` | `test_utils/utils.go` | Test mirror of the production wiring: ctx bound to test deadline + errgroup + `EgrpKey`. Use in every goroutine-launching test. |
| `config.ShutdownFlag` / `RestartFlag` | declared `config/config.go` ~line 194; consumed by the signal goroutine ending `LaunchModules` | In-process shutdown/restart requests (web UI restart sends to `RestartFlag`). Production restart = `syscall.Exec` (`restartProgram`, `cmd/root.go`) — but TESTS re-run `LaunchModules` in the same process, so globals survive relaunch. Many leaks below stem from exactly that. |
| `oncePrometheus sync.Once` | `launchers/launcher.go` | "Configure once per process even if LaunchModules runs many times" — the correct pattern for relaunch-safe globals. |
| Buffered early logging | `BufferedLogHook`/`FlushLogs` in `logging/logging.go`; flushed from `config.InitServer` | Pre-config log entries are buffered; `ResetTestState` calls `logging.ResetLogFlush()`. New logging state must be resettable the same way. |
| ttlcache usage rules | `serverAds` + `getServerAdsSnapshot` in `director/cache_ads.go` | **Never call `.Range()` on a jellydator/ttlcache** (Recipe 4); iterate a snapshot from `.Items()`. Standing invariant → **pelican-architecture-contract**. |
| `atomic.Pointer[T]` for lock-free readers | `directorInfo.ad` in `director/director_advertise.go` | When long-lived goroutines read a field replaced under a mutex: writers `Store()` (under the lock), readers `Load()` without it. |
| `sync.Once` + explicit reset | `fedDiscoveryOnce` + `ResetFederationForTest` in `config/config.go` | Every once-computed config-dependent global MUST have a test-visible reset wired into `ResetTestState`/`ResetConfig` (Recipe 5). |
| `AdvertiseShutdownKey` ctx value | `director/director_advertise.go`; wired in `fed_test_utils/fed.go` | A second, earlier-cancelled context inside the main ctx so tests stop advertising loops before tearing down the rest. |

House test rules that interact with everything here (owner: **pelican-testing-and-qa**):
no `time.Sleep` waits — use `require.Eventually` (AGENTS.md line ~228; enforced by human
review, not a linter); every test calls `server_utils.ResetTestState()` in cleanup;
never set TLSSkipVerify in fed tests.

## Recipe 1 — Prove a goroutine leak

**When:** goroutine or FD counts grow across test runs/iterations; nightly fed tests
die late in the suite (FD exhaustion looks like unrelated network errors — see worked
example in Recipe 3); you suspect a background goroutine is never stopped.

**The repo already uses goleak** (`go.uber.org/goleak v1.3.0`, direct dependency in
`go.mod`; verified 2026-07-05). Existing example — `TestSlowTransfers` in
`client/handle_http_test.go`:

```go
t.Cleanup(func() {
    goleak.VerifyNone(t,
        // Ignore the progress bars
        goleak.IgnoreTopFunction("github.com/vbauerster/mpb/v8.(*Progress).serve"),
        goleak.IgnoreTopFunction("github.com/vbauerster/mpb/v8.heapManager.run"),
    )
})
```

Run it to see the pattern work (verified 2026-07-05, passes in ~6 s):
`go test -tags client -race -run 'TestSlowTransfers$' -timeout 120s ./client/`

### Method

1. Write a test that runs the suspect code INCLUDING its shutdown path (cancel
   the ctx, `egrp.Wait()`), then `t.Cleanup(func() { goleak.VerifyNone(t) })`.
   goleak checks at cleanup time — the cancel/wait must run before it (in the
   test body or a later-registered `t.Cleanup`, which runs earlier).
2. On failure goleak prints each leaked goroutine's stack; the TOP frame is the
   parked function — that names the leak. Add `IgnoreTopFunction` only for
   third-party goroutines proven to be process-lifetime singletons.
3. If goleak's process-wide view is too noisy (fed tests launch legitimate
   process-lifetime goroutines), use the capture-diff fallback:

```go
// dumpGoroutines returns all goroutine stacks (debug=1 groups identical stacks).
func dumpGoroutines() string {
    var buf bytes.Buffer
    _ = pprof.Lookup("goroutine").WriteTo(&buf, 1)
    return buf.String()
}

nBefore := runtime.NumGoroutine()
// --- run the suspect code, including its shutdown path ---
// Goroutine exits are asynchronous: poll, don't sleep.
// TRAP (verified): testify's Eventually runs the condition in its OWN goroutine,
// inflating NumGoroutine by one while polling — hence the +1.
if !assert.Eventually(t, func() bool {
    return runtime.NumGoroutine() <= nBefore+1
}, 5*time.Second, 20*time.Millisecond, "goroutine count did not return to baseline") {
    t.Logf("goroutines after (baseline %d):\n%s", nBefore, dumpGoroutines())
}
```

   (Snippet compiled and executed 2026-07-05; without the `+1` it can never pass.)
4. Diff the before/after dumps: a leak is a stack present only in AFTER,
   typically parked in `chan receive`, `select`, or `IO wait`.
5. To quantify: run the suspect code N times in a loop; a leak grows the count
   by a fixed amount per pass — that amount is goroutines-leaked-per-launch.

### Worked example: the logrus `WriterLevel` pipe leak

`logrus.Logger.WriterLevel()` **spawns a goroutine per call** — verified in
logrus v1.9.3 `writer.go`: it creates an in-memory `io.Pipe()` and does
`go entry.writerScanner(reader, printFunc)`; the goroutine exits only when the
returned `*io.PipeWriter` is closed. Every unclosed call = one leaked goroutine
parked in the pipe read. Two nuances from the logrus source (documented
discrepancy): (a) it is `io.Pipe`, NOT `os.Pipe` — Pelican's comments at both
call sites (and `d3403f1a`'s) say "os.Pipe ... file descriptors", which
overstates it; no FDs are involved, the cost is the goroutine plus pinned
memory. (b) logrus sets a GC finalizer that closes an unreachable writer, so
counts can shrink after a GC — never rely on that; close explicitly.
**Signature in dumps:** a growing pile of goroutines with top frame
`github.com/sirupsen/logrus.(*Entry).writerScanner`.

Fix shape (commit `d3403f1a`, 2026-07-03, "web_ui: close the HTTP ErrorLog
WriterLevel pipe on shutdown") — keep a handle, close it on shutdown:

```go
warnWriter := log.StandardLogger().WriterLevel(log.WarnLevel)
logWriter := builtin_log.New(warnWriter, "", 0)
...
egrp.Go(func() error {
    <-ctx.Done()
    ...
    defer warnWriter.Close() // stops the scanner goroutine, releases the pipe
    err = server.Shutdown(ctx)
```

Per-connection variant: commit `1933a734` (origin broker reverse connections —
one `WriterLevel` per connection; fixed with `defer brokerWarnWriter.Close()` in
the one-shot serve goroutine). Both call sites (`web_ui/ui.go`,
`origin/broker_client.go`) now carry warning comments — a new `WriterLevel`
call means you own its `Close()`. Story → **pelican-failure-archaeology**.

**Proven when:** AFTER-dump minus BEFORE-dump is empty (or `goleak.VerifyNone`
passes) across ≥ 2 consecutive launch/shutdown iterations, AND you can point at
the stack that used to remain and the `Close()`/cancel that now stops it.

## Recipe 2 — Prove a data race and root-cause it

**When:** nightly CI shows `WARNING: DATA RACE`; a test fails with
`race detected during execution of test`; or you suspect unsynchronized access.

### Method

1. Reproduce locally, mirroring the nightly invocation (see the "Run \"go test\""
   step in `.github/workflows/test-linux.yml`: `gotestsum ... -- -p=4
   -timeout=30m -race -tags=<client|server> ./...`) scoped to the suspect
   package (verified runs locally, 2026-07-05):

```bash
gotestsum --format pkgname-and-test-fails --hide-summary=output -- \
  -race -timeout=5m -tags=server ./director/
# or plain go test; add -count=N because races are probabilistic:
go test -race -count=20 -run 'TestNameHere$' -tags server ./director/
```

   Fed tests (`e2e_fed_tests/`, anything importing `fed_test_utils`) FAIL
   without XRootD in PATH: `XRootD binary not found in PATH. Please install
   XRootD version 5.8.2 or later` (`CheckXrootdVersion`, `xrootd/version.go`).
   Environment setup → **pelican-build-and-env**.
2. Read the report. Exact structure (generated and verified 2026-07-05):

```
==================
WARNING: DATA RACE
Read at 0x00c000022278 by goroutine 7:
  <pkg>.<function that read without synchronization>()
      <file>:<line> +0x48
Previous write at 0x00c000022278 by goroutine 6:
  <pkg>.<function that wrote>()
      <file>:<line> +0x194
Goroutine 7 (running) created at:
  <pkg>.<function that spawned the reader>()   [one block per goroutine]
      <file>:<line> +0x10c
==================
--- FAIL: TestX (0.00s)
    testing.go:1465: race detected during execution of test
```

   The two conflicting accesses share an address (= same variable); the
   creation stacks tell you which subsystems are colliding.
3. Map to happens-before: what synchronization edge SHOULD order the two access
   sites — a mutex both sides hold, a channel send/receive, an `egrp.Wait()`
   before the second access, an atomic? The race is always a missing edge; name
   it precisely ("reader R at X does not hold mutex M that writer W holds").
4. Fix by adding the cheapest correct edge — repo order of preference:
   (a) make readers stop first (cancel + `egrp.Wait`) if racing shutdown;
   (b) `atomic.Pointer[T]` if long-lived readers must not block on the writer's
   mutex; (c) widen the existing mutex. Never "fix" by removing the reader's
   observation of updates unless staleness is provably acceptable.
5. Re-run step 1 with `-count=20`; then the whole package without `-run` — the
   first race often masks a second one (see worked example).

### Worked example: the `directorInfo.ad` race (commit `84810c33`, 2026-07-03)

Symptom: `TestConcurrentFullAndRangeReads` failed intermittently on -race macOS
nightlies. Root cause per the commit: `directorInfo.ad` was replaced under
`directorAdMutex` as newer director ads arrived, but long-lived forwarding
goroutines (`launchForwardAds`, `getDirectorToken`) read it WITHOUT the lock —
racing the pointer write. Missing edge: reader did not hold the writer's mutex.

Fix — option (b) above, before/after from the commit:

```go
// before:
type directorInfo struct {
    ad *server_structs.DirectorAd
// after:
    ad atomic.Pointer[server_structs.DirectorAd]
// writes (still under directorAdMutex) use Store(); lock-free reads use Load():
func (dir *directorInfo) advertiseURL() string {
    if ad := dir.ad.Load(); ad != nil {
        return ad.AdvertiseUrl
    }
    return ""
}
```

The fix exposed a SECOND masked race (same commit): director self-tests left
ad-forwarding goroutines running (calling `GetFederation` → viper) while test
cleanup reset viper via `config.ResetConfig`. Fix: tests cancel and `egrp.Wait()`
for those goroutines before returning. Lesson: after fixing a race, rerun the
whole package under -race — the first race often hides a shutdown-ordering race
behind it (Recipe 3). Evidence bar from the commit message: "Verified with
`go test -race`: TestConcurrentFullAndRangeReads 6/6 (was 0/6)".

**Proven when:** you can state the missing happens-before edge in one sentence,
the fix adds exactly that edge, and the reproducing command passes ≥ 20
consecutive `-race` runs where it previously failed within N runs (record both N's).

## Recipe 3 — Shutdown-ordering analysis

**When:** panics/SIGSEGVs during shutdown; resources used after close
(`sql: database is closed`); test cleanup races (`unlinkat ... directory not
empty`); FD leaks across relaunches.

### The lifecycle architecture (verified against source)

Production path (`Execute` in `cmd/root.go` → `LaunchModules` in
`launchers/launcher.go`):

1. `Execute` creates `errgroup.WithContext(context.Background())`, stores the
   egrp in ctx under `config.EgrpKey`; `LaunchModules` retrieves it (fresh one
   if absent) and wraps ctx with its own cancel (`shutdownCancel`). Every
   subsystem launches via `egrp.Go(...)` or helpers taking `(ctx, egrp)`.
2. A signal goroutine (end of `LaunchModules`) selects on SIGINT/SIGTERM/SIGQUIT/
   SIGHUP, `config.RestartFlag`, `config.ShutdownFlag`, `ctx.Done()`; on shutdown
   it may run `handleGracefulShutdown` (advertise "shutting down", wait
   `Xrootd.ShutdownTimeout`), then calls `shutdownCancel()` and returns
   `ErrExitOnSignal`/`ErrRestart`, which propagates out through `egrp.Wait()` in
   `Execute`.
3. So the ONLY orderly teardown is: **cancel ctx → every egrp goroutine sees
   `ctx.Done()` and returns → `egrp.Wait()` unblocks → process exits (or
   `syscall.Exec` restarts it)**. There is no per-subsystem stop API.

The canonical test-side cleanup — function `NewFedTest` in
`fed_test_utils/fed.go` (quoted from source; its comment explains the order:
removing tmpPath while the server still uses it → `unlinkat <tmpPath>:
directory not empty`):

```go
t.Cleanup(func() {
    cancel()
    if err := egrp.Wait(); err != nil && err != context.Canceled && err != http.ErrServerClosed {
        require.NoError(t, err)
    }
    err := os.RemoveAll(tmpPath)
    require.NoError(t, err)
    // Throw in a config.Reset for good measure. Keeps our env squeaky clean!
    server_utils.ResetTestState()
})
```

Memorize the order: **cancel → `egrp.Wait` → `RemoveAll` → `ResetTestState`**.
Every shutdown bug below violates "resource released only after all its users
stopped". (`ResetTestState` is last because it shuts down the DB and resets
config — things the draining goroutines may still touch.)

### Method: the resource-ownership table

1. Enumerate the subsystem's resources — goroutines, channels, DB handles,
   listeners, temp dirs, OS pipes, child processes:

```bash
grep -n "go func\|egrp.Go\|\.Go(" <pkg>/*.go | grep -v _test               # goroutines
grep -n "make(chan\|close(\|Open\|Listen\|MkdirTemp" <pkg>/*.go | grep -v _test
```

2. Build a table: resource | creator | closer | goroutines using it | what
   guarantees the close runs AFTER all users stop.
3. Verify each row has **exactly one closer**, sequenced after `egrp.Wait()`
   (or after users are provably done). Two closers = double-close panic risk
   (Recipe 7 item 3). Zero closers = leak (Recipe 1).
4. For globals: what happens when `LaunchModules` runs AGAIN in the same process
   (every fed test does this)? Reassigned global = orphaned old resource.

### Worked example A: the DB-close saga — three commits in one afternoon (2026-07-03)

1. `63b834d8` "close all server DB handles on shutdown, not just the current
   global": `ShutdownDB` closed only what the global `database.ServerDatabase`
   pointed at; each fed-test server called `InitServerDatabase` and reassigned
   the global, orphaning earlier handles (~10 FDs each, WAL SQLite). On macOS CI
   (`ulimit -n 256`) the FD table filled and forked XRootD processes could no
   longer open their monitoring UDP socket — the failure appeared far from the
   leak. Fix: track every opened handle (`openedServerDatabases` + mutex), close
   them all. The commit also added `ServerDatabase = nil` "as apparent tidiness".
2. `0b98c269` "close directly-assigned global handle in ShutdownDB": tests that
   assigned `ServerDatabase` directly never registered their handle, so nothing
   closed it; on Windows `t.TempDir()` cleanup failed with "being used by
   another process". Fix: also close the untracked current global, deduped to
   avoid double close. (Its message cites `c345f18e` — the pre-rebase hash of
   `63b834d8`; not an ancestor of main, though `git show` may still resolve it
   via an unrelated remote branch.)
3. `94b9ed83` "don't nil ServerDatabase after ShutdownDB, to avoid a shutdown
   SIGSEGV": the tidiness nil turned a benign race into a crash.
   `LaunchPeriodicAdvertise` runs in the SAME errgroup as the goroutine calling
   `ShutdownDB` and can win one more loop iteration after the DB closes. Nil
   global → SIGSEGV in `gorm.(*DB).getInstance` (the intermittent
   `TestDirectorShutdown`/`TestExpirationDirector` CI panics); non-nil closed
   handle → graceful `sql: database is closed`, logged and dropped.
   `sql.DB.Close` is documented idempotent, so re-closing is safe.

Ownership-table reading: N creators, one closer that only knew the last handle,
users (advertise loop) not sequenced before the close. The final design accepts
the "one more iteration" race and makes it harmless — sometimes the correct fix
is a benign failure mode, not more ordering.

### Worked example B: per-launch resource leak (commit `3b9e4af4`, 2026-07-03)

gin-rate-limit's `InMemoryStore` starts a cleanup goroutine the library never
stops; `loginRateLimitMiddleware` created a fresh store per call and
`RegisterAuthEndpoints` runs on each web-engine launch → one leaked
`clearInBackground` goroutine per relaunch. Fix: one store per limit value for
the process lifetime (`loginRateLimitStore` in `web_ui/middleware.go`) — the
`oncePrometheus` idiom generalized. Rule: a third-party object spawning an
unstoppable goroutine must be a process-lifetime singleton, never per-launch.

**Proven when:** your ownership table has no row with zero or two closers, no
close that can precede a user's last access, and (for globals) an in-process
relaunch does not orphan resources — demonstrated by Recipe 1's capture-diff
across two `LaunchModules` cycles, plus FD counts (`lsof -p <pid> | wc -l`)
returning to baseline.

## Recipe 4 — Lock-order (ABBA) analysis

**When:** goroutines pile up blocked on mutexes; a subsystem wedges without
crashing; you're adding a lock or calling into locked code while holding one.

### Method: build the lock graph by hand

1. List the package's locks — named mutexes AND lock-bearing containers
   (ttlcache, sync.Map, gorm all have internal locks):

```bash
grep -rn "sync.RWMutex\|sync.Mutex" director/*.go | grep -v _test
# verified (main@289fd41b), 5 named: healthTestUtilsMutex, statUtilsMutex,
#   filteredServersMutex, directorAdMutex, currentMetadataDiscrepancyLock
grep -rn "ttlcache.New" director/*.go | grep -v _test
# more locks hide inside ttlcache instances (verified): serverAds, directorAds,
#   per-ad ResultCache, namespaceKeys, clientIp{RandAssignment,GeoOverride}Cache
```

2. For each lock, list acquisition sites:
   `grep -rn "filteredServersMutex\.\(R\)\?Lock" director/*.go`.
3. For every site, note what OTHER locks can be held inside the critical section
   — including *implicit* ones: every ttlcache method (`Get`, `Set`, `Items`,
   `Range`) takes its internal lock; gorm calls may take SQLite locks.
4. Draw edges "A held while acquiring B". A cycle = ABBA deadlock waiting for
   scheduling. Even acyclic, holding A across a *slow or wedgeable* operation on
   B transmits B's stalls to all of A's users.
5. Break edges by snapshotting: copy data out under B, release B, then take A —
   exactly what the fix below does.

### Worked example: serverAds `Range` + `filteredServersMutex` (commit `eca4f46c`, 2026-06-11)

The subtle part: **the deadlocked lock never appears in Pelican's code.** It is
ttlcache's internal `items.mu` RWMutex, and the bug is inside the dependency.
Quoted from ttlcache v3.3.0 `cache.go` (the version pinned in `go.mod`):

```go
func (c *Cache[K, V]) Range(fn func(item *Item[K, V]) bool) {
    c.items.mu.RLock()
    ...
    for item := c.items.lru.Front(); item != c.items.lru.Back().Next(); item = item.Next() {
        i := item.Value.(*Item[K, V])
        expired := i.isExpiredUnsafe()
        c.items.mu.RUnlock()          // <-- unlocked window: the list can mutate
        if !expired && !fn(i) {
            return
        }
        if item.Next() != nil {       // <-- read of list links OUTSIDE the lock
            c.items.mu.RLock()        // <-- re-acquired; loop condition touches
        }                             //     lru.Back() on the next iteration
    }
}
```

Per the commit message: Range "leaks that lock if an entry is evicted or deleted
mid-walk — routine under registration churn plus TTL expiry. One leaked reader is
fatal: the write-preferring RWMutex then blocks every reader and writer." One
concrete path (my analysis of the v3.3.0 source, not verbatim from the commit):
eviction runs `c.items.lru.Remove(elem)` and container/list zeroes the removed
element's links. The `item.Next() != nil` check runs OUTSIDE the lock, so when
the current element is evicted between that check and the `RLock()` grant,
`item = item.Next()` then yields nil and the loop condition
(`nil != lru.Back().Next()`, false on a non-empty list) exits the loop —
`Range` returns still holding the read lock, forever. If instead the cache
empties entirely, `lru.Back()` is nil and the loop condition panics with a nil
dereference (the gin engine installs `gin.Recovery()` — `GetEngine`,
`web_ui/ui.go` — so a request handler survives that as a 500).

The second edge: `updateDowntimeFromRegistry` held the global
`filteredServersMutex` while reading serverAds — the wedged cache lock stalled
the registration path too; goroutines piled up until the director was OOM-killed.
Fix (before/after from the commit):

```go
// before:
filteredServersMutex.Lock()
defer filteredServersMutex.Unlock()
ads := serverAds.Items() // cache lock taken INSIDE our lock -> transmits stalls
// after:
ads := serverAds.Items() // snapshot FIRST, no Pelican lock held
filteredServersMutex.Lock()
defer filteredServersMutex.Unlock()
```

plus a single sanctioned iteration idiom, `getServerAdsSnapshot()` in
`director/cache_ads.go` (copies `Items()` so callers iterate their own slice).
The standing invariants ("never Range serverAds"; "never hold
filteredServersMutex across a serverAds access") are owned by
**pelican-architecture-contract**; the incident story by
**pelican-failure-archaeology**. The upstream bug is unfixed as of the commit —
ANY new `.Range()` on a jellydator/ttlcache can re-trip it. Repo-wide check
(verified: only a benign `sync.Map.Range` in `metrics/health.go` remains):

```bash
grep -rn "\.Range(" --include='*.go' . | grep -v _test
```

**Proven when:** the lock graph (including dependency-internal locks) is acyclic
AND no lock is held across a call that can block on another subsystem's lock.
For a live wedge: a goroutine dump (`pprof.Lookup("goroutine")`, or SIGQUIT for
a crash dump) shows the cycle — goroutines parked in `sync.(*RWMutex).RLock`/
`.Lock` whose held-lock sets you can reconstruct from the stacks.

## Recipe 5 — `sync.Once` staleness in long-lived test processes

**When:** a test passes alone but fails in the suite; a computed global (URL,
port, token endpoint) shows a stale value — typically a default port like `:8444`
after the real listener bound a random port.

Why this class exists: one `go test` process runs many tests, and fed tests run
`LaunchModules` repeatedly; production runs it once. Any `sync.Once`-guarded
global that snapshots config is a bug if (a) it can fire before config is final
within one launch, or (b) it survives into the next test. Class (b) is mostly
solved: `config.ResetConfig` (called by `server_utils.ResetTestState`) resets
`fedDiscoveryOnce`, `onceTransport`, `setServerOnce`, and the other config
onces; `ResetTestState` itself resets `baseAdOnce`. Class (a) is the live
trap — `ResetTestState` can't help mid-launch.

### Method

1. Find the Once and what its `Do` closure snapshots (config values? ports?):
   `grep -n "sync.Once" <pkg>/*.go`.
2. Establish WHEN it first fires relative to the value becoming final. The
   killer window here: `config.InitServer` → listener bind →
   `UpdateConfigFromListener` (a random `Server.WebPort` becomes real only
   inside `LaunchModules`); a config-snapshotting Once firing earlier caches the
   default port.
3. Check the reset exists and is wired: an exported `ResetXxxForTest()` that
   replaces the Once (`fedDiscoveryOnce = &sync.Once{}` — function
   `ResetFederationForTest` in `config/config.go`). `ResetConfig` re-creates
   the Once inline for cross-test hygiene; the exported reset is what you call
   directly for within-launch ordering fixes.
4. Fix ordering bugs by deferring the Once (reset it so the next caller —
   sequenced after inputs are final — recomputes), NOT by pre-computing and
   patching the cached struct: a patched snapshot silently carries every other
   field's stale value.

### Worked example: fed-discovery Once (commits `c28544e4` → `b0bdd334`, 2026-07-04)

Step 1 (`c28544e4` "start discovery server before LaunchModules"):
`TestFedToken_PosixOrigin` sporadically failed — the origin's `scitokens.cfg`
was generated during `LaunchModules` while the discovery httptest server didn't
exist yet, pinning a wrong federation issuer on disk (XRootD's scitokens plugin
re-reads it only every 60 s): `Token issuer ... is not in list of allowed issuers`.

Step 2 (`b0bdd334` "reset the fed-discovery sync.Once instead of caching stale
info"): the first fix called `config.GetFederation` + `SetFederation` before
`LaunchModules` — firing `fedDiscoveryOnce` while `Server.ExternalWebUrl` still
had its default `:8444` port, snapshotting a stale `JwksUri` into
`globalFedInfo` with no invalidation path once the real port bound. Two macOS
nightly failures traced to that snapshot. The fix, from the diff of
`fed_test_utils/fed.go`:

```go
// before:
require.NoError(t, param.Federation_DiscoveryUrl.Set(discoveryServer.URL))
fedInfo, err := config.GetFederation(ctx)   // fires the Once TOO EARLY
require.NoError(t, err, "error getting federation info")
fedInfo.DiscoveryEndpoint = discoveryServer.URL
config.SetFederation(fedInfo)               // patches ONE field of a stale snapshot
// after:
require.NoError(t, param.Federation_DiscoveryUrl.Set(discoveryServer.URL))
config.ResetFederationForTest()             // next GetFederation (inside
                                            // LaunchModules, after the real port
                                            // binds) recomputes everything
```

(`b0bdd334`'s message cites `fe32f96e` — the pre-rebase hash of `c28544e4`;
not resolvable on main.)

**Proven when:** you can name the exact call that fires the Once early, show the
reset defers recomputation past the point where all inputs are final, and the
previously-flaky test passes repeatedly in full-suite order (not just alone):
`go test -race -count=10 -run 'TestName$' -tags server ./<pkg>/`.

## Recipe 6 — Flaky-vs-real adjudication protocol

**When:** a test fails in CI and someone (possibly you) wants to say "flaky,
re-run it". This protocol replaces that instinct with a decision.

### Decision rule (in order; stop at first match)

| Observation | Verdict |
|---|---|
| Any `-race` hit, ever, anywhere | **Real bug. No exceptions.** The race detector has no false positives — it reports only observed unsynchronized accesses. Go to Recipe 2. |
| Panic / SIGSEGV / `close of closed channel` in cleanup or shutdown | **Real bug** (shutdown-ordering class). Go to Recipe 3. |
| Failure only under timing variance (timeout exceeded, "expected condition never became true") | **Audit before blaming infra**: does the test use `time.Sleep` or a tight `require.Eventually` deadline? A sleep-based wait is a test bug (house rule, AGENTS.md ~line 228). Only after the wait logic is proven event-driven and generously bounded may you attribute to infrastructure — with the N-run evidence below. |
| Fails only on one OS / only in full-suite order | Suspect state bleed: missing `ResetTestState`, or Recipe 5 staleness. Real test bug until proven otherwise. |

### Method

1. **N-run locally** to measure the failure rate (a fuller harness script ships
   in **pelican-diagnostics-and-tooling**; the inline form, verified 2026-07-05):

```bash
go test -race -count=20 -run 'TestName$' -tags server ./<pkg>/
# -count runs the test N times in ONE process — this also exercises the
# cross-test state-bleed surface (Recipe 5). For fresh-process iterations,
# loop the command itself.
```

2. **Check the nightly history** — the scheduled workflows aggregate JUnit
   results over the last 14 runs (`analyze-runs` job in
   `.github/workflows/test-linux-scheduled.yml`; scripts in
   `.github/scripts/analyze-junit-results/`). Read-only queries:

```bash
gh run list -R PelicanPlatform/pelican --workflow test-linux-scheduled.yml --limit 14
# verified shape (2026-07-06):
# completed  failure  Run Tests (Linux) [on schedule]  ...  schedule  28778615896  29m12s  2026-07-06T08:34:50Z
gh run view <run-id> -R PelicanPlatform/pelican --log-failed      # failing steps' logs
gh run download <run-id> -R PelicanPlatform/pelican -p 'junit-*'  # the JUnit XMLs
```

   The analyzer's summary (`test-failure-analysis.md`) lands in each scheduled
   run's step summary — a test failing across many nights in one matrix leg is
   a deterministic environment interaction, not noise. NOTE (verified
   2026-07-06): nightlies currently fail routinely; `eb40bf5a` predicted the
   badge would "be red for the foreseeable future". A red nightly is a queue of
   unproven real bugs — the 2026-07-03/04 purge (Recipes 1–5's worked examples)
   came from working that queue.
3. **Localize before excusing.** If N-run passes locally but CI fails, diff the
   environments (macOS `ulimit -n 256` — Recipe 3 example A; container users;
   XRootD presence). "Passes locally" plus a named, verified environmental
   mechanism is an acceptable adjudication; "passes locally" alone is not.

**Proven flaky-infrastructure when:** the wait logic is event-driven with
generous bounds, ≥ 20 local runs pass under -race, AND you name the specific
environmental mechanism. Anything less: file it as a real bug with your N-run
numbers. Evidence standards → **pelican-research-methodology**.

## Recipe 7 — PREVENTION checklist for any new goroutine / channel / resource

Run this as PR self-review whenever a diff adds `go func`, `make(chan`, a handle
`Open`/`Listen`, a `sync.Once`, or a third-party object that spawns goroutines.
Reviewers enforce these harder than linters do (→ **pelican-change-control**).

1. **Who owns the ctx?** The goroutine must select on a `ctx.Done()` derived
   from the `LaunchModules` ctx (or `TestContext` in tests); without one it is
   unreachable by shutdown → guaranteed Recipe 1 finding.
2. **Is it registered with the errgroup?** Prefer `egrp.Go(...)` over bare
   `go func` for anything outliving a request, or `egrp.Wait()` never waits for
   it and cleanup races it (Recipe 3 example A step 3 — the advertise loop).
3. **Who closes the channel — exactly one closer?** Multiple close paths =
   `panic: close of closed channel`. Standing in-tree example (verified
   2026-07-05): `TransferClient.Close` in `client/handle_http.go` closes
   `tc.work` under a `closeOnce`, but the engine shutdown path *also* closes it
   directly, bypassing the once; both sides wear a
   `defer func() { _ = recover() }()` band-aid with a `TODO(bbockelm)`
   acknowledging the unclear ownership. Do not copy the recover hack — design a
   single owner (typically: only the producer closes; consumers detect closure).
4. **Third-party objects with unstoppable goroutines** (rate-limit stores,
   progress bars, ttlcache with eviction): process-lifetime singletons guarded
   by `sync.Once` (`oncePrometheus`/`loginRateLimitStore` idiom) — never
   per-launch or per-request.
5. **Every handle in the Recipe 3 ownership table** with one closer sequenced
   after all users stop? For `WriterLevel`-like APIs, read the dependency's
   source to learn what `Close` stops (Recipe 1).
6. **Does `ResetTestState` cover your new state?** Package-level vars, Onces,
   callbacks must reset via the package's `xxxReset` hook or `ResetConfig`, or
   the NEXT test inherits your state (Recipe 5) → **pelican-testing-and-qa**.
7. **Will it survive an in-process relaunch?** Production restart is
   `syscall.Exec` (fresh process); tests re-run `LaunchModules` in-process.
   Reassigned global handle = orphaned old one (Recipe 3 example A);
   re-registered endpoints = re-created stores (example B). Ask: "second launch,
   same process — what leaks or double-creates?"
8. **Locks:** never hold a Pelican mutex across a call into a lock-bearing
   container or another subsystem (Recipe 4). Snapshot, release, then lock.
9. **Evidence before merge:**
   `go test -race -count=20 -run 'TestYours$' -tags <tags> ./<pkg>/` — PR CI
   will NOT run -race for you; the nightly will find it at 07:00 UTC with your
   name on the commit.

## Provenance and maintenance

Facts verified 2026-07-05/06 against `main@289fd41b` (some `gh` queries dated
2026-07-06). All quoted commits verified via `git show <hash>` and confirmed
reachable from main (`git merge-base --is-ancestor <hash> main`). Snippets in
Recipes 1–2 were compiled and executed on macOS/arm64, go1.25.0,
gotestsum v1.13.0 (goleak/`TestSlowTransfers`, the capture-diff snippet, a
generated `-race` report matching the Recipe 2 template, and the gotestsum
flags all re-executed 2026-07-06). The concrete ttlcache leak/panic path in
Recipe 4 is labeled as analysis (derived from ttlcache v3.3.0 source, not a
repro run), as is the `io.Pipe`-not-`os.Pipe` correction to the in-repo
comments in Recipe 1.

CAUTION: the commands below grep the working tree, and this checkout sometimes
sits on a release branch (e.g. `v7.25.x`). Check `git branch --show-current`
first; if not on main, verify against a snapshot instead:
`git show main:<path> | grep ...` (never check out branches just to verify).

| Volatile fact | Re-verify with |
|---|---|
| goleak dependency, in use, example passes | `grep goleak go.mod` ; `go test -tags client -race -run 'TestSlowTransfers$' -timeout 120s ./client/` |
| -race only in scheduled (nightly) workflows | `grep -rn "race" .github/workflows/*.yml` |
| Nightly gotestsum invocation flags | `grep -A12 'gotestsum' .github/workflows/test-linux.yml` |
| fed.go cleanup order (cancel→Wait→RemoveAll→Reset) | `grep -n -A9 'Explicitly run tmpPath cleanup' fed_test_utils/fed.go` |
| Signal/ShutdownFlag handling; restart = syscall.Exec | `grep -n -e ShutdownFlag -e RestartFlag -e ErrRestart launchers/launcher.go` ; `grep -n syscall.Exec cmd/root.go` |
| Director lock inventory (5 named mutexes + ttlcache internals) | `grep -rn --exclude='*_test.go' -e sync.RWMutex -e sync.Mutex -e ttlcache.New director/*.go` |
| No new `.Range(` on ttlcache | `grep -rn --include='*.go' --exclude='*_test.go' '\.Range(' .` |
| Dependency pins: ttlcache v3.3.0, logrus v1.9.3 | `grep -e ttlcache -e sirupsen go.mod` ; read `cache.go` `Range` / `writer.go` `WriterLevel` in the module cache |
| gin.Recovery installed on the engine | `grep -n -e gin.New -e gin.Recovery web_ui/ui.go` |
| fedDiscoveryOnce reset (ResetFederationForTest + ResetConfig) | `grep -n "fedDiscoveryOnce" config/config.go` |
| ResetTestState contents | `grep -n -A30 "func ResetTestState" server_utils/server_utils.go` |
| TransferClient.Close recover hack still present | `grep -n -B2 -A6 "closeOnce.Do" client/handle_http.go` |
| ShutdownDB closes tracked + untracked, leaves global non-nil | `grep -n -A40 "func ShutdownDB" database/server.go` |
| Nightly junit analyzer scripts exist | `ls .github/scripts/analyze-junit-results/` |
| Worked-example commits still on main | `for c in d3403f1a 1933a734 84810c33 63b834d8 0b98c269 94b9ed83 3b9e4af4 eca4f46c c28544e4 b0bdd334 eb40bf5a; do git merge-base --is-ancestor $c main && echo "$c ok"; done` |

Line-number anchors in this skill are approximate by design; every code reference
is paired with a symbol name — re-locate with `grep -n "<symbol>" <path>`.
