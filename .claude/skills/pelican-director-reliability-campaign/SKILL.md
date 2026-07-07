---
name: pelican-director-reliability-campaign
description: Executable, decision-gated campaign for keeping the Pelican director alive and correct at scale. Load when working on director OOM/goroutine pileup, redirects hanging or "timeout awaiting response headers", serverAds/ttlcache locking, filteredServersMutex contention, eviction-handler deadlock (#3511), HA/multi-director cascade failures ("No sources found", peer discovery), JWT clock-skew ad expiry, or registration-churn load. Contains numbered phases with verified commands, expected numbers, a ranked solution menu with theory obligations, and fenced-off wrong paths.
---

# Director Reliability Campaign

The confirmed hardest live problem in this repo: a single director process holds
the entire federation's routing state in one in-memory TTL cache (`serverAds`),
serves every client redirect from it, and re-verifies every origin/cache
heartbeat against it. Every production director incident to date has been some
combination of (1) a lock wedged inside or around that cache, (2) goroutine
pileup behind the wedge until OOM, or (3) HA peers amplifying instead of
absorbing the failure. This skill is the campaign to fix that class, phase by
phase, with numeric gates.

All repo facts verified 2026-07-05/06 against `main@289fd41b`; live GitHub
state date-stamped 2026-07-06. Key files (`director/cache_ads.go`,
`director/director_api.go`) verified byte-identical between `main` and
`v7.25.x` at those commits; files that differ are called out inline.

## When to use this skill

- Director symptoms: OOM-kill, monotonically climbing goroutine count, clients
  timing out on redirects while `GET /api/v1.0/director/directors` still
  returns 200, registration (`registerOrigin`/`registerCache`) stalls.
- Any change touching `serverAds`, `filteredServersMutex`, `statUtils`,
  `healthTestUtils`, `directorAds`, or any `ttlcache` usage in `director/`.
- HA/multi-director work: peer discovery, ad forwarding, "No sources found"
  after a peer director outage, clock-skew ad expiration.
- You want to add load-testing, profiling, or race coverage to the director.
- Triaging issues labeled `director` + `critical`, or #3511 specifically.

**When NOT to use — route to siblings:**
- The full incident narratives (what happened, which commits) → `pelican-failure-archaeology`.
- The numbered invariants and wire-format freeze contract themselves → `pelican-architecture-contract`.
- General profiling/race/metrics techniques not specific to the director → `pelican-diagnostics-and-tooling`.
- Writing the formal race/leak/shutdown proof for a fix → `pelican-concurrency-and-shutdown-proofs`.
- PR labels, backports, `create-patch`, release trains → `pelican-change-control`.
- Standing up a real director service (certs, ports, systemd) → `pelican-run-and-operate`.
- Definitions of ads, namespaces, discovery, token profiles → `pelican-federation-domain-reference`.

## PHASE 0 — Ground truth

**Objective:** load the invariants, confirm what is live TODAY, and prove you
understand the two historical failure mechanisms before touching anything.

### 0.1 Confirm your checkout

This working copy has been observed to move between `main` and `v7.25.x`
outside of sessions. Always run first (from repo root):

```bash
git branch --show-current && git log -1 --format='%h %s %ad' --date=short
```

If you are not on `main`, facts below marked "main-only" may not hold on disk.

### 0.2 The invariants (one line each)

> Items 1–3 and 5 map to numbered invariants in **pelican-architecture-contract** (I-1 Range ban, I-2 filteredServersMutex/serverAds ABBA, I-3 four-map mutex, I-7 wire-format freeze) — read there for the full statements. Items 4 and 6 are campaign-local and are anchored to their code comments directly (they are NOT in architecture-contract's list).

1. **Never call `Range` on `serverAds`** (or any director ttlcache) — iterate a
   copy via `getServerAdsSnapshot()` in `director/cache_ads.go`, or `Items()`
   when keys are needed.
2. **Never hold `filteredServersMutex` across a `serverAds` access** — the two
   locks are independent; nesting them is the ABBA hazard. Snapshot first (see
   comment above the lock in `updateDowntimeFromRegistry`, `director/cache_ads.go`).
3. `filteredServersMutex` deliberately guards four maps: `filteredServers`,
   `serverDowntimes`, `topologyDowntimes`, `federationDowntimes`.
4. **Always lock `statUtilsMutex` before `healthTestUtilsMutex`** (documented
   in the `serverAds.OnEviction` handler, `director/director_api.go`).
5. Ad structs (`OriginAdvertiseV2`, `ServerAd`, `NamespaceAdV2`, `DirectorAd`
   in `server_structs/director.go`) are cross-version wire format: **add
   fields, never rename/remove JSON keys**. `ServerAd` carries a "BE WARNED"
   comment requiring sync with `director/director_ui.go` response structs.
6. Prometheus metric names and label sets are frozen ABI — including live
   typos (the `insersions` label on `pelican_director_ttl_cache`). Add new
   series; never fix-in-place.

### 0.3 Why Range is banned; what the ABBA pair is (the gate)

- **Range ban:** `ttlcache` v3.3.0's `Range` can leak the cache's internal read
  lock if the eviction goroutine removes the current entry mid-iteration; one
  leaked reader wedges the write-preferring RWMutex → redirects/registration
  block → goroutine pileup → OOM. This killed the production director (fix PR
  #3513, commit `eca4f46c` on main). **Full library-source dissection is
  single-owned in pelican-concurrency-and-shutdown-proofs Recipe 4** — read it
  before touching any ttlcache.
- **ABBA pair:** `filteredServersMutex` vs. `serverAds`' internal lock.
  `updateDowntimeFromRegistry` used to hold `filteredServersMutex` while
  reading `serverAds` while the redirect path held the cache lock and then
  called `checkFilter` (which takes `filteredServersMutex.RLock`) — opposite
  acquisition orders. Fixed by snapshot-before-lock; the ordering rule keeps
  it fixed.

**GATE:** If you cannot restate both mechanisms from memory after reading the
above, read `pelican-failure-archaeology` before proceeding.

### 0.4 Enumerate the live issue set (run these; results below are 2026-07-06)

```bash
# Always -R: the local 'origin' remote is a personal fork.
gh issue list -R PelicanPlatform/pelican --label critical --label director --state open \
  --json number,title,createdAt --limit 30
```

Expected (2026-07-06): 7 issues — #3108 (discoverFederationImpl rework), #3107
(test file transfer cleanup), #3095 (Director.Tests red herring), #2537 (token
audiences), #2127 (don't block all ads if subset unapproved), #2119
(multi-director follow-up), #1999 (logfile reopen).

```bash
gh issue list -R PelicanPlatform/pelican --state open \
  --search "director lock OR OOM OR deadlock" --json number,title --limit 10
```

Expected (2026-07-06): **#3511** "Director: goroutine leak and client timeouts
from a blocking `errgroup.Wait()` in the `serverAds` eviction handler"
(labels `bug, director`, OPEN — this is the campaign's current front, see
Phase 3.1) and **#3489** "Data races found by the Go race detector" (OPEN;
partial fix PR #3490 also OPEN).

Lineage — all MERGED (verify: `gh pr view <n> -R PelicanPlatform/pelican --json state,title`):

| PR | What | Status 2026-07-06 |
|---|---|---|
| #3513 | serverAds Range lock leak / OOM fix (`eca4f46c`; cherry-pick `086b6278` on v7.25.x) | MERGED, `critical, create-patch` |
| #3452 | HA director cascade-failure fixes (issue #3449) | MERGED, `create-patch` |
| #3473 | JWT clock-skew tolerance (60s leeway; jwx ≥ v2.1.0 for `jwt.WithResetValidators`) | MERGED, `create-patch`; v7.26.x backport #3492 MERGED; v7.25.x got narrowed commit `6b3b2d56` after a revert cycle (story: pelican-failure-archaeology) |

If any of the above shows a different state than listed, re-derive the live
set before planning work — this table is the most volatile part of this skill.

## PHASE 1 — Reproduce load locally

**Objective:** a repeatable in-process harness producing baseline numbers for
N synthetic ads, with no live cluster, no XRootD, no registry.

### 1.1 How registration really works (so you know what the harness bypasses)

- Origins/caches POST `server_structs.OriginAdvertiseV2` JSON to
  `POST /api/v1.0/director/registerOrigin` / `registerCache` (routes in
  `director/director.go`, function `registerServerAd`), bearing a JWT signed
  by the server's own key with scope `pelican.advertise`
  (`token_scopes.Pelican_Advertise`).
- The director verifies via the registry (namespace approval + JWKS fetch,
  function `verifyAdvertiseToken` in `director/origin_api.go`); JWKS results
  cache in the `namespaceKeys` ttlcache with TTL = `Director.AdvertisementTTL`.
- Accepted ads land in `serverAds` via `recordAd` (`director/cache_ads.go`)
  with TTL = the ad's own `Expiration` if set, else `Director.AdvertisementTTL`
  (default 15m). Servers re-advertise every `Server.AdvertisementInterval`
  (default 1m), auto-clamped to ⅓ of `Server.AdLifetime` (default 10m) in
  `LaunchPeriodicAdvertise`, `launcher_utils/advertise.go`.
- **There is no rate limiting or backpressure on the registration endpoints**
  (verified: no limiter middleware on those routes; the only gin rate limiter
  in the repo guards web-UI login).
- Test recipe for a real-token HTTP registration (when you need the full
  path): mint with `token.NewWLCGToken()` + `AddScopes(token_scopes.Pelican_Advertise)`
  and pre-seed `namespaceKeys` with your issuer's JWKS to bypass the live
  registry — working example in `TestVerifyAdvertiseToken`,
  `director/origin_api_test.go`.
- `recordAd` side effects you must handle in any harness: it spawns one stat
  `ResultCache` goroutine per server (via `statUtils`) and, unless the ad sets
  `DisableDirectorTest: true` or `FromTopology: true`, launches file-transfer
  health tests against the advertised host. Synthetic ads MUST set
  `DisableDirectorTest: true`.

### 1.2 The churn benchmark (verified; run it now)

Write this file as `director/zz_campaign_bench_test.go` in your working tree
(it is a normal `_test.go`; delete it before commit unless Phase 4 promotes
it), **or** inject it without touching the tree via `go test -overlay` as
shown in 1.3:

```go
package director

// Campaign benchmark: redirect hot path (getAdsForPath) under registration churn —
// the interleaving class that produced the PR #3513 OOM.

import (
	"context"
	"fmt"
	"net/url"
	"runtime"
	"testing"
	"time"

	"github.com/pelicanplatform/pelican/server_structs"
)

const (
	// OSDF-scale approximation: hundreds of servers, thousands of namespaces.
	campaignServers    = 400
	campaignNsPerAd    = 10
	campaignNsFamilies = 50
)

// DisableDirectorTest MUST be true or recordAd launches file-transfer health
// tests against the fake host.
func campaignMakeAd(i int) (server_structs.ServerAd, []server_structs.NamespaceAdV2) {
	sType := server_structs.CacheType.String()
	if i%4 == 0 {
		sType = server_structs.OriginType.String()
	}
	sAd := server_structs.ServerAd{
		URL:                 url.URL{Scheme: "https", Host: fmt.Sprintf("server-%d.campaign.example.org:8443", i)},
		Type:                sType,
		DisableDirectorTest: true,
	}
	sAd.Name = fmt.Sprintf("CAMPAIGN_SERVER_%d", i)
	sAd.Expiration = time.Now().Add(15 * time.Minute)
	nses := make([]server_structs.NamespaceAdV2, 0, campaignNsPerAd)
	for j := 0; j < campaignNsPerAd; j++ {
		nses = append(nses, server_structs.NamespaceAdV2{
			Path: fmt.Sprintf("/campaign/ns-%d/sub-%d", i%campaignNsFamilies, j),
			Caps: server_structs.Capabilities{PublicReads: true, Reads: true},
		})
	}
	return sAd, nses
}

func BenchmarkGetAdsForPathUnderChurn(b *testing.B) {
	serverAds.DeleteAll()
	go serverAds.Start() // eviction goroutine must run: it is half of the historical race
	b.Cleanup(func() {
		serverAds.DeleteAll()
		serverAds.Stop()
		shutdownStatUtils()
	})

	ctx := context.Background()
	for i := 0; i < campaignServers; i++ {
		sAd, nses := campaignMakeAd(i)
		recordAd(ctx, sAd, &nses)
	}
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	b.Logf("baseline: ads=%d goroutines=%d heapAlloc=%.1f MB",
		serverAds.Len(), runtime.NumGoroutine(), float64(ms.HeapAlloc)/1024/1024)

	stopChurn := make(chan struct{})
	churnDone := make(chan struct{})
	go func() {
		defer close(churnDone)
		i := 0
		for {
			select {
			case <-stopChurn:
				return
			default:
			}
			sAd, nses := campaignMakeAd(i % campaignServers)
			recordAd(ctx, sAd, &nses)
			i++
		}
	}()
	b.Cleanup(func() { close(stopChurn); <-churnDone })

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			oAds, cAds := getAdsForPath(fmt.Sprintf("/campaign/ns-%d/sub-%d/file.txt", i%campaignNsFamilies, i%campaignNsPerAd))
			if len(oAds) == 0 && len(cAds) == 0 {
				b.Error("no ads matched; harness is broken")
				return
			}
			i++
		}
	})
	b.StopTimer()

	runtime.GC()
	runtime.ReadMemStats(&ms)
	b.Logf("after: ads=%d goroutines=%d heapAlloc=%.1f MB",
		serverAds.Len(), runtime.NumGoroutine(), float64(ms.HeapAlloc)/1024/1024)
}
```

Run (repo root; director tests need no build tags — only `!windows`
constraints exist in that package):

```bash
go test -run 'XXXNONE' -bench 'BenchmarkGetAdsForPathUnderChurn' -benchtime 2s ./director/
```

**Expected output** (executed 2026-07-06 on darwin/arm64, 12 cores, both
`main@289fd41b` and `v7.25.x@f25a879b` — statistically identical):

```
BenchmarkGetAdsForPathUnderChurn-12   26396   94885 ns/op
    baseline: ads=400 goroutines=403 heapAlloc=9.5 MB
    after:    ads=400 goroutines=406 heapAlloc=9.8 MB
PASS  ok  github.com/pelicanplatform/pelican/director  ~4-22s
```

Baseline numbers to record for YOUR machine: ns/op (≈95µs here), heapAlloc
for 400 ads × 10 namespaces (≈9.5 MB), goroutine count (≈ N_servers + 3: one
stat `ResultCache` goroutine per registered server — itself a scaling fact
worth knowing: 4000 servers would mean 4000 idle cache goroutines).
Log-noise like `Concurrency limit 'Director.StatConcurrencyLimit' must be
positive; ignoring value 0 and using 100 instead` is normal without config
init.

**GATES:**
- Benchmark errors with "no ads matched" → your `getAdsForPath`/`recordAd`
  signatures drifted from this recipe; re-derive from `director/sort.go` and
  `director/cache_ads.go` before trusting any numbers.
- `after` goroutines ≫ `baseline` (more than ~10 above) → you have a leak in
  the code under test; jump to Phase 2.3.

### 1.3 Overlay variant (keeps the tree pristine)

```bash
REPO=$(git rev-parse --show-toplevel); TMP=$(mktemp -d)
# ...write the benchmark file to $TMP/zz_campaign_bench_test.go, then:
printf '{"Replace": {"%s/director/zz_campaign_bench_test.go": "%s/zz_campaign_bench_test.go"}}\n' "$REPO" "$TMP" > $TMP/overlay.json
go test -overlay $TMP/overlay.json -run 'XXXNONE' -bench 'BenchmarkGetAdsForPathUnderChurn' -benchtime 2s ./director/
```

Verified working 2026-07-06 with identical output to 1.2.

### 1.4 Full-federation stress harness (exists already; needs XRootD)

`TestStatMemory` in `director/stat_stress_test.go` boots fed-in-a-box
(`fed_test_utils.NewFedTest` with `director/resources/director-public.yaml`),
hammers the director's stat/presence cache, and asserts **heap growth
< 5e5 bytes and goroutine growth < 20** after full cache turnover:

```bash
PELICAN_RUN_STAT_STRESS=1 PELICAN_STRESS_DURATION=60s PELICAN_STRESS_SNAPSHOT_HEAP=1 \
  go test ./director/ -run TestStatMemory -count=1 -v
```

Marked **derived, not executed**: requires XRootD binaries (none on the
verification machine); the env-var gate, knobs, and thresholds are read
directly from the test source. `PELICAN_STRESS_SNAPSHOT_HEAP=1` writes
`baseline-heap.prof`/`aftertest-heap.prof` for `go tool pprof` diffing.

## PHASE 2 — Measure

**Objective:** turn "director seems slow/leaky" into a number and a named lock.

### 2.1 Race detector on churn-heavy director tests (verified)

```bash
go test -race ./director/ -run 'TestRecordAd|TestServerAdsCacheEviction|TestLaunchTTLCache' -count=3
```

Expected: `ok github.com/pelicanplatform/pelican/director ~8s`. Observed
flake rate on the verification machine: 1 failure in 15 runs (failure output
not race-related). For the HA path add
`-run 'TestForwardingReachesAllDirectors|TestSendMyAd|TestDoDiscovery'`.

**Branch matters here (verified 2026-07-06):** on `main@289fd41b` the HA trio
is race-clean; on `v7.25.x@f25a879b` it reports a real **DATA RACE**
(`config.ResetConfig` in test cleanup vs. `config.GetFederation` called from a
leaked `launchForwardAds` forwarding goroutine — the `directorInfo.ad`
atomic.Pointer fix and test-lifecycle fixes were never backported). The
underlying unsynchronized config globals are tracked in OPEN issue #3489.

**GATES:**
- Output contains `WARNING: DATA RACE` → real finding. Capture the full trace,
  identify both goroutines' stacks, then follow `pelican-concurrency-and-shutdown-proofs`
  to write the proof; file/link an issue (labels `bug`, `director`) referencing
  #3489 if it is a config-global race.
- `FAIL` with no `DATA RACE` string → flake protocol: re-run 5×
  (`-count=3` each). Persistent → treat as a reproducible bug, not a flake.
- All green → proceed.

Remember the repo discipline: PRs never run `-race`; only the nightly
(`.github/workflows/test-linux-scheduled.yml`, cron `0 7 * * *`, sets
`race_detection: true` → `-race -timeout=30m`) does. A race you introduce
today surfaces tomorrow at 07:00 UTC with your name on it. **Caveat verified
2026-07-06: `race_detection: true` exists only on `main` — the `v7.25.x` copy
of the scheduled workflow lacks it, so release-branch code is effectively
never raced in CI.** Consistent with that, this campaign found a live data
race on v7.25.x (above) that CI never caught.

### 2.2 Lock contention: mutex profile via test flags (verified)

The zero-infrastructure path (works with the Phase 1 benchmark):

```bash
go test -run 'XXXNONE' -bench 'BenchmarkGetAdsForPathUnderChurn' -benchtime 1s \
  -mutexprofile /tmp/mutex.out -o /tmp/director.test ./director/
go tool pprof -top -nodecount=8 /tmp/director.test /tmp/mutex.out
```

**Expected output** (executed 2026-07-06; your percentages will vary, the
shape should not):

```
Type: delay ... 4039.52ms total
 1576.76ms 39.03%  sync.(*RWMutex).Unlock
 1184.54ms 29.32%  runtime.unlock
  ...
         0  26.17%  github.com/jellydator/ttlcache/v3.(*Cache[...]).Get   (cum)
         0  13.41%  github.com/jellydator/ttlcache/v3.(*Cache[...]).Items (cum)
         0  12.90%  github.com/jellydator/ttlcache/v3.(*Cache[...]).Set   (cum)
```

Interpretation: contention concentrates inside ttlcache's single internal
RWMutex — `Get` (the duplicate-check reads in `recordAd`), `Items` (the
snapshot), `Set` (the write). This is the measured justification for the
Phase 3 menu ordering. Block profile: same commands with `-blockprofile`.

### 2.3 Memory growth method

In-process (no cluster): run the Phase 1 benchmark with `-benchtime 30s` and
compare the `baseline`/`after` heapAlloc log lines, or use `TestStatMemory`
(1.4) whose pass/fail thresholds are already numeric. A TTL cycle for
leak-hunting purposes is `Director.AdvertisementTTL` (default 15m; the stress
config drops `Server.AdLifetime` to 2s so ads expire and re-register many
times per minute).

**GATES:**
- Heap grows monotonically across ≥3 full TTL/AdLifetime cycles after GC →
  **leak protocol**: snapshot heap before/after
  (`PELICAN_STRESS_SNAPSHOT_HEAP=1` or `pprof.WriteHeapProfile`), diff with
  `go tool pprof -base`, identify the retaining path, then
  `pelican-concurrency-and-shutdown-proofs` for the lifecycle proof.
- Heap plateaus but ns/op degrades or goroutines accumulate → **contention
  protocol**: 2.2 mutex/block profiles; look for goroutines parked in
  `sync.(*RWMutex)` under `serverAds` callers; check for the #3511 signature
  (goroutines blocked in `LaunchPeriodicDirectorTest` → `serverAds.Get` while
  one goroutine sits in `OnEviction` → `Errgroup.Wait`).
- Both flat → your load is too gentle; raise `campaignServers`, add churn
  goroutines, or shorten ad expiry to force eviction traffic.

### 2.4 Live-director observability (derived, not executed — needs a running director)

- Prometheus exposition: `GET /metrics` on the web port. Gated by
  `Monitoring.MetricAuthorization` (default **true**) — needs a token with
  scope `monitoring.scrape`, or set the param false in a test rig.
- Director internals series (defined in `metrics/director.go`, updated every
  10s by `LaunchMapMetrics` in `director/director_api.go`):
  - `pelican_director_ttl_cache{name="serverAds"|"jwks", type="insersions"|"evictions"|"hits"|"misses"|"total"}`
    (the `insersions` typo is live ABI — do not fix; add a new series if you
    need a clean name),
  - `pelican_director_map_items_total{name="filteredServers"|...}`,
  - `pelican_director_advertisements_received_total{status_code,...}`,
  - `pelican_director_rejected_advertisements{hostname}`,
  - `pelican_director_redirects_total{destination,status_code,...}`,
  - `pelican_director_server_count`, `pelican_director_stat_active`,
    `pelican_director_stat_total`, `pelican_director_server_statusweight`.
- pprof over HTTP: `Server.EnablePprof: true` (default false) exposes
  `/api/v1.0/debug/pprof/{heap,goroutine,mutex,block,profile,trace,allocs}`
  behind admin web-UI auth (`web_ui/pprof.go`). The stress-test config
  `director/resources/director-public.yaml` already enables it.
- Wedge triage signature (from #3511): redirects time out, `/directors`
  still 200, goroutine count climbing → grab
  `/api/v1.0/debug/pprof/goroutine?debug=2` and look for one goroutine in
  `serverAds.OnEviction → Wait` and many in `serverAds.Get/Items`.

Scrape-frequency detail: TTL-cache stats are gauges refreshed every 10s, so
sub-10s dynamics are invisible there; use pprof for those.

## PHASE 3 — Solution menu, RANKED

Ranked by (evidence of live impact) × (blast radius if wrong). Every item
lists its **theory obligation** — what you must be able to state before
writing code — and its **evidence bar** for Phase 4.

### 3.1 Fix the eviction-handler blocking Wait (OPEN issue #3511) — do this first

**What (verified in code, identical on main and v7.25.x):** the
`serverAds.OnEviction` handler in `LaunchTTLCache`
(`director/director_api.go`) calls `statUtil.Errgroup.Wait()` and
`util.ErrGrp.Wait()` inline. ttlcache v3.3.0 invokes eviction callbacks
*while holding its internal lock* (verified in the library's `evict()`:
callbacks run inside the `c.items.mu` critical section). The health-test loop
being waited on calls `serverAds.Get` (`director/monitor.go`, function
`LaunchPeriodicDirectorTest`) — which needs that same lock to return. If the
loop is at that point when eviction fires: deadlock; the cache lock is held
forever; every redirect blocks; goroutines pile up until restart/OOM. The
code even carries a comment admitting "deadlock can happen…".

**Theory obligation:** state the full cycle (eviction goroutine holds cache
lock → OnEviction → Wait on health loop → health loop blocked on cache lock)
and why `util.Cancel()` cannot break it (context cancellation cannot preempt
a goroutine parked on a mutex acquisition).

**Fix shape (candidate, not yet designed):** make eviction cleanup
asynchronous — hand the util to a reaper goroutine/queue and return from the
callback without waiting; or make the health loop hold no cache access at
its Wait-able points. Any fix must preserve invariant 4 (lock order) and must
not resurrect Range (invariant 1).

**Evidence bar:** a regression test that forces the interleaving (evict while
health loop is between Get calls) and deadlocks before the fix within a
`require.Eventually` window; race-clean per Phase 4; before/after Phase 1
benchmark unchanged within noise.

### 3.2 ttlcache usage audit + regression guard (mechanical, low risk)

Every ttlcache in the repo can re-trip the Range leak. Audit (verified
2026-07-06: the only non-test `.Range(` in the repo is `sync.Map.Range` in
`metrics/health.go` — benign):

```bash
# char class [([] catches both New( and generic instantiations New[string, ...](
grep -rnE "ttlcache\.New[([]" --include='*.go' . | grep -v _test.go   # 28 on main@289fd41b, 20 on v7.25.x (2026-07-06)
grep -rn "\.Range(" --include='*.go' . | grep -v _test.go                 # expect ONLY metrics/health.go (sync.Map — benign)
```

Director-owned instances to know by name: `serverAds`, `namespaceKeys`
(JWKS, TTL = AdvertisementTTL), `directorAds` (HA peers, hardcoded 15m),
`clientIpRandAssignmentCache`, `clientIpGeoOverrideCache`, per-server stat
`ResultCache`s (capacity-bounded, `Director.CachePresenceCapacity`).

**Theory obligation:** before touching any ttlcache, be able to state the leak
mechanism from the library source — single-owned in
**pelican-concurrency-and-shutdown-proofs** Recipe 4 (per-element RUnlock;
unlocked `item.Next()` check; removal in the check→re-lock window makes the loop
exit holding the re-taken read lock) — not just "Range is banned".

**Guard (candidate — does not exist yet):** a CI grep or a Go test that fails
on any new non-test `ttlcache`-receiver `.Range(`/`.RangeBackwards(` call.
Keep the allowlist explicit (`sync.Map.Range` is fine). Route the CI-wiring
part through `pelican-change-control`.

**Evidence bar:** guard demonstrably fails on a planted violation, passes on
the current tree.

### 3.3 Lock-scope reduction / sharding of filteredServersMutex's four-map domain

**Document the current contract FIRST** (this is the theory obligation).
Verified call-site map (function names are the stable anchors):

| Site | Mode | Function (director/) |
|---|---|---|
| cache_ads.go | Lock | `applyServerDowntimes` |
| cache_ads.go | RLock | `isServerInDowntime`, `getCachedDowntimes` |
| cache_ads.go | Lock | `updateDowntimeFromRegistry` (snapshots serverAds BEFORE locking) |
| advertise.go | Lock | `updateDowntimeFromTopology` |
| director.go | Lock ×2 | `registerServerAd` (hot path: every heartbeat) |
| director_api.go | RLock | `checkFilter` (hot path: every ad considered on every redirect) |
| director_api.go | Lock | `ConfigFilteredServers` |

`checkFilter` is taken per-ad inside `getAdsForPath`'s loop — with 400 ads
that is 400 RLock/RUnlock per redirect; the Phase 2.2 profile shows the cost
today is dominated by ttlcache's lock, not this one. **So: do not shard until
a mutex profile shows `checkFilter`/`filteredServersMutex` as a top-5 delay
site.** If it does: candidate designs are (i) copy-on-write snapshot of the
filter map (like `getServerAdsSnapshot`), or (ii) one mutex per map. Either
way, prove no new ABBA pairs using the lock-order method in
`pelican-concurrency-and-shutdown-proofs`, and preserve invariant 2's
acquisition rule at every site in the table above.

**Evidence bar:** mutex-profile before/after showing the targeted site's
delay reduced; zero new lock-order edges (document the full order graph in
the PR); race-clean per Phase 4.

### 3.4 Registration backpressure / rate limiting (design-gated)

**What exists today: nothing** — `registerOrigin`/`registerCache`/
`registerDirector` have no limiter (verified). Heartbeat arrival model
(theory obligation — write this in the design doc):

- Steady state: each server re-advertises every
  `min(Server.AdvertisementInterval, Server.AdLifetime/3)` = min(1m, 200s) =
  **1m** at defaults → N servers ≈ N/60 req/s (400 servers ≈ 6.7 req/s —
  trivial). The risk is not steady state; it is (a) thundering herd after a
  director restart (all servers advertise immediately on their next tick,
  plus first-boot `doAdvertise` fires at once), and (b) each registration's
  cost being amplified by registry round-trips on `namespaceKeys` cache
  misses (TTL = AdvertisementTTL = 15m).
- **Starvation-freedom obligation:** a legitimate server must never lose its
  `serverAds` entry because rate limiting deferred its re-ad past ad expiry.
  Any limiter must therefore (i) be per-source, not global; (ii) admit at
  least one ad per server per `AdLifetime/3`; (iii) shed load by rejecting
  with a retryable status (503 + Retry-After), never by queueing unboundedly
  (that is the OOM shape again).

**Evidence bar:** a load test (Phase 1 harness extended to the HTTP path)
showing p99 registration latency bounded under 100× steady-state herd while
zero synthetic servers drop from `serverAds` (watch
`pelican_director_ttl_cache{name="serverAds",type="total"}` /
`pelican_director_rejected_advertisements`).

### 3.5 HA / multi-director state (the ambitious end)

**What exists TODAY (all verified on main):**

- Each director keeps peers in the `directorAds` ttlcache (15m TTL,
  `director/director_advertise.go`); peer seeds come from
  `Server.DirectorUrls` (stringSlice param); discovery loop `doDiscovery`
  lives in `server_utils/director_discovery.go`.
- Directors self-advertise (`sendMyAd`) and gossip service ads to peers via
  `POST /api/v1.0/director/registerDirector` with `SeenBy` loop-breaking;
  clients of the fleet read `GET /api/v1.0/director/directors`.
- Post-#3452 behavior: self-ad is self-inserted (no peer round-trip needed),
  successfully-contacted seeds are synthesized into the endpoint map even if
  no peer reports them, and expired gossip entries are dropped. The 2026-05-13
  OSDF outage mode (surviving director returns only the dead peer, namespace
  store empties, clients get 404 "No sources found") is fixed; property tests
  live in `director/ha_property_test.go` (anti-symmetry/transitivity of ad
  ordering, SeenBy exactness, skew-correction lifetime preservation).
- Clock skew handling: ads carry `Now`; receivers re-base expiry when skew
  >100ms (`CorrectTimeSkew`, `SkewThreshold` in `director_advertise.go`;
  inline equivalent in `registerServerAd`). JWT validation applies
  `token.ClockSkewLeeway` = 60s (`token/token_verify.go`, WLCG profile).
- Broker interplay: a director auto-runs the broker when
  `Director.EnableBroker` is true (default true; `launchers/launcher.go`), and
  `recordAd` registers per-server broker endpoints on the global
  `brokerDialer` — HA designs must not assume ads are pure data; recording
  one has dialer side effects.
- Deferred multi-director work is tracked in OPEN critical **#2119**.

**Theory obligation before designing anything new:** write the consistency
requirement down. The load-bearing fact: **ads are re-derivable soft state** —
every origin/cache re-advertises within ~1 minute, so a director that loses
all state converges to full routing state in ≤ one advertisement interval
(plus registry-approval checks). Therefore directors need availability and
bounded staleness, NOT consensus; any design that introduces
Raft/etcd-style strong consistency for `serverAds` is over-engineering and
adds a new failure mode. Define: maximum tolerable staleness window, behavior
during peer partition (serve stale vs. 404), and what — if anything — must
survive restart (today: nothing does, by design).

**Evidence bar:** a two-director in-process test (pattern:
`director/forward_service_test.go` + `director_advertise_self_test.go`)
demonstrating the target property, e.g. "kill peer A; B serves correct
redirects continuously; A rejoins and converges within one ad lifetime" —
extending the #3452 property-test suite rather than replacing it.

### 3.6 FENCED-OFF WRONG PATHS (each has already burned someone)

| Wrong path | Why it is wrong |
|---|---|
| Re-introducing `Range` anywhere (e.g. "avoid the Items() copy for performance") | The upstream leak is unfixed in the pinned ttlcache v3.3.0; this is the exact OOM of PR #3513. The copy is the fix. |
| Holding `filteredServersMutex` across any `serverAds` call | Recreates the ABBA pair; the snapshot-first pattern in `updateDowntimeFromRegistry` exists precisely to prevent this. |
| "Fixing" dropouts by raising `Director.AdvertisementTTL` / `Server.AdLifetime` | Masks dropout detection: dead servers keep receiving redirects for the whole extended TTL. The TTL is the failure detector. |
| Swapping ttlcache for another cache library without reading its lock semantics | The current bug class came from unread lock semantics (Range; callbacks-under-lock). Any replacement needs the same audit: iteration safety, eviction-callback locking, capacity eviction behavior. |
| Adding locks around `param` getters | `param` has its own mutex/atomic snapshot design; wrapping it invites new lock-order edges. If a param read races, the bug is elsewhere (see `pelican-config-and-flags`). |
| Doing blocking work (Wait, network, registry calls) inside any ttlcache `OnEviction`/loader callback | Callbacks run under the cache's internal lock (verified in library source) — this is issue #3511's mechanism. |
| Renaming metric names/labels or ad-struct JSON keys while "cleaning up" | Frozen wire ABI; see invariants 5–6 and `pelican-architecture-contract`. |

## PHASE 4 — Validate & promote

**Objective:** numeric before/after, race-clean, nightly-green, then through
change control. "Seems fine" is not a result.

### 4.1 Before/after numbers (same harness as Phases 1–2)

```bash
# on the base commit:
go test -run 'XXXNONE' -bench 'BenchmarkGetAdsForPathUnderChurn' -benchtime 2s -count 10 ./director/ | tee /tmp/before.txt
# on your branch (same machine, same power state):
go test -run 'XXXNONE' -bench 'BenchmarkGetAdsForPathUnderChurn' -benchtime 2s -count 10 ./director/ | tee /tmp/after.txt
go run golang.org/x/perf/cmd/benchstat@latest /tmp/before.txt /tmp/after.txt   # (benchstat: derived, not executed)
```

Success is written as numbers, for example: "p50 `getAdsForPath` under 400-ad
churn within 10% of baseline (~95µs/op on the reference machine); heapAlloc
delta after run < 0.5 MB; goroutine delta < 10". For contention fixes, attach
the 2.2 mutex-profile top-8 before/after. For #3511-class fixes, the
regression test from 3.1 must fail on base and pass on the branch.

### 4.2 Race-clean criterion (exact commands)

```bash
go test -race ./director/ -count=3 -timeout 30m          # whole package
for i in $(seq 1 7); do
  go test -race ./director/ -run 'TestRecordAd|TestServerAdsCacheEviction|TestLaunchTTLCache|TestForwardingReachesAllDirectors|TestSendMyAd|TestDoDiscovery' -count=3 || echo "RUN $i FAILED";
done
```

Bar: **zero `WARNING: DATA RACE` over ≥21 aggregate runs** of the churn/HA
set (7×3 above). Known-flaky failures without a race trace: re-run per the
2.1 flake protocol and say so in the PR. Then the **nightly-green criterion**:
after merge, confirm the next scheduled run of "Run Tests (Linux)
[on schedule]" (07:00 UTC daily) is green — that is the first time your code
meets `-race` in CI, because PR jobs run coverage instead.

### 4.3 Route through change control (summary — process owned by pelican-change-control)

- Every PR needs ≥1 label and a linked closing issue (CI-enforced). Use
  `director` + `bug`/`enhancement`; add `critical` if prod-impacting; add
  `create-patch` if the fix must land on release branches (as #3513/#3452/#3473
  all did — director reliability fixes usually qualify).
- Touched anything in `server_structs/director.go` or metric definitions?
  Run the wire-format check: fields added not renamed; JSON tags stable;
  `director_ui.go` response structs kept in sync (the "BE WARNED" comment);
  no metric/label renames. Contract details: `pelican-architecture-contract`.
- Backports are separate PRs targeting `v7.NN.x` branches, not automation.
  Note from this campaign's verification: the HA data race fixed on main
  still fires on `v7.25.x` (2.1) — when fixing director concurrency, always
  ask whether the release branches need the cherry-pick.

### 4.4 Promotion checklist

- [ ] Before/after benchmark table in PR description (n=10, benchstat).
- [ ] Race-clean evidence (4.2 command + run count) pasted.
- [ ] Regression test that fails on base, passes on branch.
- [ ] No new `.Range(` on any ttlcache; no blocking work added to eviction callbacks.
- [ ] Lock-order graph unchanged, or the new graph documented + proven acyclic.
- [ ] Wire-format check done if ad structs/metrics touched.
- [ ] Issue linked; labels set; `create-patch` decision made explicitly.
- [ ] Day after merge: nightly race run green.

## Provenance and maintenance

Facts verified 2026-07-05/06 against `main@289fd41b` (local `main` == 
`upstream/main` at verification time). Commands were executed on the working
tree at `v7.25.x@f25a879b` and cross-checked on a clean checkout of
`main@289fd41b`; `director/cache_ads.go` and `director/director_api.go` were
byte-identical between the two. Live GitHub state stamped 2026-07-06.

| Volatile fact | Re-verify with |
|---|---|
| Branch/commit of this checkout | `git branch --show-current && git log -1 --format='%h'` |
| #3511 still open (eviction-handler Wait) | `gh issue view 3511 -R PelicanPlatform/pelican --json state` |
| #3489/#3490 (race backlog) state | `gh issue view 3489 -R PelicanPlatform/pelican --json state; gh pr view 3490 -R PelicanPlatform/pelican --json state` |
| Open critical+director set (was 7) | `gh issue list -R PelicanPlatform/pelican --label critical --label director --state open --json number` |
| #3513/#3452/#3473 merged | `for n in 3513 3452 3473; do gh pr view $n -R PelicanPlatform/pelican --json state; done` |
| ttlcache pinned at v3.3.0 (Range leak unfixed) | `grep ttlcache go.mod` |
| No non-test `.Range(` beyond sync.Map in metrics/health.go | `grep -rn "\.Range(" --include='*.go' . \| grep -v _test.go` |
| 28 non-test ttlcache constructors on main | `grep -rnE "ttlcache\.New[([]" --include='*.go' . \| grep -v _test.go \| wc -l` |
| OnEviction still calls Errgroup.Wait inline | `grep -n -A14 "serverAds.OnEviction" director/director_api.go \| grep Wait` |
| No limiter on register endpoints | `grep -rn "registerOrigin\|RateLimiter" director/director.go` |
| Defaults: AdvertisementTTL 15m / AdLifetime 10m / AdvertisementInterval 1m | `grep -A6 "name: Director.AdvertisementTTL\|name: Server.AdLifetime\|name: Server.AdvertisementInterval" docs/parameters.yaml` |
| Clamp = AdLifetime/3 | `grep -n -A5 "advertiseInterval >" launcher_utils/advertise.go` |
| ClockSkewLeeway = 60s | `grep -n "ClockSkewLeeway =" token/token_verify.go` |
| SkewThreshold = 100ms | `grep -n "SkewThreshold =" director/director_advertise.go` |
| Metric names incl. `insersions` label | `grep -n "insersions\|pelican_director_ttl_cache" director/director_api.go metrics/director.go` |
| pprof routes + gating param | `grep -n "debug/pprof\|EnablePprof" web_ui/pprof.go docs/parameters.yaml` |
| Nightly-only -race (main-only flag) | `git show main:.github/workflows/test-linux-scheduled.yml \| grep -n race` |
| Stress-test thresholds (5e5 bytes / +20 goroutines) | `grep -n "5e5\|goCnt+20" director/stat_stress_test.go` |
| Benchmark recipe still compiles (signatures: `recordAd`, `getAdsForPath`) | `grep -n "func recordAd\|func getAdsForPath" director/cache_ads.go director/sort.go` |
| HA peer seeds param | `grep -A5 "name: Server.DirectorUrls" docs/parameters.yaml` |
| Reference numbers (95µs/op, 9.5MB/400 ads, N+3 goroutines) | re-run Phase 1.2 on the current machine; expect same order of magnitude, not same digits |
