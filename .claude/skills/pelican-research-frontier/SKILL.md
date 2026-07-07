---
name: pelican-research-frontier
description: >-
  Load this skill when asked "what should we work on next", "what are the open research problems", or anything about advancing Pelican's reliability/self-healing state of the art — HA/multiple directors, consistent routing state, load-aware or load-balanced redirection, "distanceAndLoad", stale-serving / origin-outage cache semantics (issue #3291), automated/self-qualifying XRootD or dependency bumps, autonomous incident response / auto-downtime, chaos or fault-injection testing, or turning a reliability hunch into a project. Contains six repo-grounded open problems, each with problem statement, why existing SOTA does not transfer, the specific repo assets that create the opening, the first three concrete steps in this repo, and a falsifiable numeric milestone.
---

# Pelican Research Frontier: Reliability and Self-Healing Federation Operations

The project lead's confirmed direction for beyond-state-of-the-art work: **hands-off
federation operations** — federations that route around failures, qualify their own
dependency upgrades, and mitigate incidents without a human on call. This skill is the
curated list of open problems in that direction. Every problem below is labeled
**OPEN PROBLEM** or **CANDIDATE**: none is committed roadmap, none is proven. Facts
verified 2026-07-05/06 against `main@289fd41b`.

**Non-negotiable rule**: any behavior change coming out of these problems — new
parameters, new ad fields, new sort algorithms, changed defaults — routes through
**pelican-change-control** (wire formats are add-only ABI; defaults need deprecation
cycles; XRootD bumps are gated). Experiments and measurements are free; merges are not.

Jargon (director, origin, cache, registry, advertisement/"ad", namespace, broker,
XRootD) is defined in **pelican-federation-domain-reference**. Short version: origins
export storage, caches copy it, the **director** redirects clients to servers using
in-memory **ads** that servers re-send every minute, and the **registry** is the
persistent trust root storing namespaces and public keys.

## When to use this skill

- You were asked to propose, evaluate, or start research-grade work on Pelican
  reliability, self-healing, HA, or federation operations.
- Task phrases like: "open problems", "research direction", "novel contribution",
  "publishable", "beyond SOTA", "what's next after the campaign".
- You touched one of these areas and want the strategic context: multiple directors /
  `directorAds` / ad forwarding; `Director.CacheSortMethod` / `distanceAndLoad` /
  `IOLoad`; issue #3291 / stale serving / origin outage; XRootD bumps / `XROOTD_VER`;
  downtime automation / `filteredServers`; chaos or fault-injection testing.
- You need a falsifiable milestone or experiment design for any of the above.

### When NOT to use

- Executing the already-scoped director-at-scale campaign (locking, OOM, HA cascade
  triage) → **pelican-director-reliability-campaign**.
- How to get a change reviewed/merged/backported, or whether you may bump XRootD →
  **pelican-change-control**.
- What happened in a past incident (the stories, commits, reverts) →
  **pelican-failure-archaeology**.
- Invariants that must hold today (serverAds locking, wire freeze, launch order) →
  **pelican-architecture-contract**.
- How to write/run tests, `NewFedTest` idioms, build tags → **pelican-testing-and-qa**.
- How to measure (race detector, profiling, metrics, log levels) →
  **pelican-diagnostics-and-tooling**.
- The evidence bar and lifecycle for turning a hunch into an accepted result →
  **pelican-research-methodology** (read it before starting any problem below).
- Definitions of federation concepts → **pelican-federation-domain-reference**.

## Problem index

| # | Problem | Status | Milestone in one line |
|---|---------|--------|----------------------|
| 1 | HA directors with convergent routing state | OPEN PROBLEM | Kill 1 of 2 directors mid-churn; survivor serves 0 spurious "no sources" errors over 600+ requests |
| 2 | Self-qualifying dependency bumps (XRootD soak harness) | OPEN PROBLEM | A real `XROOTD_VER` bump PR merges carrying machine-generated soak evidence; no revert in 30 days |
| 3 | Autonomous incident response (closed detection→mitigation loop) | OPEN PROBLEM | Injected origin failure auto-mitigated in ≤60 s over 20 injections; 0 false positives in 24 h soak |
| 4 | Load-aware redirection done right | OPEN PROBLEM | Synthetic hotspot: load-aware policy vs distance-only, ≥10k-request trace, p99 delta measured |
| 5 | Origin-controlled staleness windows (issue #3291) | OPEN PROBLEM | Semantics doc + e2e proving reads succeed for full declared window W, none succeed past W + one ad TTL |
| 6 | Federation-in-a-box chaos harness | CANDIDATE (enabler for 1, 3, 5) | Deterministic reproduction of the #3449 two-director cascade class in <5 min CI runtime |

Problems 1, 3, 4 feed **pelican-director-reliability-campaign**; do not duplicate its
triage work — this skill is for the research framing and experiments beyond it.

---

## Problem 1 — HA directors with convergent routing state

**Status: OPEN PROBLEM.**

### Problem statement

Run N directors such that clients see one consistent federation. Today every director
holds its own in-memory soft state: `serverAds` (a `ttlcache` in
`director/cache_ads.go`, TTL = `Director.AdvertisementTTL`, default 15m) plus the
`filteredServers`/downtime maps and per-director `IOLoad` polling. N directors = N
independent views converging only via servers re-advertising (every
`Server.AdvertisementInterval`, default 1m) and best-effort peer forwarding. There is
no defined consistency model, no divergence metric, and no multi-director integration
test in the repo (verified: `fed_test_utils.NewFedTest` launches exactly one director
in-process).

### Why current SOTA does not transfer

- **Consensus control planes (etcd/Raft-style)**: ads are high-churn heartbeat state,
  fully re-derivable within one advertisement interval. A consensus write per
  heartbeat buys durability nobody needs and couples director availability to quorum.
- **CDN load balancers (Maglev-class L4, anycast)**: assume one operator owns the
  network path and a central config pipeline. Pelican directors are independent HTTP
  redirectors run by a federation; the repo controls nothing below HTTPS.
- **Gossip membership (SWIM-class)**: solves member *liveness*, not consistent
  *routing metadata with per-entry authority* (each ad is signed by its server and
  trust-anchored in the registry — see pelican-architecture-contract).

The gap: a soft-state replication design with *measured* convergence bounds under
churn and director failure — anti-entropy/CRDT territory, not consensus.

### Pelican's specific assets (verified in code)

| Asset | Where | Why it matters |
|-------|-------|----------------|
| Ads are re-derivable | Servers re-advertise every 1m (`Server.AdvertisementInterval`, `docs/parameters.yaml`); ads carry own expiry | Losing a director loses nothing durable |
| Registry is the trust root and is persistent | see pelican-architecture-contract | Durable state has a home already; directors can stay stateless |
| Servers already advertise to *all* known directors | `doDiscovery` in `server_utils/director_discovery.go` (federation metadata + `Server.DirectorUrls` param + `/api/v1.0/director/directors`) | Multi-master ingestion exists |
| Directors flood-forward ads to peers with anti-loop `seenBy` | `forwardServiceAd` in `director/director_advertise.go`; endpoints `/directors` + `/registerDirector` registered in `director/director.go` | Replication channel exists |
| Ads have a happens-after partial order | `ServerBaseAd.After()` over StartTime/InstanceID/GenerationID; invariants tested in `director/ha_property_test.go` (11 property tests: anti-symmetry, transitivity, restart-wins, seenBy exactness, skew) | This is the seed of a formal convergence argument |
| Clock-skew correction already landed | `CorrectTimeSkew` in `director/director_advertise.go`, `SkewThreshold` = 100ms | One classic distributed-systems failure mode pre-solved |
| HA cascade fixes landed | PR #3452 (merged 2026-05-15, fixes #3449; prod OSDF incident 2026-05-13) | Incident story in pelican-failure-archaeology; the *fix* is the baseline to measure |

### First three steps in this repo

1. Read `director/director_advertise.go` (`registerDirectorAd`, `forwardServiceAd`,
   the `forwardAd` struct) and run the existing invariant tests
   (repo root; verified 2026-07-06, <1 s after compile; expect
   `ok  github.com/pelicanplatform/pelican/director  0.7s`):

   ```
   go test -tags "client server" -run 'TestAfterOrdering|TestSeenBy|TestForwarding|TestTimeSkew' -count=1 ./director/
   ```
2. Build the missing two-director harness. Anchors: `e2e_fed_tests/main_test.go`
   already builds a real `pelican` binary once per run (`buildOnce`); start a second
   `pelican serve --module director` subprocess wired to the in-process federation via
   `Server.DirectorUrls`. Expect port/config isolation pain — document it; that
   outcome feeds Problem 6.
3. Define the divergence metric and probe it: poll
   `GET /api/v1.0/director_ui/servers` (route group in `director/director_ui.go`) on
   both directors at 1 Hz and diff server name + generation. Metric: max window during
   which the lists differ under churn (servers restarting, ads expiring).

### You have a result when…

…a two-director harness exists in `e2e_fed_tests/` and, with servers re-advertising at
the 1m default and a synthetic client issuing ≥1 redirect request/s: (a) killing one
director (`kill -9`) mid-churn produces **zero** spurious `noOriginsForNsErr` ("404 no
sources") responses from the survivor across a 10-minute window (≥600 requests) for
namespaces registered before the kill; (b) the restarted director returns to ad parity
within **2×** the advertisement interval (≤2 min at defaults); (c) steady-state
divergence between directors is ≤ one advertisement interval for 95% of ad updates.
A blocked/falsified outcome is also a result: if flood-forwarding cannot meet the
bound under churn, the measured divergence distribution is the publishable artifact
and the input to a redesign proposal (via pelican-change-control).

### Literature pointers (verify before citing)

Raft (Ongaro & Ousterhout, USENIX ATC 2014) as the thing *not* to use and why; CRDTs
(Shapiro et al., SSS 2011); Dynamo's anti-entropy design (DeCandia et al., SOSP 2007);
SWIM membership (Das/Gupta/Motivala, DSN 2002); Maglev (Eisenbud et al., NSDI 2016);
metastable failures (Bronson et al., HotOS 2021 — the #3449 cascade is a textbook
instance). Search keywords: "soft-state replication", "anti-entropy convergence
bounds", "control-plane availability".

---

## Problem 2 — Self-qualifying dependency bumps (the XRootD soak harness)

**Status: OPEN PROBLEM.**

### Problem statement

Make an XRootD version bump carry machine-generated evidence strong enough that the
bump PR qualifies *itself*. Motivating cost (story: pelican-failure-archaeology;
policy: pelican-change-control): the 5.9.5 upgrade (PR #3488, issue #3487) was
reverted a week later by PR #3497 ("We've discovered issues with 5.9.5 and removed it
from the osg-testing repos", merged 2026-06-02), and the v7.25.x release branch
separately downgraded 5.9.2→5.9.1 (commit `fe785866`). The breakage was found
downstream, not by this repo's CI — the falsifiable target is a harness that would
have caught it here.

### Why current SOTA does not transfer

- **Dependabot/Renovate-style automation** qualifies bumps with unit tests. XRootD
  regressions manifest in data-plane behavior — proxy-cache semantics, TPC, auth
  callouts, restarts — under sustained load, which unit tests never reach.
- **Vendor/distro qualification (osg-testing repos)** is human-paced, external, and
  not diffable against Pelican's own workloads; it found the 5.9.5 problem *after*
  Pelican had already merged the bump.
- **Differential testing** (McKeeman-style) is the right shape but has no off-the-shelf
  harness for "Go control plane supervising a C++ daemon across two daemon versions".

### Pelican's specific assets (verified)

| Asset | Where |
|-------|-------|
| Single version knob for containers | `ARG XROOTD_VER="5.9.2"` at `images/Dockerfile:316` (2026-07-05), with a NOTE requiring the same bump in `github_scripts/osx_install.sh` (which builds tag `v5.9.2-pelican` from the PelicanPlatform/xrootd fork) |
| Test/dev image targets in the same Dockerfile | stages `pelican-test` and `pelican-dev` (`images/Dockerfile`); `make pelican-build-server-image` wraps `docker build -f images/Dockerfile` |
| Whole-federation-in-one-process e2e tests | `e2e_fed_tests/` (30+ test files incl. cache corruption, restart, streaming, downtime) on `fed_test_utils.NewFedTest`; see pelican-testing-and-qa |
| Nightly race + JUnit failure analysis already automated | `.github/workflows/test-linux-scheduled.yml` (cron `0 7 * * *`, `race_detection: true`) feeding `.github/scripts/analyze-junit-results/analyze_junit_results.py`, which writes `test-failure-analysis.md` from JUnit XML |
| The motivating incident is recent and documented | PRs #3488/#3497, issue #3487, commit `fe785866` |

### First three steps in this repo

1. Enumerate which tests actually exercise the XRootD data plane vs pure-Go paths:
   read `e2e_fed_tests/README.md`, then classify the test files
   (`cache_corruption_test.go`, `restart_test.go` are XRootD-heavy; `posixv2_*_test.go`
   bypass XRootD — the pure-Go origin data plane serves those). The XRootD-reachable
   subset is the soak corpus.
2. Prototype the differential build (derived from `images/Dockerfile` targets — **not
   executed during verification**, container builds are slow):

   ```
   docker build -f images/Dockerfile --target pelican-test --build-arg XROOTD_VER=<candidate> -t pelican-test:xrootd-<candidate> .
   ```

   Trap recorded in the Dockerfile itself: the RPM comes from osg-testing and the
   release string embeds `OSG_SERIES`/`BASE_OS`; a candidate version must exist in
   osg-testing or `XROOTD_RELEASE` must be overridden.
3. Prototype the report: run the soak corpus N times against baseline and candidate
   images (JUnit XML out), then reuse
   `.github/scripts/analyze-junit-results/analyze_junit_results.py` (its docstring
   confirms it aggregates JUnit XML from `artifacts/`) to diff failure *signatures* —
   new signature in candidate ∧ absent in baseline = veto.

### You have a result when…

…one real XRootD bump PR (routed through pelican-change-control, which owns bump
policy) carries an attached machine-generated report — ≥20 repetitions of the
XRootD-reachable e2e corpus on baseline and candidate, zero new failure signatures,
plus a race-detector pass equivalent to the nightly — and merges **without a revert
for 30 days**. Falsified if a harness-passed bump is later reverted for a cause the
corpus demonstrably exercised; that outcome is itself publishable — it bounds what
in-repo soak can qualify.

### Literature pointers (verify before citing)

Differential testing (McKeeman, Digital Technical Journal 1998); OSS-Fuzz (Google,
public docs); SQLite's public testing discipline. Keywords: "dependency update
qualification", "regression signature mining", "flaky test detection CI".

---

## Problem 3 — Autonomous incident response

**Status: OPEN PROBLEM.**

### Problem statement

Close the loop between failure detection and traffic mitigation. Both halves exist and
are verified working, but nothing connects them:

- **Detection**: the director runs a file-transfer test against every registered
  origin/cache every `Director.OriginCacheHealthTestInterval` (default **15s**; loop is
  `LaunchPeriodicDirectorTest` in `director/monitor.go`). Results update
  `healthTestUtils` and an EWMA `StatusWeight` on the ad. Component health lives in
  `metrics/health.go` (`SetComponentHealthStatus`, Prometheus gauge
  `PelicanHealthStatus`), and the director's embedded Prometheus scrapes every
  origin/cache (`web_ui/prometheus.go`, job `origin_cache_servers`, discovered via
  `/api/v1.0/director/discoverServers`) — failure history is queryable.
- **Mitigation**: the `filteredServers` map excludes servers from all redirects
  (`checkFilter` in `director/director_api.go`, consulted by `getAdsForPath` in
  `director/sort.go`). It is fed by server-declared downtimes arriving in ads
  (`applyServerDowntimes` in `director/cache_ads.go`), registry polling
  (`updateDowntimeFromRegistry`/`PeriodicFedDowntimeReload`, same file), OSDF topology,
  and the static `Director.FilteredServers` param. Operators drive it via the downtime
  REST API (`/api/v1.0/downtime`, registered in `web_ui/ui.go`) and the CLI (verified
  by running the built binary 2026-07-06):

  ```
  pelican downtime --help
  # → Available Commands: create, delete, list, update
  # → Flags: -s/--server <web URL>, -t/--token <admin token file>
  ```

**The verified gap**: no code path writes `filteredServers` from director health-test
failures. All six writers are downtime/config paths (verified by grep over
`director/`): static param → `permFiltered` (`director_api.go`); downtime-in-ads →
`serverFiltered` (`applyServerDowntimes`); registry/web-UI downtime → `tempFiltered`
(two sites in `cache_ads.go`); OSDF topology → `topoFiltered` (`advertise.go`);
pre-shutdown drain → `shutdownFiltered` (`director.go`). The only health gate on the
redirect path, `cacheNotInErrorState` in `director/sort.go`, trusts the server's
*self-reported* status (each server stamps `metrics.GetHealthStatus().OverallStatus`
into its own ad — `origin/advertise.go` / `cache/advertise.go`), and a gray-failed
server never reports itself Critical. So a server failing the director's own tests
keeps receiving traffic under the default `distance` sort; `StatusWeight` only
matters in the non-default `adaptive` sort.

### Why current SOTA does not transfer

- **Single-operator auto-remediation** (SRE-style runbook automation; FBAR-class
  systems — industry practice, not a checked citation) assumes the responder owns the
  failing machine. A director cannot restart someone else's origin; the only
  federated-safe actuator is *routing*.
- **Kubernetes-style health gating** assumes a readiness probe the workload owner
  writes and a single control plane. Here detection is *external* (director-run
  transfer tests), and a false-positive downtime removes a whole site's data for every
  user — the cost asymmetry demands explicit false-positive budgets, which
  liveness-probe practice does not provide.

### Pelican's specific assets

All listed above, plus: `e2e_fed_tests/downtime_test.go` exercises downtime end to end,
and the health test files land under `/pelican/monitoring/directorTest/` with
director-side and cache-side cleanup — i.e., the *probe traffic* is already
production-safe by design.

### First three steps in this repo

1. Trace detection: `director/monitor.go` (`LaunchPeriodicDirectorTest` → status
   transitions) and confirm the gap yourself:
   `grep -rn 'filteredServers\[' director/ --include='*.go' | grep -v _test` — six
   writers, all downtime/config paths; none in `monitor.go`.
2. Reproduce manual mitigation as the baseline: in a `NewFedTest`-based test (or the
   existing `e2e_fed_tests/downtime_test.go`), create a downtime via the API and
   assert the director stops redirecting to the server. Measure
   POST-to-first-rerouted-request time; that is the floor automation must beat.
3. Prototype the controller **externally** first — a client that watches the
   director's Prometheus (`PelicanHealthStatus`, per-server test metrics) and POSTs
   downtime to the failing server's `/api/v1.0/downtime` — zero core changes needed.
   Productizing the loop inside the director (auto-filter with hysteresis) is a
   behavior change → pelican-change-control.

### You have a result when…

…with fault injection (SIGSTOP the XRootD child, or kill the origin subprocess in a
Problem 6 harness): (a) mean time to mitigation — fault injected → director no longer
returns the failed server in redirects — is **≤ 60 s** (detection ≤ 2 health-test
intervals at the 15s default, plus propagation), measured over **20** injections;
(b) a **24 h fault-free soak** produces **zero** false-positive downtimes; (c) the
baseline is quantified: without the controller, mitigation waits for ad-TTL expiry
(15 min default) or a human. Falsified if the false-positive budget cannot hold at 15s
probe cadence — that trade-off curve (probe interval vs FP rate vs MTTM) is itself the
result.

### Literature pointers (verify before citing)

Gray failure (Huang et al., HotOS 2017 — differential observability is exactly the
director-vs-origin view mismatch); Google SRE book (Beyer et al., O'Reilly 2016);
failure-detector theory (Chandra & Toueg, JACM 1996). Keywords: "auto-remediation
false positive budget".

---

## Problem 4 — Load-aware redirection done right

**Status: OPEN PROBLEM.**

### Problem statement

`Director.CacheSortMethod=distanceAndLoad` is admittedly a placeholder: the switch in
`sortServerAds` (`director/sort.go`) maps `DistanceAndLoadType` to plain
`DistanceSort{}` with the comment "currently a place holder for distance (per our
parameters.yaml docs)", and `docs/parameters.yaml` says the same. Meanwhile the entire
load-signal pipeline already exists and runs. The problem: design and validate a
load-aware policy that provably improves tail latency without oscillation, given the
signal's real staleness.

### Why current SOTA does not transfer

- **Power-of-two-choices / C3-style replica selection** assumes the balancer sits on
  the request path with fresh per-request feedback. The director is *off* the data
  path: it sees load as a 15-second poll of a 5-minute Prometheus rate, never sees
  request completions, and its decision (HTTP 307 + ranked `Link` header, top
  `sourceServerAdsLimit` = 6 servers) is sticky — clients keep using a cache after
  redirect.
- Classic stale-signal risk: herding (everyone sent to the least-loaded server until
  the next poll flips it). Candidate policies must be evaluated for oscillation, not
  just mean improvement.

### Pelican's specific assets (verified end to end)

The signal pipeline, all live code:

1. XRootD emits a binary UDP monitoring stream; `metrics/xrootd_metrics.go` decodes it
   into Prometheus metrics including `xrootd_server_io_total` (declared at
   `metrics/xrootd_metrics.go:590`, 2026-07-05).
2. The director's embedded Prometheus scrapes every origin/cache
   (`web_ui/prometheus.go`, job `origin_cache_servers`).
3. `LaunchServerIOQuery` (`director/director_api.go`) runs a 15s ticker querying
   `rate(xrootd_server_io_total{job="origin_cache_servers"}[5m])` and writes
   `ServerAd.IOLoad` (JSON `io_load`, `server_structs/director.go`); `-1` = unknown.
4. `AdaptiveSort` already consumes it: final weight = DistanceWeight × IOLoadWeight ×
   StatusWeight × AvailabilityWeight (`director/sort_algorithms.go`; halving threshold
   100, factor 200).
5. Every redirect decision can record its weights: `RedirectWeights` inside
   `RedirectInfo` (`server_structs/director.go`) — offline decision forensics is a
   field away.

Known wart to fix on the way (verified): `director/advertise.go` initializes
`IOLoad = 0.0` claiming 0.0 means unknown, while the query loop uses `-1` and
`ioLoadWeightFn` treats 0.0 as a valid (perfect) load — two "unknown" conventions.

### First three steps in this repo

1. Confirm signal liveness in a running federation: `IOLoad` is surfaced per server as
   `ioLoad` in `GET /api/v1.0/director_ui/servers` (`director/director_ui.go`) —
   check whether real deployments have non-(-1) values. If the signal is dead in
   production, that finding reshapes the problem (fix the pipeline first).
2. Build the offline simulator at the sort layer — no servers needed:
   `director/sort_algorithms_test.go` already fabricates ads with set `IOLoad` and
   asserts exact `RedirectWeights` (`TestIOLoadWeightFn` and the weighted-sort tests).
   Extend that pattern into a trace replay: ≥10k synthetic requests, ≥3 cache ads, one
   hot (IOLoad ramping), a simple service-time model; compare distance-only vs
   AdaptiveSort vs candidates on p99 proxy and assignment-share oscillation.
3. Only then touch behavior: implement the real `distanceAndLoad` behind the
   already-documented enum value, dark-launched by logging would-have-been rankings
   via `RedirectInfo` without changing responses. Enum values and the default sort are
   frozen surface → pelican-change-control.

### You have a result when…

…the hotspot experiment (1 hot cache among ≥3, ≥10k-request replayed trace, load
signal delayed by the real 15s poll + 5m rate window) produces a measured comparison
vs distance-only: (a) p99 completion proxy — target ≥25% reduction; (b) oscillation —
no cache's assignment share swings >50% between consecutive 15s windows; (c) no
regression under uniform load (p50 within 5% of baseline). A negative result — stale
signal cannot beat distance at 15s granularity — quantifies the freshness the pipeline
must deliver and becomes the requirements doc for changing the poll design.

### Literature pointers (verify before citing)

Mitzenmacher "power of two choices" (IEEE TPDS 2001); C3 adaptive replica selection
(Suresh et al., NSDI 2015); "The Tail at Scale" (Dean & Barroso, CACM 2013). Keyword:
"load balancing with stale information" — a known literature line under exactly this
phrase; locate before citing.

---

## Problem 5 — Origin-controlled staleness windows (issue #3291)

**Status: OPEN PROBLEM. The most-commented open issue in the tracker (6 comments,
unlabeled, open since 2026-03-30; verified via `gh` 2026-07-06).**

### Problem statement

When an origin's ad expires (TTL 15 min), `getSortedAds` in `director/sort.go` returns
`noOriginsForNsErr` for the whole namespace — the code comment says shutting down the
origin "is the same as unplugging from the federation" — even for objects fully
present on caches. Issue #3291 (filed for IGWN's immutable gravitational-wave
datasets) asks for an origin-*declared* staleness window: "my data is immutable; serve
cached copies for W after I disappear." The research contribution is the semantics:
bounded staleness for federated caching with **authority separation** — origin
declares, registry persists, director enforces, cache serves — plus an executable
proof the bound holds.

Key signals from the thread (read it: `gh issue view 3291 -R PelicanPlatform/pelican
--comments`): one maintainer notes origin-shutdown-as-unplug is also an *authority*
decision, not just data availability; another argues the origin should declare a
validity window and suggests the **registry** (persistent — survives the outage,
unlike ads) as where it must live; an IGWN representative asked on 2026-05-21 for the
7.25 commits that supposedly made progress — unanswered in-thread as of 2026-07-06, so
check for newer motion before starting.

### Why current SOTA does not transfer

- **HTTP `stale-while-revalidate`/`stale-if-error` (RFC 5861, RFC 9111)** are pairwise
  directives between one server and one cache on the response path. Here the enforcer
  is a third party (the director) routing to caches whose contents it cannot
  enumerate, and the *authorization metadata* needed to issue tokens (`createFedTok`
  in `director/fed_token.go`; namespace ads carry auth requirements) comes from the
  very origin that is now absent.
- **CDN serve-stale/origin-shield** puts policy in the CDN operator's hands; #3291
  explicitly requires the *data owner* to control the window, because mutability
  profiles differ per origin within one federation.
- **Bounded-staleness SLAs** (session guarantees, Terry et al., PDIS 1994; Pileus,
  SOSP 2013) give the vocabulary but assume the store replicates internally; here
  "replicas" are caches that populated themselves on demand and may hold nothing.

### Pelican's specific assets

- The exact denial point is one function: `getSortedAds` (`director/sort.go`,
  `len(originAds) == 0` branch → `noOriginsForNsErr`).
- Ads are extensible: a window field on the origin ad is add-only wire evolution
  (freeze rules: pelican-architecture-contract), and
  `features/resources/feature-version-compatibility.yaml` + `features/features.go`
  give version-gating for new capabilities across mixed-version federations.
- The registry is persistent and already the trust root — the natural home per the
  issue thread (param/API work routes through pelican-config-and-flags and
  pelican-change-control).
- A purpose-built hook simulates "origin vanishes without process death":
  `fed_test_utils.FedTest.AdvertiseCancel` cancels the advertising context
  (`director.AdvertiseShutdownKey`) — the origin keeps running but its ads stop, so
  the TTL-expiry path is directly testable in-process.
- The pure-Go cache (`Cache.EnableV2`, hidden, default false — BadgerDB-backed
  `local_cache.PersistentCache`, launched in `launchers/cache_serve.go`) gives Go-side
  control over cache serve/fetch behavior without touching XRootD/xrdcl-pelican
  (pinned 1.7.1 in `images/Dockerfile`, 2026-07-05).

### First three steps in this repo

1. Read the issue thread and the denial path; enumerate *every* director decision that
   consults `originAds` beyond the 404 (token issuance in `director/fed_token.go`,
   capability predicate filtering in `getSortedAds`, PROPFIND proxying). The semantics
   doc must answer each: what happens during the window?
2. Write the semantics doc *before* code (pelican-research-methodology). Minimum:
   who declares W and where it persists; read/write/list and token issuance during W;
   behavior at W expiry; interaction with *declared* downtime (should downtime
   suppress stale-serving? decide and defend).
3. Prototype behind a hidden param: retain expired namespace metadata in a secondary
   "stale but servable" structure keyed by prefix. E2e shape: `NewFedTest` → fetch
   object through cache → `ft.AdvertiseCancel()` → pass ad TTL (short
   `Director.AdvertisementTTL` in test config; `require.Eventually`, never
   `time.Sleep` — pelican-testing-and-qa) → assert reads still redirect to the cache
   within W and 404 after W.

### You have a result when…

…the semantics doc is reviewed by maintainers (link it on #3291) **and** an e2e test
demonstrates, with declared window W and ad TTL T (run W = 4×T at test scale):
(a) 100% of reads of a cached object succeed throughout W after the origin's last ad
expiry; (b) **zero** reads succeed after W + T — the falsifiable bound, one stale read
past it falsifies the implementation; (c) 100% of writes fail immediately during the
outage; (d) a returning origin restores normal behavior within one advertisement
interval.

### Literature pointers (verify before citing)

RFC 5861, RFC 9111; session guarantees (Terry et al., PDIS 1994); Pileus consistency
SLAs (Terry et al., SOSP 2013). Keywords: "bounded staleness", "TTL-based cache
consistency", "availability under partition for read-mostly workloads".

---

## Problem 6 — Federation-in-a-box chaos harness

**Status: CANDIDATE — an enabler, not a headline: Problems 1, 3, and 5 all need its
fault-injection and measurement substrate. Promote to OPEN PROBLEM only if the
milestone below survives the two-director cohabitation question.**

### Problem statement

There is no systematic way to inject faults into a whole federation and record a
machine-readable timeline of what every component observed. Individual pieces exist
(see assets); what's missing is the harness that composes them: declare a topology,
declare a fault schedule, get back an event log that experiments can assert on.

### Why current SOTA does not transfer

- **Jepsen-class checkers** verify strong-consistency models of a single store against
  a formal spec; a federation's properties are weaker and heterogeneous (routing
  convergence, bounded staleness, heartbeat liveness), and part of the system is a
  supervised C++ subprocess (XRootD) plus an embedded Java one (OA4MP).
- **Chaos engineering practice** (Basiri et al., IEEE Software 2016) targets one
  organization's production with blast-radius controls; a research harness here must
  run in CI, deterministically, in minutes.

### Pelican's specific assets (all verified)

| Asset | Where |
|-------|-------|
| One-process federation | `fed_test_utils.NewFedTest` (`fed_test_utils/fed.go`): broker + cache + origin + director + registry + local cache in a single test process |
| Purpose-built fault hooks | `AdvertiseShutdownKey` ctx (stop advertising without killing the origin), `DirectorDiscoveryShutdownKey` (`server_utils/director_discovery.go`) — both wired into `NewFedTest` |
| XRootD restart as an injectable event | `xrootd.RestartXrootd` (`xrootd/restart.go`), already driven by `e2e_fed_tests/restart_test.go`, which asserts component health transitions (OK → ShuttingDown/Critical → OK) via `require.Eventually` |
| Downtime as an injectable mitigation | `/api/v1.0/downtime` API + `pelican downtime` CLI (Problem 3) |
| Observability to record | `metrics/health.go` component states; director Prometheus; `RedirectInfo` decision records |
| Real-binary subprocess topologies | `e2e_fed_tests/main_test.go` builds the `pelican` binary once per run |

### First three steps in this repo

1. Inventory the injectable surface (table above) as the harness spec: fault types v1
   = stop-advertising, XRootD restart, subprocess SIGKILL, downtime POST; out of scope
   v1 = network partitions (needs namespaces/containers) and clock skew (needs
   libfaketime or injection at `CorrectTimeSkew`).
2. Implement one composed fault as proof: origin stops advertising → assert director
   behavior across the TTL boundary. (Literally step 3 of Problem 5 — build once,
   share.)
3. Define the timeline format (JSON lines: timestamp, component, event, health state,
   redirect outcome) and make `restart_test.go`-style assertions consume it, so
   Problems 1/3/5 measure with the same ruler.

### You have a result when…

…the harness deterministically reproduces the #3449/#3452 cascade *class* — two
directors, one dies, assert the survivor never enters the self-sustaining empty state
PR #3452 fixed — in **< 5 minutes** wall time, in CI, emitting the machine-readable
timeline. Known risk to resolve first (also the blocker for Problem 1, step 2):
whether two director instances can cohabit a test topology without config/port
cross-talk; if not, the documented blocker plus a subprocess-only fallback design is
the deliverable.

### Literature pointers (verify before citing)

Jepsen (jepsen.io — tooling, not a paper); chaos engineering (Basiri et al., IEEE
Software 33(3), 2016). Keyword: "deterministic simulation testing" — FoundationDB's
publicly documented approach is the aspirational reference; verify specifics.

---

## Working discipline for all six problems

1. **Label honestly.** Everything stays OPEN/CANDIDATE until its milestone is met. No
   "Pelican now supports X" claims off the back of a prototype.
2. **Prediction before measurement.** Write the expected number down first —
   pelican-research-methodology owns the evidence bar.
3. **Experiments are cheap, merges are not.** External controllers, offline simulators,
   and test-only harnesses need no process; anything changing served behavior, wire
   formats, parameters, or defaults goes through pelican-change-control.
4. **Test discipline applies to research code**: no `time.Sleep`, no `TLSSkipVerify`
   in fed tests, always `ResetTestState` — see pelican-testing-and-qa. Human reviewers
   enforce these harder than linters.
5. **Negative results are deliverables.** Each milestone states what the falsified
   outcome is worth; write it up either way.

## Provenance and maintenance

Facts verified 2026-07-05/06 against `main@289fd41b` (upstream-synced 2026-07-04).
Commands below re-verify each volatile fact; run from the repo root. GitHub state
(issue/PR status, comment counts) is the most volatile — re-check before quoting.

**Check the checkout first**: `git branch --show-current`. This machine's working
tree has been found parked on the release branch `v7.25.x` while these facts are
stamped against `main`. If not on main, do not checkout — re-verify read-only against
the ref: `git grep '<pattern>' main -- <path>` and `git show main:<file>`; to *run*
main's tests without touching the tree, `git archive main | tar -x -C <tmpdir>` and
run there (both test commands below were executed that way on 2026-07-06).

| Volatile fact | Re-verify with |
|---------------|----------------|
| `distanceAndLoad` still a placeholder | `grep -n 'DistanceAndLoadType' director/sort.go` → expect "place holder" comment mapping to `DistanceSort{}` |
| XRootD container pin = 5.9.2 | `grep -n 'ARG XROOTD_VER' images/Dockerfile` → line ~316 |
| macOS build pins fork tag v5.9.2-pelican | `grep -n 'checkout v' github_scripts/osx_install.sh` |
| xrdcl-pelican pin = 1.7.1 | `grep -n 'XRDCL_PELICAN_VER' images/Dockerfile` |
| Issue #3291 open, 6 comments, unlabeled | `gh issue view 3291 -R PelicanPlatform/pelican --json state,labels,comments --jq '{state,labels:[.labels[].name],n:(.comments|length)}'` |
| PR #3452 merged (HA cascade fix), PR #3497 merged (5.9.5 revert) | `gh pr view 3452 -R PelicanPlatform/pelican --json state,mergedAt` (same for 3497) |
| `Director.AdvertisementTTL` default 15m | `grep -A5 'name: Director.AdvertisementTTL' docs/parameters.yaml` |
| `Server.AdvertisementInterval` default 1m | `grep -A9 'name: Server.AdvertisementInterval' docs/parameters.yaml` |
| `Director.OriginCacheHealthTestInterval` default 15s | `grep -A5 'name: Director.OriginCacheHealthTestInterval' docs/parameters.yaml` |
| `sourceServerAdsLimit` = 6 | `grep -n 'sourceServerAdsLimit' director/sort.go` |
| IOLoad pipeline: 15s ticker, 5m rate query | `grep -n 'xrootd_server_io_total' director/director_api.go metrics/xrootd_metrics.go` |
| IOLoad unknown-convention mismatch (0.0 vs -1) | `grep -n 'IOLoad' director/advertise.go director/director_api.go` |
| No health-driven writer of `filteredServers` | `grep -rn 'filteredServers\[' director/ --include='*.go' \| grep -v _test` → 6 writers (param, ads-downtime, registry ×2, topology, shutdown drain); none in `monitor.go` |
| Redirect health gate is self-reported only | `grep -n 'cacheNotInErrorState' director/sort.go`; source of `ServerAd.Status`: `grep -n 'OverallStatus' origin/advertise.go cache/advertise.go` |
| Downtime CLI exists (create/delete/list/update) | `go build -tags "client server" -o /tmp/pelican ./cmd && /tmp/pelican downtime --help` (CLI-only build; web UI assets not required) |
| Downtime API at `/api/v1.0/downtime` | `grep -n '"/downtime"' web_ui/ui.go` |
| HA property tests (11) pass | `go test -tags "client server" -run 'TestAfterOrdering\|TestSeenBy\|TestForwarding\|TestTimeSkew' -count=1 ./director/` → `ok` in ~1 s |
| `NewFedTest` = exactly one in-process director | read module bitmask in `fed_test_utils/fed.go` (`modules.Set(server_structs.DirectorType)` once) |
| Nightly race + JUnit analysis | `grep -n 'race_detection\|cron' .github/workflows/test-linux-scheduled.yml`; `ls .github/scripts/analyze-junit-results/` |
| `Cache.EnableV2` hidden, default false | `grep -A9 'name: Cache.EnableV2' docs/parameters.yaml` |
| `AdvertiseCancel` fault hook | `grep -n 'AdvertiseCancel' fed_test_utils/fed.go` |
| Feature version-gating mechanism | `ls features/resources/` → `feature-version-compatibility.yaml` |
| #3291 thread motion since 2026-06-23 | `gh issue view 3291 -R PelicanPlatform/pelican --json updatedAt,comments --jq '{updatedAt,n:(.comments|length)}'` |

Not executed during verification (labeled inline where prescribed): the
`docker build --target pelican-test --build-arg XROOTD_VER=...` differential build
(derived from `images/Dockerfile` stage names/ARG and the `pelican-build-server-image`
Makefile target); any live-federation probe (`/api/v1.0/director_ui/servers` verified
from route registration in `director/director_ui.go` and use in
`e2e_fed_tests/director_test.go`).
