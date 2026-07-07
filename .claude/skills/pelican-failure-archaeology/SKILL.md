---
name: pelican-failure-archaeology
description: Load this skill before re-attempting anything that looks "obviously fixable" in Pelican, or when you see symptoms that match a past incident — XRootD cache SIGABRT/core dumps, director OOM or lock wedge, "database is locked", rc tags that don't match branch history, duplicated or typo'd Prometheus metrics (xrootd_transfer_readv_segments_toal), JSON renames in server_structs, goroutine leaks at shutdown, or a revert commit you don't understand. Contains the verified incident chronicle (symptom, root cause, commit/PR evidence, status on main and release branches, lesson) plus a runbook of exact git/gh commands for doing history archaeology in this repo.
---

# Pelican Failure Archaeology

The chronicle of every major incident, revert, and dead end in this repository —
so nobody re-fights a settled battle. Every entry was re-verified against
`main@289fd41b` and live GitHub state on 2026-07-05. Commit hashes are stable;
line numbers drift, so each line-anchored claim is paired with a symbol name.

## When to use this skill

- You are about to rename a JSON key, Prometheus metric, config default, or API
  response shape and want to know if that class of change has burned us before. (It has.)
- You see a `Revert "..."` commit in `git log` and need the story behind it.
- You hit a symptom that smells historical: cache process SIGABRT, director
  OOM/deadlock, `database is locked`, JWT validation failures across servers,
  Prometheus memory blow-up, flaky shutdown tests.
- You found a TODO citing a GitHub issue and want to know if it is still real.
- You are tempted to "fix" something that looks wrong (a typo'd metric name, a
  duplicated metric, an orphaned directory) — check here first: some wrong-looking
  things are deliberate.
- You need the exact commands to trace a change: commit → PR, fix → backport,
  tag → actual commit.

**When NOT to use:**
- Diagnosing a live failure right now → `pelican-debugging-playbook` (symptom→triage table).
- The locking/launch-order/wire-freeze invariants themselves → `pelican-architecture-contract` (this file tells the stories; that one states the rules).
- Race/leak/shutdown proof techniques → `pelican-concurrency-and-shutdown-proofs`.
- XRootD bump policy, backport process, PR gates → `pelican-change-control`.
- Param deprecation mechanics and precedence → `pelican-config-and-flags`.
- Jargon (XRootD, XrdPfc, director, origin, cache, federation) → `pelican-federation-domain-reference`.

## Before reading: repo layout facts you need

- In this working clone, `upstream` = `PelicanPlatform/pelican` (authoritative);
  `origin` = a personal fork (stale). Every `gh` command must pass
  `-R PelicanPlatform/pelican` or it targets the fork.
- Release branches: `v7.N.x` per minor (e.g. `upstream/v7.25.x`, `upstream/v7.26.x`).
  Backports land there as cherry-picks with `(cherry picked from commit <sha>)`
  trailers — but not always (see entry 6's twist).
- **Local tags in this clone can disagree with upstream tags** (verified for
  `v7.25.1-rc.1`). When tag identity matters, use
  `git ls-remote upstream 'refs/tags/<tag>*'`, never the local tag.
- Entry format below: Symptom → Root cause → Evidence → Status (2026-07-05) → Lesson.

---

## 1. XRootD 5.9.x downgrade ladder (2026-05 → 2026-06, still live)

**Symptom.** A production cache (UWDF), running a v7.25.x build with XRootD 5.9.2,
repeatedly core-dumped: uncaught C++ `std::length_error ("vector::reserve")` thrown
in `XrdPfc::File::ReadOpusCoalescere` on the `File::Open()` path → SIGABRT,
~27 restarts over 5 days (full description in commit `fe785866`'s message).
XrdPfc is XRootD's proxy-file-cache plugin — the cache data plane.

**Root cause.** Upstream XRootD regression somewhere in 5.9.2–5.9.5. Not fixed in
Pelican code; managed by pinning.

**Evidence — the ladder on `v7.25.x`** (each rung shipped in an rc):

| Commit | Pin change | First rc tag containing it |
|---|---|---|
| `91d55179` | cherry-pick of PR #3488 (5.9.5) | pre-rc.1 |
| `c55115f9` | images → 5.9.5-1.1 | v7.25.1-rc.3 |
| `2336dd7f` | images → 5.9.3-1.1 | v7.25.1-rc.4 |
| `bf2d73ed` | images → 5.9.2-1.1 | v7.25.1-rc.5 |
| `fe785866` | 5.9.2 → 5.9.1 | v7.25.1-rc.7 |

On `main`: PR #3488 (merged 2026-05-30) upgraded to 5.9.5; PR #3497 reverted it
outright on 2026-06-02 (commit `72f04760`; PR body: "We've discovered issues with
5.9.5 and removed it from the osg-testing repos").

**Status (2026-07-05).** Live inconsistency: `images/Dockerfile` `ARG XROOTD_VER`
is **5.9.2 on `main`** (line 316) and **on `v7.26.x`**, but **5.9.1 on `v7.25.x`**
(line 315). Issue **#3487** ("Update xrootd to 5.9.5 in containers") is still OPEN.
Nobody has decided whether the 5.9.1 pin should flow forward — treat any XRootD
bump as contested. Bump policy: see `pelican-change-control`. Pin file locations:
see `pelican-build-and-env`.

**Lesson.** Never casually bump XRootD. Version bumps here are production
incidents waiting for a deployment; the fix ladder ran four rcs downhill.

## 2. Director OOM: ttlcache `Range` read-lock leak (2026-06)

**Symptom.** Director OOM-killed under registration churn; before dying, both
redirects and server registration stall and goroutines pile up.

**Root cause (four-link chain, from commit `eca4f46c`'s message, verified).**
1. `getAdsForPath` walked the `serverAds` cache (a `jellydator/ttlcache/v3`
   `v3.3.0` — see `go.mod`) using `Range` on every redirect.
2. `Range` releases/re-acquires the cache's internal read lock around each element
   and **leaks that lock if an entry is evicted or deleted mid-walk** — routine
   under registration churn plus TTL expiry.
3. One leaked reader is fatal: the write-preferring `RWMutex` then blocks every
   reader and writer of the cache.
4. `updateDowntimeFromRegistry` held the global `filteredServersMutex` while
   reading `serverAds` — an ABBA nesting hazard — so the wedge propagated into
   the registration path.

**Evidence.** PR **#3513** (labels: `bug, critical, director, create-patch`,
merged 2026-06-12). Fix commits: `eca4f46c` (main), `086b6278` (v7.25.x
cherry-pick, first shipped in `v7.25.1-rc.6`), `052c86a7` (v7.26.x cherry-pick).

**Status.** Fixed on `main`, `v7.25.x`, `v7.26.x`. The rules are codified in code
comments: at the `serverAds` declaration and on `getServerAdsSnapshot` in
`director/cache_ads.go` (~lines 59–61 and 89–91): iterate via
`getServerAdsSnapshot()` (or `Items()` when you need keys/Item wrappers);
**never `Range`**. Same `Items()`-not-`Range()` rule appears four times in
`director/director_advertise.go` (lines 153, 258, 550, 594) for `directorAds`.
Whether the `Range` leak was ever reported upstream to jellydator/ttlcache:
OPEN QUESTION (the commit message says it should be).

**Lesson.** Fix the class, not the call site — the fix introduced a single
snapshot idiom and documented the ban where it would be re-broken. Locking
invariants live in `pelican-architecture-contract`; proof techniques in
`pelican-concurrency-and-shutdown-proofs`.

## 3. JWT clock-skew rc fiasco (2026-05-29 → 2026-06-01)

**Symptom (process failure, not code failure).** A release-candidate line had to
be partially unwound in public: patches reverted, an rc release deleted, and a
tagged commit left orphaned off-branch.

**Timeline (all verified).**
1. PR **#3473** "Fix JWT Clock Skew Tolerance" merged to `main` 2026-05-29
   (merge `2b11d625`; labels `bug, director, create-patch`).
2. Same day, a broad manual backport `95089644` ("Patch PR #3473...") landed on
   `v7.25.x`, followed by rc.1 version-bump `b46b1f39`, and rc.1 was tagged/cut.
3. 2026-06-01: both reverted on the branch — `77b0730b` (revert of the bump),
   `f27f5edb` (revert of the patch).
4. Replaced by the narrower `6b3b2d56` "Backport director-related fixes from
   #3473" plus jwx bump `29738903` — needed because the fix uses
   `jwt.WithResetValidators`, which only exists in lestrrat-go/jwx v2.1.0+
   (today: v2.1.6 on both branches; used as `jwt.WithResetValidators(false)` in
   `VerifyWithKeysetStrict`, `token/token_verify.go`).
5. `v7.26.x` got its own backport PR **#3492** (merged 2026-06-09, commit `76f3606e`).

**The residue, verified against upstream refs 2026-07-05:**
- Upstream tag `v7.25.1-rc.1` still points at `b46b1f39` — the FIRST cut,
  which contains the later-reverted broad patch. The GitHub **release object**
  for v7.25.1-rc.1 was deleted (`gh release view v7.25.1-rc.1` → "release not found").
- Upstream tag `v7.25.1-rc.2` points at `582cd737`, which is **not an ancestor of
  `upstream/v7.25.x`** — it lives on an abandoned parallel line (preserved in this
  clone as local-only branch `v7.25.x-backup`, diverging after rc.0 `a9d4c0e1`).
- The surviving branch carries second, **untagged** "Bump versions to
  v7.25.1-rc.1/rc.2" commits (`52acb378`, `8022085a`).
- `6b3b2d56` carries two `cherry picked from` trailers (`73799b3f`, `80feb691`)
  and **neither hash is reachable from any upstream branch** — `80feb691` is on
  the abandoned line (reachable only via the orphaned rc.2 tag), `73799b3f` was
  the head of backport PR #3492 and exists here only in a local PR checkout.

**Lessons.**
- rc tags and releases are mutable during stabilization: a tag may point at a
  commit off the branch, a release may be deleted, and a "Bump versions to X"
  commit subject does not mean that commit is the tagged X.
- `-backup` branches are graveyards, not WIP.
- Never trust this clone's local tags; use `git ls-remote upstream`.

## 4. Capabilities JSON: three reverts in 16 months (2024-10 → 2026-02)

**Symptom.** Mixed-version federations break when the director's advertised
JSON changes shape: old caches/origins can't parse namespace policies.

**Root cause.** The `Capabilities` struct in `server_structs/director.go` is a
**cross-version wire format** exchanged between directors, origins, and caches.
Renaming its JSON keys is a protocol break, even when the Go code compiles fine
everywhere.

**Evidence — the three attempts:**

| Attempt | Commit(s) | Outcome |
|---|---|---|
| 1. Rename JSON to match Go names (`ba186d23`) | reverted by `7395fadd` (2024-10-10): *"I thought this change would be non-breaking but I was WRONG"* | reverted |
| 2. New Caps struct + handle old JSON | reverted by `786f4d12` (2024-11-12) | reverted |
| 3. PR **#2841** "Handle legacy Capability name gracefully" (merged 2026-02-04; includes `0e2dc1d8` `UnmarshalJSON` conversion helper and `f3291596`) | reverted by PR **#3131** → `0cfabbef` on main (2026-02-17), `3e53026c` cherry-pick on v7.24.x | reverted |

Why attempt 3 died (PR #3131 body, verbatim mechanism): old caches call
`/api/v2.0/director/listNamespaces` to build scitokens/authfile access policies;
a new v7.24 director returned JSON they didn't recognize, so they built wrong
policies. Reverted to unblock the v7.24 release.

**Status (2026-07-05, main).** The settled state is: Go field names are the new
ones, **JSON tags are frozen at the legacy names** — in `server_structs/director.go`
(`Capabilities` struct, ~lines 55–62): `PublicReads` → `"PublicRead"`,
`Reads` → `"Read"`, `Writes` → `"Write"`, `Listings` → `"Listing"`,
`DirectReads` → `"FallBackRead"`, with the comment "Note that the json are kept
in uppercase for backward compatibility". **No conversion helper survives on main**
(no `UnmarshalJSON` in `server_structs/`) — the `0e2dc1d8`/`f3291596` helpers were
part of the reverted attempt 3, not a resolution. None of #3131's proposed exits
(v3 API endpoint; dual-parsing caches; wait for a v26 breaking window) is
implemented (no `api/v3` routes in `director/`).

**Lesson.** `server_structs` JSON is frozen ABI: add fields, never rename keys.
The freeze contract itself is owned by `pelican-architecture-contract`.

## 5. Prometheus cardinality blow-up and the one-day revert-of-revert (2024-11)

**Symptom.** After new director redirection metrics shipped (`07f03a60`
"Add network label", 2024-10-09), Prometheus memory usage exploded.

**The dance.** 2024-11-21: metrics removed (`2dce0176`, PR #1760) and the
`network` labels removed (`fa7cf4db`, PR #1759). **The next day** both removals
were themselves reverted (`138e90bd`, PR #1761; `0ecb8be1`, PR #1767) because
removing published metric names/labels breaks downstream consumers — the removal
was a second compat incident on top of the first capacity incident. Cherry-picks
of the reverts (`e6771978`, `8353dd2a`) live on `v7.11.x`.

**Status (2026-07-05, main).** The permanent residue is **19 deliberately
duplicated metrics** (`grep -rn 'TODO: Remove th' --include='*.go' .` → 19),
kept across two rename waves (v7.16 and v7.25). Flagship example in
`metrics/xrootd_metrics.go` (~lines 483–501): the readv-segments counter exists
in **three generations simultaneously** — `xrootd_transfer_readv_segments_count`
(original), `..._toal` (v7.16 rename that introduced a typo), `..._total`
(v7.25 correction) — and call sites increment each generation
(e.g. `PacketsReceived.Inc()` immediately followed by `PacketsReceivedTotal.Inc()`
in `ConfigureMonitoring`, `metrics/xrootd_metrics.go:1088–1089`).

**Do NOT** "fix" the `_toal` typo or delete a duplicated metric: dashboards and
downstream OSG monitoring consume the old names. Removal requires a declared
compat break (no such window is scheduled — OPEN QUESTION).

**Lesson.** Metric names and labels are simultaneously a capacity surface
(label cardinality × memory) and a frozen compat surface (names). Add, never
rename; if you must rename, ship both and keep both for years.

## 6. SQLite `busy_timeout` retry built on a false premise (2026-04)

**Symptom.** `database is locked` errors during DB backup; the backup acted as a
DB-wide outage for readers.

**What happened.**
1. `dba0f823` (2026-04-15): raised `busy_timeout` to 30 s and added
   retry-with-backoff in `database/backup.go` — engineering around the symptom.
2. `f214d11e` (2026-04-16): found the real bug — WAL (SQLite write-ahead logging,
   which lets readers proceed during writes) **was never on**. The Go driver
   `glebarez/sqlite` wraps `modernc.org/sqlite`, whose DSN parser only honors the
   `_pragma=name(value)` form; the `_journal_mode=WAL` shorthand was **silently
   ignored**, leaving the DB in rollback-journal mode while everyone believed WAL
   was enabled.
3. `14b96918` (2026-04-16, same day): reverted the entire workaround —
   "Revert unnecessary busy_timeout bump and retry-with-backoff mechanism because
   WAL is actually on now" (−49 lines).

**Evidence & backport twist.** All three commits are on `main` inside PR **#3347**
"Fix DB backup" (merge `c2cc2cae`, 2026-04-22). `v7.25.x` has the same content via
`082764db` — a commit whose subject says "Merge pull request #3347 …" but which
**is not a merge commit** (`082764db^2` does not exist). SHA-containment checks
(`git merge-base --is-ancestor f214d11e upstream/v7.25.x`) therefore say "not
backported" while the content is fully present — see the runbook below.

**Status.** Correct DSN on both branches: `database/utils/utils.go` (~lines 24–29)
uses `_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)`.
Sequel: `4ccd3c73` (2026-07-04, main only) adds `enableSqliteWAL` in
`xrootd/xrootd_config.go` (~line 523) to put the scitokens-cpp JWKS SQLite cache
on WAL too — and it verifies the pragma took effect instead of assuming.

**Lesson.** Verify the premise before engineering around it. One
`PRAGMA journal_mode` query would have shown WAL was off. Also: config strings
that are silently ignored are a recurring Pelican trap (cf. `pelican-config-and-flags`).

## 7. July 2026 shutdown-leak purge — the nightly-race-detector cluster

**Context.** PRs never run the Go race detector: `.github/workflows/test-linux.yml`
is a `workflow_call` with `race_detection` defaulting to `false`; only
`.github/workflows/test-linux-scheduled.yml` (nightly cron `0 7 * * *`) sets
`race_detection: true`. That nightly job was added by `eb40bf5a` (2026-03-23).
Consequence: shutdown/goroutine-lifecycle races merge silently and surface up to
a day later — historically the costliest failure class in this repo.

**The cluster (2026-07-03/04, all on `main` only — none backported to `v7.25.x`
or `v7.26.x` as of 2026-07-05):**

| Commit | Defect |
|---|---|
| `d3403f1a` | web_ui: logrus `WriterLevel` pipe for the HTTP ErrorLog never closed on shutdown → goroutine + fd leak per launch |
| `1933a734` | origin: same `WriterLevel` leak in the broker reverse-connection path |
| `63b834d8` | database: only the current global DB handle closed on shutdown; others leaked |
| `94b9ed83` | database: `ServerDatabase` nil'd after `ShutdownDB` → shutdown-time SIGSEGV in late readers |
| `0b98c269` | database: directly-assigned global handle never closed |
| `3b9e4af4` | web_ui: gin-rate-limit `InMemoryStore` starts an unstoppable cleanup goroutine; one store was created per launch → goroutine leak per web-engine launch |
| `84810c33` | director: data race on `directorInfo.ad` — replaced under `directorAdMutex` but read lock-free by long-lived forwarding goroutines (`launchForwardAds`, `getDirectorToken`); fixed with `atomic.Pointer` |
| `c28544e4` | fed_test_utils: start discovery server before `LaunchModules` (test infra) |
| `b0bdd334` | fed_test_utils: the above fired the federation-discovery `sync.Once` too early, freezing stale `:8444` URLs into `globalFedInfo`; fix resets the Once |

Archaeology quirk: `b0bdd334`'s message cites hash `fe32f96e`, which does not
exist in the repo — it is the pre-rebase hash of `c28544e4`. Commit messages can
reference hashes that were rewritten before merge.

**Lesson.** Everything launched must be shut down, and tests must prove it.
Proof recipes: `pelican-concurrency-and-shutdown-proofs`. Measurement/flake
hunting: `pelican-diagnostics-and-tooling`. Test idioms: `pelican-testing-and-qa`.

## 8. Authfile/defaults wholesale revert — the earliest defaults incident (2023-12)

**What happened.** PR **#500** "Pelican authfile fix" (merged 2023-12-14 15:51 UTC)
moved the default locations of generated XRootD files — e.g. `Xrootd.Authfile`
default moved from the config dir to the run dir and was renamed
`authfile-generated` — and gated topology reload behind the OSDF flag. It was
reverted **wholesale ~45 minutes later** (`d3f05d9a`, 16:36 UTC, reverting merge
`1313facf`), restoring the `viper.SetDefault` lines in `config/config.go`
(`Xrootd.RobotsTxtFile`, `Xrootd.ScitokensConfig`, `Xrootd.Authfile`,
`Xrootd.MacaroonsKeyFile`).

**Lesson.** Config defaults are a production compatibility surface — changing a
default path breaks running deployments as surely as an API break. This is the
oldest instance of the rule "never change a default or remove a deprecated param
without a deprecation cycle" (policy: `pelican-change-control`; mechanics:
`pelican-config-and-flags`).

## 9. Drop-privileges raw-syscall revert (2025-07)

**What happened.** `syscall.Setuid`/`Setgid` panicked when CGO was disabled, so
`7fd60592` (in PR #2476) rewrote `launchers/droppriv_unix.go` to use **raw
syscalls**, bypassing Go's `AllThreadsSyscall` mechanism — dangerous, because
uid/gid changes must apply to all OS threads. Four days later `4d0e3e63`
(in PR **#2488** "Enable CGO for the binary build that includes purego") reverted
it: the correct fix was to enable CGO for that build, not to bypass the runtime
guarantee.

**Status.** `main` uses plain `syscall.Setgid`/`Setuid` in
`dropPrivileges` (`launchers/droppriv_unix.go`, ~lines 48/52). The raw-syscall
version was cherry-picked to `v7.17.x` (`e5a4b4c3`) and the revert never was —
`v7.17.x` still contains raw syscalls (that branch is long-dead; do not build from it).
Related follow-on: `9257ac88` (in PR #3457, 2026-06) routes cache test-file
eviction through the evict API when `Server.DropPrivileges` is on, because the
unprivileged process cannot delete files directly.

**Lesson.** Privilege-drop code is repeat-offender territory. Prefer fixing the
build configuration over bypassing runtime guarantees; anything touching
uid/gid/threads needs an all-threads argument written down.

## 10. Pin drift: xrootd-s3-http and the OSG dnf repo list

**Incident A — a revert that de-synced its own pins.** `57e3bb82` (2026-01-26)
"Revert 'Bump version of xrootd-s3-http to v0.6.2'" set
`github_scripts/osx_install.sh` back to **v0.6.1** but `images/Dockerfile`
(`ARG XROOTD_S3_HTTP_VER`) back to **0.6.0** — the two pin locations are
hand-synchronized and this "revert" left them inconsistent. Today (main) both
say 0.6.7 (`osx_install.sh:93`, `Dockerfile:92`) — currently in sync, by hand.

**Incident B — the dnf repo list is not ours.** `0e982404` (2025-12-08) re-adds
the `osg-development` repo after its removal broke container builds;
`e497639b` (2026-06-11, on `v7.25.x`, cherry-pick of main's `34c62796`) removes
`osg-upcoming` because "changes in upstream build targets ... preventing
container builds". The OSG packaging team owns that repo list; it changes under us.

**Lesson.** Version pins live in multiple files with no automation keeping them
equal; every bump/revert must touch all of them (locations enumerated in
`pelican-build-and-env`; ecosystem ownership in `pelican-ecosystem-and-upstreams`).

## 11. Meta-entries: lineage, stale issue pointers, dead code that looks alive

**Repo lineage — PR-number collision trap.** `main` has TWO root commits:
`7c8602dc` (2020-06-24, "Initial commit") from the **stashcp** era, and
`df23f463` (2023-06-12, "Initial skeleton of the `pelican` CLI"). The repo began
as `stashcp` (first Go version `ca50faed`, 2021-03-18; module renamed to
`opensciencegrid/stashcp` in `9f0a9fc0`, 2021-09-23) — pre-mid-2023 history is a
different product. Verified trap: commit `3b3a976c` (2022-08-16) says
"Merge pull request #57 from djw8605/fix-stash-plugin", but
`gh pr view 57 -R PelicanPlatform/pelican` returns an unrelated PR ("Bump go
version in the publish-container action"). **PR numbers in commits dated before
2023-06 belong to `opensciencegrid/stashcp`, not this repo.**

**Closed-issue TODOs — issue closed ≠ code fixed.** Verified 2026-07-05:

| Issue | State | TODO still in code at |
|---|---|---|
| #1391 (consolidate healthTestUtils/statUtils maps) | CLOSED | `director/director.go:143` — the maps still exist |
| #1540 (director stopped sending `base-path`) | CLOSED | `director/director.go:432` |
| #1929 (skip director lookup for local cache) | CLOSED | `local_cache/cache_test.go:393` |
| #2709 (servers declare own location — UI follow-up) | CLOSED | `director/sort_utilities.go:413` |
| #3107 (test file transfer util cleanup) | **OPEN** | `server_utils/test_file_transfer.go:78` |

Issues get closed without the annotated code changing. Never treat a closed
issue as evidence the TODO is done; check the code.

**Dead code that looks alive.**
- `requiresCacheChaining` (`director/director.go:618`) — the TODO above it
  (line 612) states the feature "has never been turned on in production". Do not
  assume that path is battle-tested; do not build on it without flagging.
- `registry/migrations/` (3 SQL files) is **orphaned**: zero Go references, no
  `go:embed` (verify: `grep -rn 'registry/migrations' --include='*.go' .` → empty).
  Live migrations are `database/{universal,registry,origin}_migrations`.
  Whether the orphan is kept deliberately: OPEN QUESTION.

---

## How to do archaeology here — mini-runbook

Run everything from the repo root. `upstream` = `PelicanPlatform/pelican`.
This repo merges PRs as merge commits ("Merge pull request #N from ...");
recent `main` commit subjects use `component:` prefixes (`director:`, `web_ui:`,
`database:`, `xrootd:`, `fed_test_utils:`).

**1. Find reverts (46 on main as of 2026-07-05):**
```bash
git log --oneline --grep='^Revert' main            # list them
git log --oneline --grep='^Revert' main | wc -l    # → 46
```
The revert message names the reverted sha: `git show -s <revert-sha>` →
"This reverts commit <sha>." Then `git show <original-sha>` for the other side.

**2. Find when a symbol/string appeared or died (pickaxe):**
```bash
git log --oneline -S 'getServerAdsSnapshot' main -- director/
# → eca4f46c Stop iterating the live serverAds cache under its own lock
```

**3. Commit → PR (needs the FULL 40-char sha; commit must exist upstream):**
```bash
gh api repos/PelicanPlatform/pelican/commits/$(git rev-parse eca4f46c)/pulls \
  -q '.[]|"\(.number)|\(.title)"'
# → 3513|Stop iterating the live serverAds cache under its own lock
```
A short sha you pad by guessing digits will 422 with "No commit found" — always
`git rev-parse` first. PR details/labels/base:
`gh pr view 3513 -R PelicanPlatform/pelican --json title,state,mergedAt,labels,baseRefName`.

**4. Is a fix on a release branch / in a release? Three checks, in order:**
```bash
# (a) sha containment — fast but can lie (see caveat)
git merge-base --is-ancestor eca4f46c upstream/v7.26.x && echo yes || echo no   # → no
# (b) cherry-pick trailer — finds the backport's own sha
git log --all --oneline --grep='cherry picked from commit eca4f46c'
# → 086b6278 Stop iterating the live serverAds cache under its own lock
# (c) subject search on the branch — catches trailer-less backports
git log upstream/v7.26.x --oneline --grep='serverAds cache under its own lock'
# → 052c86a7 ...
```
Then map to shipped releases: `git tag --contains 086b6278` → `v7.25.1-rc.6`, `v7.25.1-rc.7`.
**Caveat (verified, entry 6):** content can be present without sha ancestry —
PR #3347 reached `v7.25.x` as `082764db`, a non-merge commit wearing a
"Merge pull request #3347" subject (`082764db^2` doesn't exist). When (a) says
no, run (b) and (c), and if still unsure, diff the file itself:
`git show upstream/v7.25.x:database/utils/utils.go | grep _pragma`.

**5. Tags: trust upstream, not this clone.**
```bash
git ls-remote upstream 'refs/tags/v7.25.1-rc.1*'
# → b46b1f39...  (local `git rev-parse v7.25.1-rc.1` gives a DIFFERENT sha here)
```
A tag may point off-branch (entry 3: `v7.25.1-rc.2` → `582cd737`, not an
ancestor of `upstream/v7.25.x`). Check with `git merge-base --is-ancestor`.

**6. Who wrote this line and why:**
```bash
git blame -L 56,62 director/cache_ads.go   # sha per line → feed into step 3
```

**7. Repo-specific gotchas checklist:**
- [ ] Pass `-R PelicanPlatform/pelican` to every `gh` command (`origin` is a fork).
- [ ] Commit dated before 2023-06? Its "PR #N" is a stashcp PR, not this repo's.
- [ ] Commit message cites a sha that doesn't exist? Likely a pre-rebase hash
      (verified: `b0bdd334` → `fe32f96e`).
- [ ] "Merge pull request #N" subject on a release branch may not be a merge commit.
- [ ] Issue number in a TODO? `gh issue view N -R PelicanPlatform/pelican --json state`
      — CLOSED does not mean the code changed (entry 11).
- [ ] The `create-patch` PR label marks backport intent; backports are separate
      manual PRs/pushes per release branch, not automated.

## Provenance and maintenance

All facts verified 2026-07-05 against `main@289fd41b`, `upstream/v7.25.x@f25a879b`
(= tag v7.25.1-rc.7), `upstream/v7.26.x`, and live GitHub via `gh` (read-only).
Every command above was executed at least once on that date. Volatile facts and
how to re-check them cheaply:

| Fact (as of 2026-07-05) | Re-verify with |
|---|---|
| XRootD pin: main+v7.26.x=5.9.2, v7.25.x=5.9.1 | `grep XROOTD_VER images/Dockerfile; git show upstream/v7.25.x:images/Dockerfile \| grep XROOTD_VER` |
| Issue #3487 (xrootd 5.9.5) still OPEN | `gh issue view 3487 -R PelicanPlatform/pelican --json state` |
| Lock-leak fix on all 3 branches (`eca4f46c`/`086b6278`/`052c86a7`) | runbook step 4 with `eca4f46c` |
| `Range` ban comments in `director/cache_ads.go:59-61,89-91` | `grep -n 'Do not use Range' director/cache_ads.go` |
| ttlcache dep v3.3.0 | `grep ttlcache go.mod` |
| Upstream tag rc.1→`b46b1f39`, rc.2→`582cd737` (off-branch); rc.1 release deleted | `git ls-remote upstream 'refs/tags/v7.25.1-rc.*'`; `gh release view v7.25.1-rc.1 -R PelicanPlatform/pelican` |
| `v7.25.x-backup` is local-only | `git ls-remote upstream 'refs/heads/v7.25.x*'` |
| Capabilities JSON tags frozen; no UnmarshalJSON in server_structs | `grep -n 'json:"PublicRead"' server_structs/director.go; grep -rn UnmarshalJSON server_structs/` |
| 19 duplicated-metric TODOs; `_toal` typo metric alive | `grep -rn 'TODO: Remove th' --include='*.go' . \| wc -l; grep -n toal metrics/xrootd_metrics.go` |
| SQLite DSN `_pragma=` form on both branches | `grep -n _pragma database/utils/utils.go` |
| Shutdown-purge cluster main-only (not on v7.25.x/v7.26.x) | `for c in d3403f1a 3b9e4af4 84810c33; do git merge-base --is-ancestor $c upstream/v7.26.x \|\| echo "$c not backported"; done` |
| Nightly-only race detector (`race_detection` default false) | `grep -n race_detection .github/workflows/test-linux.yml .github/workflows/test-linux-scheduled.yml` |
| s3-http pins in sync at 0.6.7 | `grep XROOTD_S3_HTTP_VER images/Dockerfile; grep 'xrootd-s3-http' github_scripts/osx_install.sh` |
| Closed-issue TODO table (5 rows) | `for i in 1391 1540 1929 2709 3107; do gh issue view $i -R PelicanPlatform/pelican --json number,state -q '"\(.number):\(.state)"'; done` |
| `requiresCacheChaining` never-in-prod TODO | `grep -n -B6 'func requiresCacheChaining' director/director.go` |
| `registry/migrations/` orphaned | `grep -rn 'registry/migrations' --include='*.go' .` (expect empty) |
| Revert count on main = 46 | `git log --oneline --grep='^Revert' main \| wc -l` |
| Two root commits (`7c8602dc`, `df23f463`) | `git rev-list --max-parents=0 main` |

Line numbers cited (Dockerfile:316/315, cache_ads.go:59-91, director.go:143/432/612/618,
xrootd_metrics.go:483-501/1088, utils.go:24-29, droppriv_unix.go:48/52,
sort_utilities.go:413, cache_test.go:393, test_file_transfer.go:78) are
main@289fd41b anchors — expect drift; search the paired symbol name instead.
