---
name: pelican-research-methodology
description: Load when turning a hunch into an accepted result in the Pelican repo — diagnosing a root cause ("I think the bug is...", "the mechanism is...", "root cause found"), designing an experiment, deciding whether evidence is sufficient to merge a fix, reviewing someone else's diagnosis, promoting or retiring an experimental feature, or writing an investigation/design doc. Contains the evidence bar with worked positive/negative examples from this repo's history, the predict-numbers-first rule with executed measurements, the idea lifecycle (hidden params → experimental builds → stabilization or retirement), an adversarial-refutation checklist with commands, and a copy-pasteable investigation template.
---

# Pelican Research Methodology: From Hunch to Accepted Result

This skill encodes how investigation results get accepted in this repository, grounded
entirely in verified episodes from its own history. The written seed of this discipline
is `AGENTS.md` (top of file): *"When presented with an issue or bug, always ask: Is this
an isolated bug, or does it represent a class of bugs that can be fixed?"* Everything
below is that principle, operationalized.

Convention for this document: run all commands from the repo root unless stated
otherwise. All command outputs shown were actually executed on 2026-07-05 against
`main@289fd41b` unless marked otherwise.

## When to use this skill

- You have a hypothesis about a bug's root cause and are deciding whether it is proven.
- You are about to build a fix on top of an assumption ("since WAL is on...", "since
  the library tolerates skew...").
- You are asked to review/refute someone else's diagnosis or optimization.
- You are proposing an experiment and need the prediction-table format.
- You want to ship an experimental feature, flip a default, or retire a failed idea.
- You are writing up an investigation, incident, or design and need the house format.
- Task phrases in context: "root cause", "I believe the mechanism is", "how do we know",
  "is this evidence enough", "hidden parameter", "experimental release", "design doc",
  "post-mortem", "was this tried before".

### When NOT to use

- Symptom-to-triage lookup for a live failure → **pelican-debugging-playbook**.
- What actually happened in a past incident (full story, commits) → **pelican-failure-archaeology**.
- How to run the race detector, profilers, metrics → **pelican-diagnostics-and-tooling**.
- Race/leak/shutdown proof recipes specifically → **pelican-concurrency-and-shutdown-proofs**.
- Gating/review/backport rules for landing the resulting change → **pelican-change-control**.
- Which open problems are worth researching → **pelican-research-frontier**.
- Doc pipelines and house style for docs-of-record → **pelican-docs-and-writing**.

## 1. The evidence bar

**A diagnosis is accepted when ONE mechanism explains EVERY observation — including the
negative ones — and survives an assigned refutation pass (section 4). A theory that
explains only the headline symptom is not a diagnosis; it is a hunch.**

### Worked positive: the serverAds/ttlcache lock-leak (June 2026)

Context: the director is the federation's redirect service; `serverAds` is its in-memory
TTL cache of server advertisements, backed by `github.com/jellydator/ttlcache/v3`
(jargon: see **pelican-federation-domain-reference**; locking invariants owned by
**pelican-architecture-contract**). Directors were being OOM-killed in production.
Evidence source: commit `eca4f46c` ("Stop iterating the live serverAds cache under its
own lock", 2026-06-11, main) and PR #3513 (`bug, critical, director, create-patch`);
the incident story is owned by **pelican-failure-archaeology**.

Two candidate theories against the observation set:

| # | Observation (from `git show eca4f46c` / PR #3513) | Theory A: "memory pressure — raise limits" | Theory B: "ttlcache `Range` leaks its read lock on mid-walk eviction; ABBA nesting spreads the stall" |
|---|---|---|---|
| O1 | Director memory grows until OOM-kill | Explains (delays recurrence) | Explains: blocked goroutines pile up behind the wedged write-preferring RWMutex |
| O2 | New server registrations stall at the same time | Does NOT explain | Explains: `updateDowntimeFromRegistry` held `filteredServersMutex` while reading the wedged `serverAds` |
| O3 | Onset correlates with registration churn + TTL expiry, not with fleet size | Does NOT explain | Explains: the leak requires an entry evicted/deleted mid-`Range`-walk |
| O4 | Restart clears it; symptom recurs | Does NOT explain (recurs at any ceiling) | Explains: a fresh process holds no leaked lock |

Theory A explains one observation of four. Theory B explains all four. Only B was
accepted, and it was accepted at the *class* level: the fix replaced every `Range` walk
with a snapshot idiom and codified the prohibition in code — `director/cache_ads.go`
comment at the `serverAds` declaration: "Do not use Range, which is not safe to iterate
concurrently with cache writes."

```bash
grep -n 'Do not use Range' director/cache_ads.go
# 61:	// Item wrappers). Do not use Range, which is not safe to iterate concurrently with cache writes.
```

### Worked negative: the SQLite retry built on an unverified premise (April 2026)

Symptom: `SQLITE_BUSY` / "database is locked" during the periodic `VACUUM INTO` backup.
The response was engineered on the premise that WAL (SQLite write-ahead-logging journal
mode, where readers don't block on writers) was already enabled — the DSN string
contained `_journal_mode=WAL`, so it *looked* enabled:

| Step | Commit | What happened |
|---|---|---|
| Build on premise | `dba0f823` | Raise `busy_timeout` to 30 s for the backup |
| Build more | `d715eb78` | "Handle transient SQLITE_BUSY errors with retries" |
| Premise falsified | `f214d11e` (2026-04-16) | glebarez/sqlite (modernc.org) only honors `_pragma=name(value)` DSN form; the `_journal_mode=WAL` shorthand was **silently ignored** — the DB had been in rollback-journal mode the whole time, so readers blocked on writers by design |
| Machinery retired | `14b96918` (same day) | "Revert unnecessary busy_timeout bump and retry-with-backoff mechanism because WAL is actually on now" |

```bash
git show 14b96918 -s --format='%s'
# Revert unnecessary busy_timeout bump and retry-with-backoff mechanism because WAL is actually on now
```

The missing step was one direct observation before building: open the live database and
run `PRAGMA journal_mode;` — it would have returned `delete`, not `wal`. Two commits of
retry machinery were built, reviewed, and merged to treat a symptom of a premise nobody
had checked.

### The premise-verification rule

**Every "given that X" in your reasoning chain must be backed by a direct observation,
not by configuration that claims X.** Config strings, DSN parameters, YAML defaults, and
dependency versions are *claims*; observe the effect.

Second micro-example, same failure class: the v7.25.1-rc.1 tag (`b46b1f39`, upstream)
was cut on a cherry-pick (`95089644`, the JWT clock-skew patch) that called
`jwt.WithResetValidators` — an API that exists only in jwx ≥ v2.1.0, while the branch's
`go.mod` pinned v2.0.21. The premise "the cherry-pick compiles against the release
branch's dependency set" was never checked. Executed verification (scratch clone):

```bash
# in a scratch clone: git checkout b46b1f39 && go build ./token/
# token/token_verify.go:338:7: undefined: jwt.WithResetValidators
```

Consequence: no `v7.25.1-rc.1` release artifacts exist (`gh release list -R
PelicanPlatform/pelican` jumps rc.0 → rc.2), the patch and version bump were reverted
(`f27f5edb`, `77b0730b`), and a narrower backport plus the jwx bump (`6b3b2d56`,
`29738903`) replaced them. Full story: **pelican-failure-archaeology**.

## 2. Predict numbers before running

**A hypothesis without a numeric prediction (a value, a range, or an exact error string)
is not yet testable. Sharpen it until it forecasts one, write the forecast down, then
measure.** Writing the prediction first is what distinguishes confirmation from
curve-fitting: if you look at the measurement first, any theory can be adjusted to "explain" it.

### The prediction table (mandatory format for experiments)

| Hypothesis | Measurement (exact command) | Predicted value/range | Actual | Verdict |
|---|---|---|---|---|
| ... | ... | ... | ... | CONFIRMED / REFUTED / AMBIGUOUS |

Rules: fill the first three columns before running anything; never edit the "Predicted"
column after measuring; an AMBIGUOUS verdict means the experiment was underpowered —
design a sharper one, do not argue the result.

### Worked example: the JWT clock-skew episode

Background: Pelican servers authenticate to each other with JWTs (JSON Web Tokens);
`iat`/`nbf`/`exp` are the issued-at/not-before/expiry claims. Operators reported
registration failures with the exact error `"iat" not satisfied` while insisting "both
clocks are more or less correct" (issue #3254, with debug logs in the body). The fix was
PR #3473 (merge `2b11d625`). Applied prediction-first, the investigation is two rows:

| Hypothesis | Measurement | Predicted | Actual (executed 2026-07-05, scratch clone) | Verdict |
|---|---|---|---|---|
| Pre-fix validation tolerates 0 s of issuer-ahead skew (jwx default), so even sub-second offsets fail after second-truncation | Sign token with `iat = now + N`; parse via the pre-fix call form `jwt.Parse(tok, jwt.WithVerify(false))` for N ∈ {0, 5, 30, 61 s} | Pass at 0; fail with `"iat" not satisfied` for all N ≥ 1 s | `skew=0s err=nil; skew=5s/30s/1m1s err="iat" not satisfied` | CONFIRMED |
| Post-fix tolerance is exactly `ClockSkewLeeway` = 60 s (token/token_verify.go, WLCG Common JWT Profile recommendation) | Same tokens through `token.VerifyWithKeyset` at N ∈ {0, 30, 59, 61, 300 s} | Pass ≤ 60; fail > 60 | Pass at 0/30/59 s; `"iat" not satisfied` at 61 s and 5 m | CONFIRMED |

The probe is ~20 lines dropped into `token/` of a scratch clone (recipe in section 4,
step R3); the boundary tests that now guard this permanently are
`TestVerifyWithKeyset_IatNbf{Within,Exceeds}Leeway` in `token/token_verify_test.go`.

Two payoffs the prediction table buys here:

1. It converts the operators' unresolvable claim ("clocks look fine") into a sharp one:
   with zero tolerance and second-truncation, *any* positive sub-second offset can fail —
   so "clocks are fine" and "iat not satisfied" stop being contradictory.
2. It pins the fix's contract to a number (60 s, non-configurable, also extends `exp` by
   60 s — an explicitly accepted tradeoff, documented in the PR #3473 body). Anyone
   later observing a 45 s-skewed token being accepted knows it is by design, not a bug.

For measurement tooling (pprof, metrics, race detector, log levels) see
**pelican-diagnostics-and-tooling**.

## 3. Idea lifecycle in this repo (as actually practiced)

Every mechanism below is verified to exist. Route any *promotion* (default flip,
deprecation, backport, version bump) through **pelican-change-control**.

| Stage | Mechanism | Verified evidence (2026-07-05) |
|---|---|---|
| 0. Parked idea | Issue in tracker; `parking-lot` milestone for unscheduled work | `gh api repos/PelicanPlatform/pelican/milestones` → parking-lot: 12 open / 61 closed |
| 1. Experimental toggle | `hidden: true` param in `docs/parameters.yaml` ("true to hide from public documentation" per the file's header comment) | `grep -c '^hidden: true' docs/parameters.yaml` → 58 |
| 2. Experimental builds | Upstream branch `experimental` + tags `vX.Y.Z-experimental.N`; goreleaser builds real RPMs from them | `gh release list` shows v7.27.0-experimental.0/1, v7.25.0-experimental.0–11, and v7.25.0-experimental+ADIOS.backend; `git rev-list --count main..upstream/experimental` → 23 |
| 3a. Stabilize: merge to main; flip a default only via a deprecation cycle | `deprecated: true` + `replacedby:` in parameters.yaml; `handleDeprecatedConfig` in `config/config.go` warns and maps old→new | 24 `deprecated: true` entries. Mechanics owned by **pelican-config-and-flags** |
| 3b. Stabilize: mixed-version gating | `features/resources/feature-version-compatibility.yaml` compiled into `features/features.go`; director filters caches via `ServerSupportsFeature` (features/feature_compatibility.go) and `cacheSupportsFeature` (director/sort.go) | One feature today: `CacheAuthz` (NotBeforePelican v7.16) |
| 4. Documented retirement | Revert with a lessons-learned commit message; graveyard branch; parking-lot | `7395fadd`: "I thought this change would be non-breaking but I was WRONG"; `14b96918` (section 1); local branch `v7.25.x-backup` preserves the abandoned rc line |

Traps and honest caveats:

- **`features/` is NOT a feature-flag system.** It is inter-server version-compatibility
  metadata. Experimental behavior is gated by ordinary `hidden: true` params.
- **Main's `release.yml` does not build experimental tags.** Its tag patterns cover only
  `vX.Y.Z` and `-rc.N`; the `-experimental.[0-9]+` pattern was added on the
  `experimental` branch itself (commit `c02ec8b4`, reachable from the experimental tags
  but not from main). If you cut an experimental tag from a branch without that pattern,
  no artifacts appear.
- **A stage-2 resident example:** the ADIOS storage backend was merged to the
  `experimental` branch (`e6480f7e`) and shipped as `v7.25.0-experimental+ADIOS.backend`
  (2026-03-31), but is absent from main as of 2026-07-05 (`git log main -i
  --grep=adios` → empty). Ideas can live at stage 2 indefinitely; that is a supported
  state, not an error — but label such ideas "candidate", never "adopted" (section 6).
- **`v7.25.x-backup` is a local branch in this checkout only** (`git ls-remote --heads
  <upstream> | grep backup` → empty). The abandoned line's commits stay reachable
  upstream via the orphaned rc tags, but the branch name is this machine's convention.
  rc tags get re-cut; `-backup` branches are graveyards, not WIP.

## 4. Adversarial refutation protocol

**Before an investigation result is accepted, someone other than the author is ASSIGNED
to refute it.** A second AI session, given the write-up and this repo, counts as
"someone". The refuter's deliverable is either (a) a surviving objection or (b) an
explicit statement: "I attempted R1–R5 below; the result survived." Silence is not
acceptance.

### Refuter's checklist

**R1. Does the mechanism explain every observation, including negatives?**
Demand the observation-vs-theory table (section 1). Any cell where the accepted theory
"does not explain" is a live objection.

**R2. Does a cheaper mechanism explain the same set?**
Enumerate at least one rival theory and state which observation kills it. If you cannot
name the observation that kills the rival, the experiment set is incomplete.

**R3. Does the fix's test fail on the pre-fix code?**
Read-only recipe (executed 2026-07-05; local clone, source repo untouched):

```bash
SCRATCH="$(mktemp -d)"
git clone -q --shared /path/to/pelican "$SCRATCH/pelican-refute"
cd "$SCRATCH/pelican-refute"
git checkout -q <fix-commit>^                      # pre-fix tree
git checkout -q <fix-commit> -- <path/to/new_test.go>
go test ./<package>/ -run '<NewTestName>' -count=1
```

Expected outcomes and how to read them:

| Outcome on pre-fix code | Meaning |
|---|---|
| Test FAILS (assertion) | Strongest evidence: the test captures the fixed behavior |
| `FAIL [build failed]` — e.g. `undefined: VerifyWithKeyset` (observed for PR #3473's tests) | Degenerate pass: the fix introduced new API, so the test can't compile. Fall back to a behavior probe against the *old* call form (as in section 2's first table row) |
| Test PASSES | Objection: the test does not discriminate; the fix is unverified by its own tests |
| No test shipped with the fix | Flag it. This happens even for critical fixes here — `eca4f46c` (the serverAds fix) shipped with zero test files; its acceptance rested on mechanism-level reasoning (R1) alone |

**R4. Does the timeline match?** When did the bug ship vs. when did symptoms start?

```bash
git log --oneline --reverse -S 'serverAds.Range' | head -2   # find the introducing commit
# 8a5aec4b Don't stat more caches than Director intends to provide to sort
# eca4f46c Stop iterating the live serverAds cache under its own lock
git tag --contains 8a5aec4b | sort -V | head -3              # first tags carrying the bug
# v7.25.0
# v7.25.0-rc.0
# v7.25.0-rc.1
```

(Caveat: `sort -V` orders `v7.25.0` before its own rc tags; eyeball the list.)
Worked check: the `Range` call entered `getAdsForPath` on 2026-03-23 (`8a5aec4b`),
first shipped stable in v7.25.0 (2026-05-18); director OOMs were reported after the
v7.25.0 rollout; fix landed 2026-06-11. Timeline consistent. **If symptoms predate the
first tag containing the suspect commit, the mechanism is wrong or incomplete — stop.**
The complementary question "has the fix shipped yet?" is the same command on the fix:
`git tag --contains eca4f46c` → only `v7.27.0-experimental.0/1` from main;
the cherry-pick `086b6278` → `v7.25.1-rc.6/7`.

**R5. Is every premise observed, not assumed?** (Section 1's rule.) Walk the write-up's
"given that" statements; each needs a command and its output next to it.

### Refutation applies to optimizations, not just diagnoses

The `Range` bug's own origin is the cautionary tale: `8a5aec4b`'s commit message records
that switching `Items()` → `Range` was "a small performance issue brought up by Claude
related to calling '.Items()' on TTL caches." A plausible AI-suggested micro-optimization
was accepted with no one assigned to ask *"what are Range's locking semantics under
concurrent eviction?"* — and became a production OOM and an emergency patch across two
release lines. Any change justified by the word "performance" needs the same R1–R5
treatment, plus a number from section 2 (predicted speedup, measured speedup).

## 5. Where good ideas came from here

Mined from history; every episode verified. The pattern to imitate is in the last column.

| Source | Verified episode | What it turned into |
|---|---|---|
| Production incident → codified invariant | serverAds OOM (`eca4f46c`) | An in-code prohibition at the data structure itself (`director/cache_ads.go`: "Do not use Range...") plus a single blessed idiom (`getServerAdsSnapshot`). Invariant now owned by **pelican-architecture-contract** |
| Nightly instrumentation → systematic purge | `eb40bf5a` (2026-05-20) added nightly `-race` runs (`test-linux-scheduled.yml`, cron `0 7 * * *`, `race_detection: true`) precisely because PRs never pay the 2–3x overhead → inventory issue #3489 (2026-05-30, each race documented with its shared state) → fix cluster of 2026-07-03/04 (`d3403f1a`, `63b834d8`, `3b9e4af4`, `84810c33`, `b0bdd334`) | A repeatable loop: pay for instrumentation on a schedule, harvest findings into one inventory issue, burn the list down. See **pelican-concurrency-and-shutdown-proofs** for the proof recipes |
| Operator/user pain → features | Label `Facilitation` = "A request from the RCF's" (research-computing facilitators — expansion inferred from OSG usage, UNVERIFIED in-repo); e.g. #2858 (`--direct` flag, closed/shipped). Issue #3254: "a growing number of user reports" with debug logs → PR #3473 | Error strings reported by operators became test-suite boundary cases (`"iat" not satisfied` → `token/token_verify_test.go`) |
| Upstream constraint-fighting → forks/patches | `PelicanPlatform/xrootd` is a fork: "Pelican Platform's source branches and patches for the XRootD suite" (`gh repo view`). The ttlcache `Range` leak was noted in `eca4f46c` as "an upstream ttlcache bug worth reporting separately" while Pelican was made robust regardless | Fix locally for robustness first, report upstream second; never block on upstream. Repo constellation: **pelican-ecosystem-and-upstreams** |

**Implication — instrument first, theorize second.** The race purge did not come from
reading code harder; it came from buying measurements (nightly `-race`) and letting the
instrument generate the worklist. When starting an investigation, your first question is
"what instrument would make this bug class visible?", not "what do I think is wrong?"

## 6. Write-up standards

### When a design doc is warranted

Write one when the work is **cross-component**, **wire-format-adjacent** (anything
touching `server_structs` JSON, Prometheus metric names/labels, or director APIs — freeze
contract owned by **pelican-architecture-contract**), or expected to run **longer than
two weeks**. The repo's three exemplars (the complete set of `*design*.md` files as of
2026-07-05):

| File | Scope | Noteworthy practice |
|---|---|---|
| `docs/collections-design.md` | Collections/shares: origin + registry + tokens + web UI | Attribute tables; explicit example usage scenario |
| `docs/user-group-design.md` | User/group entities and authz semantics | MUST/SHOULD normative language for invariants |
| `client_agent/DESIGN-CLIENT-API-SERVER.md` | Client agent REST server | The only one with an explicit `**Status:**` header and per-phase completion marks — copy this |

### Investigation notes belong in the issue, not chat

CI enforces the substrate: every PR must carry ≥1 label and ≥1 linked closing issue
(`.github/workflows/enforce-PR-labelling.yml`; known limitation in the file's own
comment — sidebar link/unlink events don't re-trigger the check, so re-run it manually
after linking). Model artifacts to imitate:

- Issue #3489 — a race *inventory*: each entry names the shared state and the racing
  accessors. An inventory issue outlives any chat session and feeds a fix cluster.
- Issue #3254 — operator debug logs pasted verbatim into the body; the exact error
  string `"iat" not satisfied` in the issue is what made the episode searchable later.
- PR #3473 body — full mechanism write-up: root cause, library semantics, the numeric
  contract (60 s), and the accepted tradeoff, all in the merge record.
- Commit messages as archive: `eca4f46c` and `f214d11e` carry the complete mechanism.
  Future archaeology (see **pelican-failure-archaeology**) reads commits, not Slack.

### Status labeling discipline for claims

Every claim, idea, or recommendation in any handoff/design/investigation doc carries one
of four statuses. (This is the convention of this handoff library — prescriptive; among
in-repo docs only the client_agent design doc currently practices explicit status.)

| Status | Meaning | Exit criteria |
|---|---|---|
| `open` | Question; no experiment run | A prediction table exists |
| `candidate` | Mechanism proposed; some evidence; not refutation-tested | Survived section 4 |
| `adopted` | Survived refutation; landed via **pelican-change-control** | — (may still be retired) |
| `retired` | Tried and abandoned; revert/lessons recorded | Must cite the revert commit |

No oversell: an idea validated only on the `experimental` branch (section 3, stage 2) is
`candidate`, never `adopted`.

## 7. Investigation template (copy-paste)

Open an issue (or a comment on the existing one) with this skeleton. Do not skip the
negatives or the refutation section — they are what make the result accepted rather
than merely asserted.

```markdown
# Investigation: <one-line symptom>

Status: open | candidate | adopted | retired
Branch/commit investigated: <e.g. main@289fd41b>   Date: <YYYY-MM-DD>

## Symptom
Exact error strings / metrics / user reports, verbatim. Link the reporting issue.

## Observations — including negatives
- O1: ...
- O2: ...
- N1 (negative): what does NOT happen / when the symptom does NOT appear.
- Timeline: symptom first seen <date>; suspect code shipped in <tag>
  (`git log -S '<needle>' --reverse`, `git tag --contains <sha> | sort -V`).

## Hypotheses and predictions (before measuring)
| Hypothesis | Measurement (exact command) | Predicted | Actual | Verdict |
|---|---|---|---|---|
| H1 | | | | |
| H2 (cheaper rival) | | | | |

## Experiments
Command + output for each row above. State the working directory. Note anything
destructive or slow. Premises verified directly (PRAGMAs, dep versions, live config).

## Mechanism
One paragraph. Must account for every O and N above. Name the bug CLASS, not just
the instance (AGENTS.md rule).

## Refutation review
Refuter: <name/session>   Checklist: R1 [ ] R2 [ ] R3 [ ] R4 [ ] R5 [ ]
Outcome: objection(s) OR "attempted R1–R5; result survived".
R3 note: does the fix's test fail on pre-fix code? (build-failure = degenerate; probe.)

## Disposition
- [ ] Fix PR #____ (label + linked issue; gates per pelican-change-control)
- [ ] Invariant codified in code comment / pelican-architecture-contract
- [ ] Backport needed? (`create-patch` label; release-branch PRs)
- [ ] Upstream report filed? (pelican-ecosystem-and-upstreams)
- [ ] Retired: revert <sha> with lessons in the message
```

## Provenance and maintenance

Facts verified 2026-07-05 against `main@289fd41b` (upstream `PelicanPlatform/pelican`);
GitHub live-state (releases, labels, milestones) queried the same day via `gh -R
PelicanPlatform/pelican`. Skew probes and pre-fix builds were executed in a throwaway
local clone; this repo was never modified. Line numbers drift — prefer the paired symbol
names.

Re-verification one-liners for every volatile fact:

| Fact (value at verification) | Re-verify with |
|---|---|
| HEAD used for all repo facts (`289fd41b`) | `git log -1 --format='%h %s'` |
| `hidden: true` params (58) | `grep -c '^hidden: true' docs/parameters.yaml` |
| `deprecated: true` params (24) | `grep -c '^deprecated: true' docs/parameters.yaml` |
| `ClockSkewLeeway` = 60 s | `grep -n 'ClockSkewLeeway =' token/token_verify.go` |
| Range prohibition comment present | `grep -n 'Do not use Range' director/cache_ads.go` |
| Boundary tests pass (~0.3 s) | `go test ./token/ -run 'TestVerifyWithKeyset_' -count=1` |
| Experimental releases exist (v7.27.0-experimental.0/1; +ADIOS.backend) | `gh release list -R PelicanPlatform/pelican --limit 40 \| grep experimental` |
| `experimental` branch ahead of main (23 commits) | `git fetch upstream && git rev-list --count main..upstream/experimental` |
| ADIOS absent from main | `git log main --oneline -i --grep=adios \| head` (empty) |
| Main's release.yml lacks `-experimental` tag pattern | `grep experimental .github/workflows/release.yml` (empty) |
| `v7.25.x-backup` local-only | `git branch --list v7.25.x-backup` vs `git ls-remote --heads https://github.com/PelicanPlatform/pelican.git \| grep backup` (empty) |
| No v7.25.1-rc.1 release artifacts | `gh release list -R PelicanPlatform/pelican --limit 40 \| grep 'v7.25.1-rc'` |
| parking-lot milestone (12 open / 61 closed) | `gh api repos/PelicanPlatform/pelican/milestones --jq '.[] \| "\(.title) \(.open_issues)/\(.closed_issues)"'` |
| `Facilitation` label text ("A request from the RCF's") | `gh label list -R PelicanPlatform/pelican \| grep Facilitation` |
| Nightly `-race` cron (`0 7 * * *`) and PRs not running `-race` | `grep -n 'cron\|race_detection' .github/workflows/test-linux-scheduled.yml`; `grep race_detection .github/workflows/test-linux-pr.yml` (empty) |
| Feature-compat file (single feature `CacheAuthz`) | `grep -c '^Name:' features/resources/feature-version-compatibility.yaml` |
| Exactly 3 design docs | `find . -iname '*design*.md' -not -path './.git/*' -not -path '*/node_modules/*'` |
| Key commits still resolve | `git show -s --format='%h %s' eca4f46c 14b96918 f214d11e 8a5aec4b 7395fadd eb40bf5a 2b11d625 b46b1f39 c02ec8b4` |

Marked UNVERIFIED/OPEN in this skill:

- "RCF" expansion as "research-computing facilitators" — the label description says only
  "A request from the RCF's"; the expansion is inferred from OSG usage. Ask a human.
- Whether the ttlcache `Range` lock leak was ever reported upstream (jellydator/ttlcache)
  as `eca4f46c` said it should be — check that project's issue tracker.
- Whether the `experimental` branch is periodically rebased/reset (its lifecycle policy
  is undocumented); verify current divergence with the command above before relying on it.
