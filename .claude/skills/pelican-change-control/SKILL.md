---
name: pelican-change-control
description: Load when preparing, reviewing, merging, or backporting a change to PelicanPlatform/pelican — including when a PR check fails ("No labels found on the pull request", "No linked issues found", "This branch is not rebased on main", "Changes detected" from check-go-generate, "Found objects larger than 1MB", golangci-lint/pre-commit failures, validate-parameters errors), when asked to bump XRootD/plugin/dependency versions, rename a JSON field or Prometheus metric, change a config default, cherry-pick a fix to a v7.NN.x release branch, cut or interpret an rc tag, or classify a change (bug fix vs feature vs param vs wire-format vs dependency vs docs). Contains the CI gate stack with exact failure strings and fixes, CONTRIBUTE.md review policy including the two-PR dependency rule, the main-first branch/backport/release-train model, the four non-negotiable discipline rules with incident evidence, a change-classification decision table, and security-report routing.
---

# Pelican Change Control

How a change gets into `PelicanPlatform/pelican`, out to a release, and backported — as CI and the maintainers actually enforce it. All facts verified 2026-07-05 against `main@289fd41b` (workflows, CONTRIBUTE.md, git history, and live GitHub state via read-only `gh -R PelicanPlatform/pelican`).

## When to use this skill

- A PR check is red and you need the exact fix: "PR Validation", "Check Rebase on Main", "Check Go Generate Has Been Run", "Check for Large Objects", "Linter", "Validate Parameters File".
- You are about to open a PR and need labels, a linked issue, and the right gates for its change type.
- You are asked to bump XRootD, an XRootD plugin, or any container-image package.
- You are asked to rename/remove a JSON key, Prometheus metric/label, director API field, or config default.
- You need to backport a fix to a `v7.NN.x` branch, understand `create-patch`, or reason about rc tags/releases.
- A closed issue mysteriously reopened, or a stale bot closed something.

### When NOT to use

- Mechanics of the serverAds locking rules, launch ordering, or the wire-format freeze *invariants themselves* → **pelican-architecture-contract**.
- Full incident narratives (what broke, how it was found) → **pelican-failure-archaeology**.
- How to add/deprecate a config parameter step by step → **pelican-config-and-flags**.
- Test idioms (`ResetTestState`, `require.Eventually`, build tags, fed tests) → **pelican-testing-and-qa**.
- Toolchain versions, goreleaser internals, exact XRootD pin file anatomy → **pelican-build-and-env**.
- Editing docs-of-record content and codegen for docs → **pelican-docs-and-writing**.
- Where to file issues against XRootD forks, plugins, OSG infra → **pelican-ecosystem-and-upstreams**.
- Debugging a runtime failure → **pelican-debugging-playbook**.

## 1. The PR gate stack (what CI enforces, what failing looks like, the fix)

All six gates live in `.github/workflows/`. All run on every `pull_request` regardless of target branch, EXCEPT `check-rebase-on-main.yml`, which only guards PRs targeting `main`. Working directory for all fix commands: repo root.

| Workflow file | Check name in UI | Enforces |
|---|---|---|
| `enforce-PR-labelling.yml` | PR Validation | ≥1 label AND ≥1 linked closing issue |
| `check-rebase-on-main.yml` | Check Rebase on Main | current `main` is an ancestor of your HEAD |
| `check-go-generate.yml` | Check Go Generate Has Been Run | `go generate ./...` produces no diff |
| `check-large-objects.yml` | Check for Large Objects | no blob >1MB anywhere in PR commit range |
| `pre-commit-linter.yml` | Linter | golangci-lint v2.9.0, pre-commit hooks, Prettier |
| `validate-parameters.yml` | Validate Parameters File | `docs/parameters.yaml` schema rules |

### 1.1 PR Validation (`enforce-PR-labelling.yml`)

Triggers: `pull_request` types `[opened, edited, labeled, unlabeled, synchronize]`. Two independent steps:

1. **Labels**: fails with `No labels found on the pull request.` if the PR has zero labels. Fix: `gh pr edit <N> -R PelicanPlatform/pelican --add-label bug` (pick real labels; see section 5).
2. **Linked issue**: queries GraphQL `closingIssuesReferences`; fails with `❌ No linked issues found in the pull request.` if the count is 0/null. Fix: put `Fixes #<issue>` (or `Closes`/`Resolves`) in the PR *body* — editing the body fires the `edited` trigger and re-runs the check.

**The sidebar trap** (documented in the workflow's own comment, line 5: "there's no trigger to re-run any time we 'connect' or 'disconnect' an issue"): linking an issue via the GitHub sidebar does NOT re-trigger this workflow. After a sidebar link you must push a commit, edit the PR body, or re-run the check manually (`gh run rerun <run-id> -R PelicanPlatform/pelican`) to go green.

Verify a PR's state without waiting for CI:

```bash
gh pr view <N> -R PelicanPlatform/pelican --json labels --jq '[.labels[].name]'
gh api graphql -f query='{ repository(owner:"PelicanPlatform", name:"pelican") { pullRequest(number:<N>) { closingIssuesReferences(first:10){totalCount} } } }'
```

Honesty note: this gate has been merged past under incident pressure — revert PR #3497 merged 2026-06-02 with zero labels (verified via `gh pr view 3497`). Maintainers can bypass; you should not plan to.

### 1.2 Check Rebase on Main (`check-rebase-on-main.yml`)

Predicate (workflow line 28): after `git fetch origin main:main`, it requires `git merge-base --is-ancestor origin/main HEAD`. Failure output: `Error: This branch is not rebased on main.` / `Please rebase your branch on main before merging.`

The project convention is **rebase, not merge-from-main** — the check's own message prescribes rebase, and PR branches are expected to be linear. Precision note: merging the *current* main tip into your branch does satisfy the ancestry predicate at that instant (the tip becomes a parent of your merge commit), but the predicate is evaluated against `main` *at check time*, so it goes red again as soon as main moves (any later `synchronize`/`edited` event) — and reviewers expect linear history anyway. Rebase. Observed distribution over the last 100 runs (`gh run list --workflow=check-rebase-on-main.yml`, 2026-07-05): failures concentrate on `push` events to maintainer branches; `pull_request` runs mostly pass because the runner checks out GitHub's fresh merge ref. Do not overthink it — when red, rebase:

```bash
# from repo root; "upstream" = whichever remote points at PelicanPlatform/pelican (check: git remote -v)
git fetch upstream main
git rebase upstream/main
git push --force-with-lease origin <your-branch>
```

Pre-flight check before opening any PR:

```bash
git fetch upstream main && git merge-base --is-ancestor upstream/main HEAD && echo REBASED || echo NEEDS-REBASE
```

### 1.3 Check Go Generate (`check-go-generate.yml`)

Runs `go generate ./...` then fails if `git diff` is non-empty, printing `Changes detected. Here are the details:` followed by the diff. This fires when you edit any codegen source — `docs/parameters.yaml`, `docs/error_codes.yaml`, `docs/scopes.yaml`, `swagger/pelican-swagger.yaml`, `features/resources/feature-version-compatibility.yaml` — without committing the regenerated outputs (`param/parameters.go`, `config/parameter_defaults.go`, `docs/parameters.json`, `web_ui/frontend/public/data/parameters.json`, etc.).

Fix (mutates working tree — run on a clean tree):

```bash
go generate ./...   # or: make generate
git status --short  # stage and commit EVERYTHING it changed, alongside your YAML edit
```

Full codegen map: **pelican-docs-and-writing**. Add-a-param checklist: **pelican-config-and-flags**.

### 1.4 Check for Large Objects (`check-large-objects.yml`)

Walks `git rev-list --objects BASE..HEAD` and fails on any blob >1MB (1048576 bytes): `❌ Found objects larger than 1MB:` plus object hashes/paths. Trap: deleting the file in a follow-up commit does NOT fix it — the blob is still in the commit range. You must rewrite history (interactive rebase dropping/amending the offending commit, then force-push). Reproduce locally:

```bash
git rev-list --objects upstream/main..HEAD | cut -d' ' -f1 | \
  git cat-file --batch-check='%(objectname) %(objecttype) %(objectsize)' | \
  awk '$2=="blob" && $3>1048576 {print $1, $3}'
```

(Empty output = pass. Derived from the workflow source; local run verified syntax.)

### 1.5 Linter (`pre-commit-linter.yml`)

Three legs:

- **golangci-lint v2.9.0** with `--config=.golangci.yaml`. Note: `.golangci.yaml` enables only `misspell` and explicitly **disables `staticcheck`**; formatters are `gofmt` + `goimports` (local-prefix `github.com/pelicanplatform/pelican`). Do not "helpfully" enable staticcheck in a drive-by.
- **pre-commit hooks** (`.pre-commit-config.yaml`): file hygiene checks, `shellcheck`, `mdformat` (`.md` only, `.mdx` excluded), `typos`, `npm-format-fix`.
- **Prettier**: `cd web_ui/frontend && npm ci && npm run format` — a dirty diff fails.

Local reproduction (CONTRIBUTE.md documents the setup, lines ~349-390):

```bash
python3 -m pip install pre-commit && pre-commit install   # once
pre-commit run --all-files
```

### 1.6 Validate Parameters File (`validate-parameters.yml`)

Runs `python3 .github/scripts/validate-parameters/main.py` from repo root. Requires every entry in `docs/parameters.yaml` to have `name, description, type, default, components`, with `type` and `components` drawn from fixed enumerations, and `type: object` params whitelisted in `VERIFIED_OBJECT_STRUCTURES` inside the script. Failure = a Python `RuntimeError` listing each bad parameter; success = silent, exit 0. Local-run recipe (venv + PyYAML) is single-owned in **pelican-config-and-flags** §9.5.

**Documented discrepancy**: `AGENTS.md` line ~382 says to run `make validate-parameters` — **that Makefile target does not exist** (check: `grep validate Makefile`); use the python invocation above. (Drift registry: **pelican-docs-and-writing** §6.)

## 2. Review policy (CONTRIBUTE.md — the human gates)

From `CONTRIBUTE.md` (lines cited as of main@289fd41b):

- **Single concern** (line 82): "Address a single concern in the least number of changed lines as possible." Also: fix functionality OR whitespace/style, never both; add tests for changed functionality; include docs under `docs/`.
- **Review requirement** (line 87): "it is required that at least one core contributor reviews and approves your changes... If your open PR is not reviewed after a week since it's open, please ping any of the core contributors as a reminder."
- **Fork-and-pull**: contributors work on forks; large refactors and breaking changes should get an issue discussion first (recommended, not required).

### The two-PR rule for dependency/container changes

`CONTRIBUTE.md` line 101, quoted exactly:

> "Due to how Pelican's build and test workflows are structured, any proposed development that makes changes to the packages installed into the container images must be split into two separate PRs: one for updating the packages, and one for the other changes, e.g., to code, that depend on those updated packages being present."

Reason: PR CI runs tests inside the *previously built* `pelican-test:latest-itb` container (see `test-linux-pr.yml` header comment) — a PR cannot build and then test its own image. So the package-bump PR must merge (and the container rebuild on `main` must complete) before the code PR that needs the new packages can pass. CONTRIBUTE.md also describes how to pre-test the combined effect on your own fork with your own registry + `PELICAN_HARBOR_ROBOT_USER/PASSWORD` secrets.

## 3. Branch and release model

### 3.1 Main-first, cherry-pick backports

- **Everything lands on `main` first.** Release branches (`v7.0.x` … `v7.26.x`; 27 of them on upstream as of 2026-07-05, plus `v7.22.x-security-release`/`v7.23.x-security-release`) receive **cherry-picks** carrying the `(cherry picked from commit …)` trailer — 24 such commits in the branch-only range `upstream/main..upstream/v7.25.x` (2026-07-05).
- Worked example: `eca4f46c` on main (PR #3513, "Stop iterating the live serverAds cache under its own lock", labels `bug, critical, director, create-patch`) → `086b6278` on v7.25.x with trailer `(cherry picked from commit eca4f46c...)`, shipped in v7.25.1-rc.6.
- Backports are **separate PRs targeting the release branch** (verified: PR #3492 "Backport director-related clock skew fixes from #3473" → base `v7.26.x`; PR #3500 → base `v7.25.x`) or direct maintainer pushes; either way use `git cherry-pick -x <main-sha>` so the trailer is preserved.
- **Release branches never merge back into main** (`scripts/generate_goreleaser.sh` comment: "releases are tagged from release branches and do not get merged into main"). Consequence: a release-branch-only commit is invisible to the next minor. Live example as of 2026-07-05: `fe785866` pinned XRootD 5.9.1 on v7.25.x only; `main` still pins 5.9.2 (`images/Dockerfile` `ARG XROOTD_VER`). If you fix something on a release branch, ask "does main need this too?" — nothing will do it for you.
- **`create-patch` label** = "Patch this into multiple versions of Pelican" (its GitHub description). It is a *marker for humans*: `grep -r create-patch .github/` finds nothing — **no in-repo automation consumes it**. Applying the label does not create a backport; someone must open the cherry-pick PRs. If you merge a fix labeled `create-patch`, the backport PRs are part of finishing the job.

### 3.2 Tags, rc trains, and the graveyard

- **Tags drive binary versions.** Pushing `v7.NN.M` or `v7.NN.M-rc.N` to upstream fires `.github/workflows/release.yml` → goreleaser injects the version via ldflags (`-X github.com/pelicanplatform/pelican/version.version=...` in `.goreleaser.in.yml`). A "Bump versions to vX.Y.Z-rc.N" commit touches **only** `web_ui/frontend/package.json` + `package-lock.json` (verified: `git show --stat f25a879b`) — the Go side needs no file edit.
- **Every release starts as a prerelease** (`release.prerelease: true` in `.goreleaser.in.yml`); a human flips the final to "latest" on GitHub. Verified: latest = v7.25.0 (published 2026-05-18, `isPrerelease: false`); everything since is `Pre-release`. Multiple trains run simultaneously (v7.25.1-rc.*, v7.26.0-rc.*, v7.27.0-experimental.*); 9 RCs for one minor is normal, not alarming. Note: `-experimental.*` tags do NOT match `release.yml`'s tag patterns; how those GitHub releases get created is OPEN (out-of-repo or manual).
- **rc tags get re-cut, and re-cut tags do not propagate to existing clones.** The v7.25.1-rc.1/rc.2 line was abandoned mid-train (JWT clock-skew patch reverted, narrower backport substituted — story in **pelican-failure-archaeology**) and rebuilt. Verified consequences, 2026-07-05: upstream tag `v7.25.1-rc.2` points at `582cd737`, which is **not an ancestor of `upstream/v7.25.x`** (orphaned history, reachable only via the tag); this checkout's local `v7.25.1-rc.1` (`c9e3f46b`) differs from upstream's (`b46b1f39`) because `git fetch` refuses to move existing tags. An abandoned-line `v7.25.x-backup` branch may exist in team checkouts; upstream heads no longer carry it. Rules: **never trust a local rc tag** — compare with `git ls-remote https://github.com/PelicanPlatform/pelican.git 'refs/tags/v7.25.1-rc*'`; refresh with `git fetch upstream 'refs/tags/*:refs/tags/*' --force`; treat `-backup` branches as graveyards, never as WIP.
- **Containers are a separate pipeline**: `build-and-test.yml` pushes to `hub.opensciencegrid.org/pelican_platform`. PRs never push images; pushes to main push only `pelican-dev`/`pelican-test` as `latest-itb`; semver tags push all release images. `post-release.yml` curls the website's download-refresh webhook on `release: published`.

### 3.3 Issue hygiene automation

- **Closing an unlabeled issue auto-reopens it**: `enforce-issue-labelling.yml` PATCHes the issue back to open unless the closer was the stale bot or the issue carries `stale`. Symptom: your just-closed issue is open again with a failed "Issue Validation" run. Fix: add a label, close again.
- **Stale bot** (`stale-issues.yml`): issues get `stale` after 60 days of inactivity and close 30 days later. **PRs are exempt** (`days-before-pr-stale: -1`). A `stale` label is not a verdict that the issue is invalid — real operational fires have carried it.
- Milestone due dates are planning targets, not ship dates — every dated open milestone (v7.25–v7.28) was past-due as of 2026-07-05; `parking-lot` (no due date) is the unscheduled backlog.

## 4. The four non-negotiables

Human reviewers enforce these harder than any linter. Each entry: rule → why → incident (one line; full stories in **pelican-failure-archaeology**) → compliant procedure.

### 4.1 Never casually bump XRootD or plugin versions

**Rule**: An XRootD/plugin version change is a production-risk change, not a chore. It requires its own PR (two-PR rule, section 2), labels `dependencies` + `container` + affected components, and qualification evidence.

**Why**: Pelican launches the system `xrootd` binary; the pin *is* the data plane. Pins live in **three hand-synchronized places** — `images/Dockerfile` (`ARG XROOTD_VER`, with a NOTE comment demanding the sync), `github_scripts/osx_install.sh` (builds the `PelicanPlatform/xrootd` fork tag `vX.Y.Z-pelican` from source), and the runtime floor `MinXrootdVersion` in `xrootd/version.go` mirrored by the RPM dependency in `.goreleaser.in.yml`. Locations and mechanics: **pelican-build-and-env**. Bump-vs-file-upstream decisions: **pelican-ecosystem-and-upstreams**.

**Incident**: PR #3488 upgraded to 5.9.5 (merged 2026-05-30, labels `dependencies, cache, origin, container, create-patch`); PR #3497 reverted it three days later — its PR body: "We've discovered issues with 5.9.5 and removed it from the osg-testing repos" (revert commit `72f04760`). On v7.25.x the same bump triggered a four-step downgrade ladder across rc.3–rc.7 (`c55115f9` 5.9.5 → `2336dd7f` 5.9.3 → `bf2d73ed` 5.9.2 → `fe785866` 5.9.1) after a production cache SIGABRT'd ~27 times in 5 days (uncaught `std::length_error` in `XrdPfc::File::ReadOpusCoalescere` — see `git show fe785866` for the full post-mortem-quality message).

**Compliant procedure**: (1) confirm the target version exists in the OSG `osg-testing` dnf repo (the Dockerfile installs from there — availability is owned by OSG packaging, not this repo); (2) open a bump-only PR touching the pins in sync, with the two-PR split if code depends on it; (3) cite qualification: at minimum green E2E/container CI, ideally burn-in on a production-like cache (the 5.9.x incidents were only visible under real cache load); (4) write the commit message like `fe785866` — symptom, evidence, why this version; (5) if the bump must reach shipped versions, label `create-patch` and open the cherry-pick PRs per release branch — and check main/release-branch pin consistency afterward.

### 4.2 Wire formats are frozen ABI: add, never rename

**Rule**: `server_structs` JSON (director↔origin/cache advertisement), Prometheus metric names/labels, and director-server API fields are cross-version contracts in mixed-version federations. You may add fields/metrics; you may not rename or remove until every supported version understands both. The numbered invariants live in **pelican-architecture-contract**.

**Incident**: the Capabilities JSON rename was reverted **three times over 16 months** — `7395fadd` (2024-10-10, commit body: "I thought this change would be non-breaking but I was WRONG"), `786f4d12` (2024-11-12), and `0cfabbef`/`3e53026c` (2026-02-17) — before conversion helpers finally landed (`0e2dc1d8`, `f3291596`, 2025-12-05). The team deliberately keeps a *typo'd* Prometheus metric alive: `xrootd_transfer_readv_segments_toal` (`TransferReadvSegsTotalDeprecated` in `metrics/xrootd_metrics.go`, near line 494) ships alongside `_count` and the corrected `_total` because dashboards in the wild scrape the typo. Metric *label* additions are capacity changes too: the 2024-11-22 revert-of-revert pair `138e90bd`/`0ecb8be1` came from new labels blowing up Prometheus memory.

**Compliant procedure**: never rename; add the new field/metric beside the old; use `features/resources/feature-version-compatibility.yaml` (consumed by the `GenServerFeatures` generator — every feature must declare `NotBeforePelican`) as the sanctioned version-negotiation mechanism for behavior that only works past a given version; only remove the old name when the compatibility floor passes it, with a PR that says so explicitly.

### 4.3 Test discipline is sacred

One line, because **pelican-testing-and-qa** owns it: no `time.Sleep` for conditions (`AGENTS.md` line ~228: sleeps "will be rejected" — use `require.Eventually`), never `TLSSkipVerify` in federation tests, always the reset/isolation idioms (`ResetTestState`). Reviewers reject on sight. Also budget-relevant for review: **PR CI never runs the race detector** — `-race` runs only in the nightly `test-linux-scheduled.yml` (`race_detection: true`; the flag defaults to false in `test-linux.yml`). A green PR proves nothing about shutdown/goroutine races, historically this repo's costliest bug class; if your change touches goroutine lifecycle or shutdown, say in the PR how it was race-tested (see **pelican-concurrency-and-shutdown-proofs** and **pelican-diagnostics-and-tooling**).

### 4.4 Production configs must keep working

**Rule**: never change a parameter default and never remove/rename a deprecated parameter without a deprecation cycle. Mechanics (one line; owner **pelican-config-and-flags**): mark `deprecated: true` + `replacedby:` in `docs/parameters.yaml`; migration shims live in `handleDeprecatedConfig()` in `config/config.go`.

**Incident**: `d3f05d9a` (2023-12-14) reverted merged PR #500 wholesale to restore `viper.SetDefault` lines (Xrootd Authfile/ScitokensConfig/Macaroons paths) — the earliest instance of the standing theme that defaults are a compatibility surface for every deployed federation config.

## 5. Change classification decision table

Gates from section 1 apply to ALL rows (labels + linked issue, rebase, go-generate, large-objects, linter, validate-parameters). This table adds what else each change type owes. Labels named here exist in the repo taxonomy (verified via `gh label list`).

| Change type | Labels | Extra gates / discipline | Backport question | Docs to update (how: **pelican-docs-and-writing**) |
|---|---|---|---|---|
| Bug fix | `bug` + component (`director`, `cache`, `origin`, `registry`, `client`, ...); `critical` if it must make the next release | tests reproducing the bug (4.3) | Does it affect shipped versions? → label `create-patch` AND open cherry-pick PR(s) per affected `v7.NN.x` | only if documented behavior changed |
| Feature | `enhancement` + component | design-issue discussion for anything breaking; feature flag via `feature-version-compatibility.yaml` if cross-server (4.2) | almost never backported | `docs/app/**/*.mdx` user docs; swagger if new endpoints |
| Config param add/change | component + `configuration` | `validate-parameters` + `check-go-generate` will bite; defaults/deprecation cycle (4.4); full checklist in **pelican-config-and-flags** | default changes: no backport without the deprecation story | parameter docs are generated from `docs/parameters.yaml` — write the description there |
| Wire-format-adjacent (server_structs JSON, metrics, director API) | component + usually `critical` | add-never-rename (4.2); expect the hardest review | backport only additive changes | `docs/pelican-http-headers.md` if headers; swagger if API |
| Dependency / container-image bump | `dependencies`, `container`, + components | TWO-PR rule (section 2); XRootD/plugins: full 4.1 procedure | if shipped versions need it: `create-patch` + cherry-pick PRs; keep main and release-branch pins reconciled | note in PR body what changed and why |
| Docs only | `documentation` | still needs a linked issue + label (gate 1.1 has no path exemption); mdformat rewrites `.md`, leaves `.mdx` alone | docs backports do happen (PR #3500/#3501 pattern) for release-branch doc tags | — |

Unresolvable from this repo: the `no-docs-required` label's description claims "CI will fail if this label is not used unless `docs/app` is also modified", but **no workflow on any branch references it** (`git grep no-docs-required -- .github/` is empty). OPEN QUESTION — enforcement may live in an org-level app, or the description is stale. Treat the label as advisory metadata.

## 6. Security reports

- Report vulnerabilities and active exploitation to **security@pelicanplatform.org** (`SECURITY.md`), with description, reproduction info, affected versions, and your contact.
- Supported versions: **>= v7.0.0** (everything older is unsupported).
- Do NOT open a public issue or PR for an unpatched vulnerability. Note that dedicated `v7.NN.x-security-release` branches exist on upstream (v7.22.x, v7.23.x as of 2026-07-05) — security fixes may ship on trains outside the normal rc cycle.

## Provenance and maintenance

All facts verified 2026-07-05 against `main@289fd41b` plus live GitHub state (`gh` read-only, `-R PelicanPlatform/pelican`). Executed personally: the parameter validator (success path), all `gh` queries, all git-history inspections. CI failure strings are quoted from workflow source, not from live failing runs. Re-verify volatile facts cheaply:

| Volatile fact | Re-verification command (repo root) |
|---|---|
| Gate workflows exist / trigger types | `ls .github/workflows/` and `head -12 .github/workflows/enforce-PR-labelling.yml` |
| Sidebar-link no-retrigger comment | `sed -n 5p .github/workflows/enforce-PR-labelling.yml` |
| Rebase predicate | `grep -n "merge-base --is-ancestor" .github/workflows/check-rebase-on-main.yml` |
| Large-object threshold (1MB) | `grep -n 1048576 .github/workflows/check-large-objects.yml` |
| golangci-lint version (v2.9.0) | `grep -n "version: v" .github/workflows/pre-commit-linter.yml` |
| staticcheck still disabled | `grep -n -A2 "disable:" .golangci.yaml` |
| `make validate-parameters` still missing (AGENTS.md discrepancy) | `grep -n validate AGENTS.md Makefile` |
| Validator command + success | `python3 .github/scripts/validate-parameters/main.py; echo $?` (needs PyYAML) |
| Two-PR rule wording | `sed -n 99,103p CONTRIBUTE.md` |
| Review policy wording | `sed -n 80,90p CONTRIBUTE.md` |
| Release branch count (27) / security branches | `git ls-remote --heads https://github.com/PelicanPlatform/pelican.git \| grep -cE 'refs/heads/v7\.[0-9]+\.x$'` |
| Cherry-pick trailer example | `git log -1 --format=%b 086b6278 \| grep "cherry picked"` |
| Cherry-pick count on v7.25.x (24) | `git log upstream/main..upstream/v7.25.x --format=%b \| grep -c "cherry picked from"` |
| `create-patch` consumed by nothing in-repo | `grep -r create-patch .github/ ; echo $?` (expect exit 1) |
| Backport-PR-to-release-branch pattern | `gh pr view 3492 -R PelicanPlatform/pelican --json baseRefName` |
| Bump commits touch only package.json+lock | `git show --stat f25a879b` |
| Releases start as prerelease | `grep -n -A2 "^release:" .goreleaser.in.yml` |
| Latest stable (v7.25.0 as of 2026-07-05) | `gh api repos/PelicanPlatform/pelican/releases/latest --jq .tag_name` |
| rc.2 tag orphaned off v7.25.x | `git fetch upstream && git merge-base --is-ancestor 582cd737 upstream/v7.25.x; echo $?` (expect 1) |
| Local-vs-upstream tag drift | `git rev-parse v7.25.1-rc.1; git ls-remote https://github.com/PelicanPlatform/pelican.git refs/tags/v7.25.1-rc.1` |
| XRootD pin main vs v7.25.x (5.9.2 vs 5.9.1) | `grep XROOTD_VER= images/Dockerfile; git show upstream/v7.25.x:images/Dockerfile \| grep XROOTD_VER=` |
| Downgrade-ladder commits present | `git log --no-walk --oneline c55115f9 2336dd7f bf2d73ed fe785866` |
| Capabilities revert commits present | `git log --no-walk --oneline 7395fadd 786f4d12 0cfabbef 3e53026c` |
| "toal" metric still shipped | `grep -n toal metrics/xrootd_metrics.go` |
| Feature-negotiation file | `head -35 features/resources/feature-version-compatibility.yaml` |
| Deprecation keys + handler | `grep -n replacedby docs/parameters.yaml \| head -3; grep -n handleDeprecatedConfig config/config.go` |
| PR CI has no -race; nightly does | `grep -n race .github/workflows/test-linux-scheduled.yml .github/workflows/test-linux-pr.yml .github/workflows/test-linux.yml` |
| Stale bot windows (60/30, PRs exempt) | `grep -n days-before .github/workflows/stale-issues.yml` |
| Auto-reopen of unlabeled closed issues | `grep -n "state...open" .github/workflows/enforce-issue-labelling.yml` |
| Security contact + supported versions | `cat SECURITY.md` |
| `no-docs-required` still unenforced | `git grep no-docs-required -- .github/; gh label list -R PelicanPlatform/pelican --search no-docs` |
