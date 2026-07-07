---
name: pelican-build-and-env
description: >-
  Load when you need to build Pelican or set up a dev environment and hit questions or errors like "build constraints exclude all Go files in .../cmd", "only configurations files on version: 1 are supported, yours is version: 2", "make pelican-dev-build fails / .goreleaser.dev.yml not found", a blank web UI in a freshly built binary, snapshot versions reporting an ancient 7.19.4-next, or "which Go/Node/GoReleaser/XRootD versions do I need". Contains the toolchain requirements table, a speed-ranked build-path menu with verified commands and expected output, the full Makefile target reference, the goreleaser template flow, dev-environment options (devcontainer, macOS native, docker), XRootD pin file locations, and a traps table.
---

# Pelican Build & Environment

How to build this repo and stand up a dev environment, with every command verified.
Working directory for ALL commands below is the repo root unless stated otherwise.

## When to use this skill

- You need to compile the `pelican` or `pelican-server` binary (any platform).
- `go build ./cmd` fails with `build constraints exclude all Go files`.
- `goreleaser` fails with `only configurations files on version: 1 are supported, yours is version: 2`.
- `make pelican-dev-build` fails because `.goreleaser.dev.yml` does not exist.
- A binary you built serves a blank/broken web UI.
- A snapshot build reports version `7.19.4-next` (or any ancient version) on a current branch.
- You are choosing between building natively on macOS vs the dev container.
- You need to know where the XRootD version is pinned (file locations only).

**When NOT to use** (route to siblings by name):

- Running/deploying the built binary, ports, config layout, systemd → `pelican-run-and-operate`
- How to run tests, build tags for tests, `fed_test_utils`, CI matrix → `pelican-testing-and-qa`
- Whether you are ALLOWED to bump XRootD or a dependency (policy, review gates) → `pelican-change-control`
- The parameters.yaml/codegen system in depth, adding a parameter → `pelican-config-and-flags`
- Race detector, profiling, measurement → `pelican-diagnostics-and-tooling`
- Sibling repos (XRootD fork, plugins, docs site) → `pelican-ecosystem-and-upstreams`

## 1. Toolchain requirements

| Tool | Required version | Where pinned | Notes |
|---|---|---|---|
| Go | 1.25.0 | `go.mod` line 6 (`go 1.25.0`) | Any modern Go auto-downloads 1.25.0 via toolchain switching. CI parses go.mod (`.github/workflows/check-go-generate.yml`, "Set Go version" step). |
| Node | 20 | `web_ui/frontend/package.json` `"engines": {"node": "20"}` | Not strict — no `.npmrc`/`engineStrict`; node 24 only prints a warning and works. Frontend Dockerfile uses `node:20-alpine`. |
| npm | any recent | — | Needed only for the real web UI (`npm ci` requires `package-lock.json`). Plain `go build` works without it (see §2a). |
| GoReleaser | **v2** | `.goreleaser.in.yml` line 20: `version: 2` | v1 hard-fails; exact message in §1.1. Install v2 (`brew upgrade goreleaser` / repo.goreleaser.com) or use `USE_DOCKER=1` (§2f). |
| pre-commit | any recent | `.pre-commit-config.yaml` | Hooks: pre-commit-hooks v6.0.0, golangci-lint v2.9.0 (pre-push/manual stage), shellcheck v0.11.0.1 (`--severity=warning`), prettier via `npm run format:fix` (pre-push/manual), mdformat. |
| XRootD | >= 5.8.2 **at runtime only** | `MinXrootdVersion = "5.8.2"` in `xrootd/version.go` | NOT needed to build: `CGO_ENABLED=0` everywhere (`.goreleaser.in.yml`), LotMan uses purego `dlopen`. Needed to *run* origin/cache and fed tests — checked via `exec.LookPath("xrootd")` in `xrootd/plugin_check.go`. No macOS package: build from source (§5.2) or use the dev container (§5.1). |
| Docker | optional | — | Enables `USE_DOCKER=1` make paths, the devcontainer, and `make pelican-build-server-image`. |

Quick self-check (expected output from the machine these facts were verified on — macOS arm64):

```console
$ go version
go version go1.25.0 darwin/arm64
$ node --version && npm --version
v24.11.1        # engines wants 20; warning only
11.6.2
$ goreleaser --version | grep GitVersion
GitVersion:    v1.26.2   # <-- v1: WILL FAIL, see below
$ which xrootd; echo $?
1               # no XRootD: cannot serve origin/cache natively
```

### 1.1 The GoReleaser v1 failure (exact, reproduced)

```console
$ goreleaser check --config .goreleaser.in.yml
  ⨯ command failed    error=only configurations files on  version: 1  are supported, yours is  version: 2 , please update your configuration
```

Any goreleaser v1 breaks `make pelican-build` on an otherwise fully working machine. Fix: install goreleaser v2, or run `USE_DOCKER=1 make pelican-build` (uses the `goreleaser/goreleaser` image, which is v2).

### 1.2 What works where

| Task | macOS native (no XRootD) | Dev container / Linux |
|---|---|---|
| `go build` (client & server tag sets) | yes (verified) | yes |
| `make generate`, `make web-build` | yes (needs npm) | yes |
| goreleaser snapshot build | yes IF goreleaser v2 installed | yes (image ships v2) |
| Unit tests (client/server tags) | mostly (113 files are `!windows`; lotman is `linux && !ppc64le`) | yes |
| Running origin/cache, fed tests | NO without §5.2 (needs `xrootd` binary) | yes |
| RPM dependency verification | no | yes |

## 2. Build-path menu, ranked by speed

### 2a. Plain `go build` — seconds, no npm needed (verified)

```console
$ go build -o ./pelican -tags forceposix,client ./cmd     # client CLI    (~1s warm cache)
$ go build -o ./pelican-server -tags forceposix,server ./cmd  # server binary (~2s warm cache)
```

Both verified 2026-07-05; first-ever build compiles the full module graph and takes minutes.

**Tags are mandatory.** `cmd/main.go` line 1 is `//go:build client || server`, so:

```console
$ go build ./cmd
package github.com/pelicanplatform/pelican/cmd: build constraints exclude all Go files in .../cmd
```

`-tags forceposix` alone fails identically (verified). `forceposix` itself is vestigial — no `.go` file in the repo references it and `go.mod` has no `jessevdk/go-flags` — but keep it for parity with the release configs.

**Why this works without npm:** `web_ui/ui.go` embeds the UI via `//go:embed frontend/out/*` (symbol `webAssets`). A single tracked file, `web_ui/frontend/out/placeholder` (the only tracked file under `out/` — `git ls-files web_ui/frontend/out`), satisfies the embed pattern on a fresh clone. The binary compiles and runs, but the web UI is blank until you do §2b.

### 2b. Real web UI: `make web-build` then `go build`

```console
$ make web-build       # = make generate + (cd web_ui/frontend && npm ci && npm run build)
$ go build -o ./pelican-server -tags forceposix,server ./cmd
```

`npm run build` is a Next.js **static export** (`web_ui/frontend/next.config.js`: `output: 'export'`, `basePath: '/view'`) into `web_ui/frontend/out/`, which the embed in §2a picks up on the next `go build`. Takes a few minutes (npm ci + next build; not re-executed during this verification pass — a previously built `out/` already existed; command derived from Makefile lines 91-96 and release CI usage).

Trap: on Windows `make web-build` only does `touch web_ui/frontend/out/index.html` (Makefile lines 82-86) — Windows builds never contain a real UI.

### 2c. Codegen: `make generate` / `go generate ./...` — run from repo root

```console
$ make generate
```

What it does (Makefile lines 64-78):

1. Bootstrap: creates empty `docs/parameters.json` and `web_ui/frontend/public/data/parameters.json` if absent. Both are **gitignored**; they are declared as make prerequisites so the target can run on a fresh clone. `go generate` then fills them with real content.
2. Runs `go generate ./...`. There are exactly **three** `//go:generate` directives repo-wide (verified via grep): one in `generate/main.go`, two in `cmd/main.go`.

The `generate/main.go` directive is `go run ../generate` — go generate executes it with cwd = `generate/`, and every generator opens inputs/outputs via `../` relative paths (e.g. `os.Create("../param/parameters.go")` in `generate/param_generator.go`). Regenerated outputs:

| Input (edit these) | Output |
|---|---|
| `docs/parameters.yaml` | `param/parameters.go`, `param/parameters_struct.go`, `config/parameter_defaults.go` (tracked) + both gitignored `parameters.json` files |
| `docs/scopes.yaml` | `token_scopes/token_scopes.go` |
| `docs/error_codes.yaml` | `error_codes/error_codes.go` |
| `features/resources/feature-version-compatibility.yaml` | `features/features.go` |
| `swagger/pelican-swagger.yaml` (hand-maintained, tracked) | copy at `web_ui/frontend/app/api/docs/pelican-swagger.yaml` (gitignored) |

**Subtlety (verified with `go generate -n`):** the two directives in `cmd/main.go` regenerate the CLI command-reference docs under `docs/app/commands-reference/`, but `cmd/main.go` is excluded by build constraints when no tags are given — so plain `go generate ./...` **skips them silently**:

```console
$ go generate -n ./cmd                    # prints NOTHING
$ go generate -n -tags client ./cmd
go run -tags client . generate-docs docs/app/commands-reference/pelican
go run -tags server . generate-docs docs/app/commands-reference/pelican-server
```

For the docs pipeline itself, see `pelican-docs-and-writing`.

**CI enforcement:** `.github/workflows/check-go-generate.yml` runs `go generate ./...` on every PR and fails if `git diff` is non-empty. After editing any input YAML above: `make generate` and commit the regenerated tracked files, or CI rejects the PR. See `pelican-config-and-flags` for the add-a-parameter checklist.

### 2d. Full goreleaser snapshot — cross-builds everything, slow

```console
$ make goreleaser-config     # substitutes version into .goreleaser.in.yml -> .goreleaser.generated.yml
$ goreleaser --clean --snapshot --config .goreleaser.generated.yml
```

Equivalent to `make pelican-build`. Builds ALL os/arch triples for all three build ids (§4) — expect many minutes. For development, build only your platform (documented in CONTRIBUTE.md "Building" and AGENTS.md):

```console
$ make goreleaser-config
$ goreleaser build --single-target --clean --snapshot --config .goreleaser.generated.yml
```

Output lands in `dist/pelican_<os>_<arch>_<archversion>/` (e.g. `dist/pelican_darwin_arm64_v8.0/`). Requires goreleaser v2 (§1.1) and npm (before-hooks run `make web-build`). Caution: the before-hooks also run `go mod tidy`, which can rewrite `go.mod`/`go.sum` in your working tree.

### 2e. `make pelican-dev-build` — FAILS OUT OF THE BOX (two traps)

**Trap 1:** the target uses `.goreleaser.dev.yml`, which is **gitignored (`.gitignore` line 8) and has never been tracked**. Each developer hand-creates it from the example in README.md, section "Example `.goreleaser.dev.yml` File" (~line 78). Without it, goreleaser errors that the config file does not exist.

**Trap 2 (verified 2026-07-05):** the README example's `tags:` list contains only `forceposix` — no `client` or `server`. As written it cannot compile `./cmd` (§2a): `go build -tags forceposix ./cmd` fails with `build constraints exclude all Go files`. When you copy the example, **add `client` (and/or a second build with `server`) to `tags:`**.

### 2f. `USE_DOCKER=1` — containerized toolchain (derived from Makefile, not executed)

`Makefile` line 17 sets `USE_DOCKER=0`; override per-invocation:

```console
$ USE_DOCKER=1 make generate        # runs go generate inside golang:1.25
$ USE_DOCKER=1 make web-build       # builds origin-ui image from web_ui/frontend/Dockerfile (node:20-alpine)
$ USE_DOCKER=1 make pelican-build   # runs goreleaser/goreleaser image (v2) -- escape hatch for goreleaser-v1 hosts
```

## 3. Makefile target reference

Root `Makefile`, 11 `.PHONY` targets (verified 2026-07-05). `$(goos)`/`$(goarch)` are computed at lines 21-43.

| Target | What it really does |
|---|---|
| `all` | Alias for `pelican-build`. |
| `generate` | Touch-bootstraps the two gitignored `parameters.json` files, then `go generate ./...` (§2c). |
| `web-build` | `generate` + `cd web_ui/frontend && npm ci && npm run build`, but only when `out/index.html` is older than any frontend source. On Windows: fake (touch only). |
| `web-serve` | `cd web_ui/frontend && npm install && npm run dev` — Next dev server (`next dev --turbo`), port 3000. Dev loop for UI work; API proxying is covered in `pelican-run-and-operate`. |
| `web-clean` | Deletes `web_ui/frontend/out/` and `.next/`. Note: this deletes the tracked `out/placeholder` — restore with `git checkout -- web_ui/frontend/out/` or plain `go build` breaks on the embed. |
| `pelican-clean` | Deletes `dist/`. |
| `goreleaser-config` | `./scripts/generate_goreleaser.sh .goreleaser.in.yml .goreleaser.generated.yml` (§4). |
| `pelican-build` | `goreleaser --clean --snapshot --config .goreleaser.generated.yml` — full cross-platform matrix, slow (§2d). |
| `pelican-dev-build` | Same but with `.goreleaser.dev.yml` — broken until you hand-create that file (§2e). |
| `pelican-serve-test-origin` | **STALE — expect failure.** Does `cd dist/pelican_$(goos)_$(goarch)` but goreleaser v2 emits arch-versioned dirs (`pelican_darwin_arm64_v8.0`, `pelican_linux_amd64_v1`), so the `cd` fails. Observed `dist/` on the verification machine confirms the `_v8.0` suffix. (Bonus quirk: the Windows branch at Makefile lines 23-28 sets `goarch := arm64` when the processor is AMD64.) |
| `pelican-build-server-image` | `docker build -t pelican-server -f images/Dockerfile .` — the production server image. |

**Info-noise trap:** `Makefile` line 53 has an unconditional `$(info ...)` that prints a huge "These files have changed causing the website to have to rebuild: [...]" list on EVERY make invocation, including `make -n` and unrelated targets. It is noise, not an error — ignore it.

## 4. GoReleaser flow in detail

`.goreleaser.in.yml` is a **template**, not a valid config: it contains literal `%VERSION%` / `%RPMVERSION%` placeholders (goreleaser cannot template RPM version dependencies itself). The flow:

```
.goreleaser.in.yml --(scripts/generate_goreleaser.sh)--> .goreleaser.generated.yml (gitignored, .gitignore line 9)
```

**Version derivation** (`scripts/generate_goreleaser.sh`): use `$GORELEASER_CURRENT_TAG` if set (release container builds set it — `images/Dockerfile` ARG/ENV around lines 186-189); else `git describe --tags --exact-match`; else nearest tag + `-next`. RPM version replaces `-` with `~` so `7.0.0~rc.1-1 < 7.0.0-1` in RPM ordering.

**The git-describe-on-main trap (reproduced 2026-07-05):** release tags are applied on release branches (`v7.25.x`, ...) that never merge back to main — the script's own comment (lines 11-12) says so. So on main:

```console
$ git describe --tags
v7.19.4-1894-g289fd41b        # ancient tag + 1894 commits
$ ./scripts/generate_goreleaser.sh .goreleaser.in.yml /tmp/out.yml && grep version_template /tmp/out.yml
  version_template: "7.19.4-next"
```

Snapshot builds from main will forever self-report `7.19.4-next` (tag current as of 2026-07-05). This is cosmetic for dev builds; do not "fix" it by tagging. Release-train mechanics are owned by `pelican-change-control`.

**Three builds, two binaries** (`.goreleaser.in.yml` `builds:`):

| id | tags | ldflags/gcflags | platforms |
|---|---|---|---|
| `pelican` | `forceposix,client` | version metadata + `-s -w` (stripped) | linux/windows/darwin × amd64/arm64/ppc64le (minus windows-arm64/ppc64le, darwin-ppc64le) |
| `pelican-debug` | `forceposix,client` | metadata only, `gcflags all="-N"` (no inlining, symbols kept); RPM `provides: pelican` | same |
| `pelican-server` | `forceposix,server` | metadata + `-s -w` | linux/darwin only |

Two binaries exist because client CLI and server daemon are disjoint build-tag universes compiled from the same `./cmd` (§2a). All builds set `CGO_ENABLED=0` and inject `commit`/`date`/`builtBy`/`version` into the `version` package via `-X` (defaults in `version/version.go`: `"none"`, `"unknown"`, `"unknown"`, `"dev"`).

**Packages** (`nfpms:`): `pelican` (apk/deb/rpm), `pelican-debug` (rpm), `pelican-osdf-compat` (meta package: `/usr/bin/osdf` + `/usr/bin/stashcp` symlinks, condor `stash_plugin` symlink, provides/replaces `stashcache-client`/`osdf-client`/`stashcp`/`condor-stash-plugin`), and `pelican-server` (rpm: systemd units + example configs from `systemd/`; RPM requires `pelican >= 7.11.0`, `xrootd-server >= 1:5.8.2`, `xrootd-scitokens`, `xrootd-voms`, `xrdhttp-pelican >= 0.0.11`).

**Self-bootstrapping:** `before.hooks` = `go mod tidy`, `go generate ./...`, `make web-build`. A goreleaser build regenerates code and the web UI itself — so it needs npm — and `go mod tidy` may dirty `go.mod`/`go.sum`.

## 5. Dev environments

### 5.1 Dev container (recommended for server/fed work)

Live config: `.devcontainer/devcontainer.json` (CONTRIBUTE.md "Setup Dev Container" section confirms this is the one VS Code picks up). Key facts:

- Image: `hub.opensciencegrid.org/pelican_platform/pelican-dev:latest-itb` — stage `pelican-dev` of `images/Dockerfile` (`FROM pelican-test AS pelican-dev`, ~line 799). Ships XRootD + plugins, Go (version parsed from go.mod), and GoReleaser v2 (installed from repo.goreleaser.com yum repo).
- Forwarded ports: 8444 (Pelican server), 8443 (web UI), 8080. `remoteUser: vscode`; post-create installs delve.
- Works with GitHub Codespaces or local VS Code Dev Containers (steps: `.devcontainer/README.md`, CONTRIBUTE.md from "Development in Container" onward).
- `dev/devcontainer.json` is an older duplicate (same image, root user, no port config) — prefer `.devcontainer/`. `dev/dev_pelican.yaml` is the server config template CONTRIBUTE.md tells you to copy for the "federation in a box" walkthrough (`./pelican-server serve --module director,registry,origin,cache` — operation details in `pelican-run-and-operate`).
- Policy note (one line, owner `pelican-change-control`): PRs that change packages in `images/Dockerfile` must be split into two PRs — image update first (CONTRIBUTE.md ~line 101).

### 5.2 macOS native XRootD: `github_scripts/osx_install.sh`

This is the script macOS CI uses (`.github/workflows/test-macos.yml`, "Install macOS dependencies" step) to make origin/cache/fed tests runnable natively. What it does (values on main as of 2026-07-05):

1. `brew install coreutils`; downloads pinned **CMake 3.31.8** tarball from cmake.org (Homebrew's cmake 4.x breaks a dependency of xrootd-s3-http).
2. Builds from source, in order: scitokens-cpp `v1.4.1` → PelicanPlatform/xrootd fork tag `v5.9.2-pelican` → xrdcl-pelican `v1.7.1` → xrdhttp-pelican `v0.0.11` → xrootd-s3-http `v0.6.7`; symlinks the plugin libs into the XRootD libdir.
3. Appends your host's addresses to `/etc/hosts` (reverse-DNS workaround for xrootd issue #2159, which otherwise stalls startup ~10s), then smoke-tests an `xrootd` launch.

**Warning:** designed for disposable GitHub runners — it uses `sudo` freely, including `chmod -R 777 /usr/local`, and assumes `ninja`/compilers are present. Think hard before running it on a personal Mac. Expect tens of minutes (full XRootD compile). Not executed during this verification pass; contents verified by reading the script.

### 5.3 Frontend-only docker-compose loop

`web_ui/frontend/docker-compose.yml` + `web_ui/frontend/Makefile`: `docker compose run pelican-builder` (goreleaser in a container), then `docker compose up pelican-server pelican-api-proxy` (nginx proxy on 8443; you must hand-edit the `dist/` volume path in the compose file to match your arch dir), then `npm run dev` on :3000. Serving details → `pelican-run-and-operate`. Director work additionally needs a free MaxMind license key (CONTRIBUTE.md ~line 280).

## 6. XRootD pin-sync locations (mechanics only)

Bump POLICY (never casually bump; who approves; backports) is owned by `pelican-change-control`. These are the files that must move together, with values verified 2026-07-05:

| Location | main @ 289fd41b | v7.25.x (release branch) |
|---|---|---|
| `images/Dockerfile` `ARG XROOTD_VER` (~line 316; comment: "you must also update ... osx_install.sh") | `"5.9.2"` | `"5.9.1"` (commit `fe785866` "Downgrade xrootd version from 5.9.2 to 5.9.1") |
| `github_scripts/osx_install.sh` xrootd fork checkout | `v5.9.2-pelican` | `v5.9.1-pelican` |
| ... companion pins in the same script | scitokens-cpp `v1.4.1`, xrdcl-pelican `v1.7.1`, xrdhttp-pelican `v0.0.11`, xrootd-s3-http `v0.6.7` | `v1.1.3`, `v1.6.2`, `v0.0.11`, `v0.6.6` |
| `xrootd/version.go` `MinXrootdVersion` (runtime floor, NOT the build pin) | `"5.8.2"` | `"5.8.2"` |
| `.goreleaser.in.yml` pelican-server RPM deps (~line 470; comment: keep in sync with version.go) | `xrootd-server >= 1:5.8.2`, `xrdhttp-pelican >= 0.0.11` | same |

Note the deliberate two-level scheme: the *pin* (5.9.x, exact, per-branch) is what images/CI build against; the *floor* (5.8.2) is the oldest version the code accepts at runtime. The main-vs-v7.25.x divergence above is real and current — do not "sync" it without reading `pelican-change-control`.

## 7. Traps recap

| Trap | Symptom | Fix / rule |
|---|---|---|
| Stale `dist/` | Old binaries, wrong version stamps; a stale `dist/metadata.json` was observed claiming tag v7.19.4 with a literal `"%VERSION%"` (someone built against the unsubstituted `.in.yml`) | Never trust `dist/` contents; `make pelican-clean` and rebuild. Never pass `.goreleaser.in.yml` directly to goreleaser. |
| Placeholder UI | Binary builds fine but web UI is blank | Expected on fresh clone (§2a embed); run `make web-build` then rebuild (§2b). |
| Stale gitignored `parameters.json` | Web UI config page shows outdated parameters; docs JSON stale | Both files are gitignored and only refreshed by `make generate` — rerun it after touching `docs/parameters.yaml`. |
| Windows `web-build` is fake | CI/dev builds on Windows have no UI | By design (Makefile lines 82-86); build the UI on mac/Linux or in docker. |
| GoReleaser v1 | `only configurations files on version: 1 are supported, yours is version: 2` | Install v2 or `USE_DOCKER=1` (§1.1, §2f). |
| `.goreleaser.dev.yml` missing / README example lacks `client` tag | `make pelican-dev-build` fails; or dev config fails with `build constraints exclude all Go files` | Hand-create from README example AND add `client`/`server` to `tags:` (§2e). |
| git-describe on main | Snapshot self-reports `7.19.4-next` | Cosmetic; release tags live on release branches (§4). |
| Make info-noise | Huge "files have changed" wall on every `make` | `Makefile` line 53 `$(info ...)`; ignore (§3). |
| `pelican-serve-test-origin` | `cd: dist/pelican_darwin_arm64: No such file or directory` | Target predates goreleaser's `_v8.0`/`_v1` arch-suffixed dirs; `cd` into the suffixed dir manually (§3). |
| `go generate ./...` skips CLI docs | `docs/app/commands-reference/` never updates | Build constraints exclude `cmd/` without tags; run `go generate -tags client ./cmd` (§2c). |
| goreleaser before-hook `go mod tidy` | Unexplained `go.mod`/`go.sum` diffs after a snapshot build | Known behavior (§4); review before committing. |
| AGENTS.md documented discrepancy | AGENTS.md (~line 382) says `make validate-parameters` | **No such target exists** — the root Makefile's 11 targets are listed in §3. Run the validator per **pelican-config-and-flags** §9.5; the CI gate is **pelican-change-control** §1.6. |

## Provenance and maintenance

All facts verified 2026-07-05 against `main` @ `289fd41b` on a macOS arm64 host (go1.25.0, node v24.11.1, npm 11.6.2, goreleaser v1.26.2, docker 27.4.0, no system XRootD). Commands marked "verified" were executed on that host; items marked "derived" were verified by reading source/config only (`USE_DOCKER=1` paths, `npm ci && npm run build`, `osx_install.sh` execution, full goreleaser snapshot).

Re-verification one-liners for volatile facts:

| Volatile fact | Re-check command |
|---|---|
| Go version pin | `grep '^go ' go.mod` |
| Node engines pin | `grep -A2 '"engines"' web_ui/frontend/package.json` |
| GoReleaser config version | `grep -n '^version:' .goreleaser.in.yml` |
| cmd build constraint | `head -1 cmd/main.go` |
| Embed + placeholder | `grep -n 'go:embed' web_ui/ui.go && git ls-files web_ui/frontend/out` |
| go:generate census (expect 3) | `grep -rn "go:generate" --include='*.go' . \| grep -v _test` |
| Makefile target list (expect 11 PHONY) | `grep -c PHONY Makefile && grep -n '^\.PHONY' Makefile` |
| `.goreleaser.dev.yml` still untracked | `git log --oneline --all -- .goreleaser.dev.yml` (empty) and `grep -n goreleaser.dev .gitignore` |
| README dev example still missing client tag | `grep -n -A2 'tags:' README.md` (expect only `- forceposix`) |
| git-describe trap still present on main | `git describe --tags` (ancient tag + offset) |
| XROOTD_VER pin (main) | `grep -n 'ARG XROOTD_VER' images/Dockerfile` |
| XROOTD_VER pin (release branch) | `git show v7.25.x:images/Dockerfile \| grep 'ARG XROOTD_VER'` |
| osx_install.sh pins | `grep -n 'checkout v\|--branch' github_scripts/osx_install.sh` |
| MinXrootdVersion | `grep -n 'MinXrootdVersion =' xrootd/version.go` |
| RPM xrootd dep | `grep -n 'xrootd-server >=' .goreleaser.in.yml` |
| Devcontainer image | `grep -n '"image"' .devcontainer/devcontainer.json` |
| pre-commit hook versions | `grep -n 'rev:' .pre-commit-config.yaml` |
| AGENTS.md validate-parameters discrepancy | `grep -n 'validate-parameters' AGENTS.md Makefile` (hit in AGENTS.md only) |
| serve-test-origin dist path still stale | `grep -n 'pelican_\$(goos)' Makefile && ls dist/ 2>/dev/null` |
