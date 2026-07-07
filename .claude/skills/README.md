# Pelican skill library

Sixteen skills that let an engineer or an AI agent debug, extend, validate, and advance the Pelican
codebase without prior context. Each lives in `<name>/SKILL.md` with YAML frontmatter (`name`,
`description`); the `description` is the trigger — a model loads the skill when its situation matches.
You do not read these top-to-bottom; you load the one whose triggers fire.

All facts were verified against **`main` @ commit `289fd41b`** (upstream sync of 2026-07-04) on
2026-07-05/06. Every skill ends with a **Provenance and maintenance** section carrying one-line
re-verification commands for its volatile facts. NOTE: the working tree is sometimes parked on a
release branch (e.g. `v7.25.x`); when a documented line/symbol seems off, re-verify read-only against
the pinned commit: `git show 289fd41b:<path>` or `git grep <pat> 289fd41b -- <path>`.

## Reading order for a newcomer

1. **pelican-architecture-contract** — the system, its invariants, and its weak points. Start here.
2. **pelican-federation-domain-reference** — the jargon and protocols (origin/cache/director, tokens, XRootD, broker). Keep open as a glossary.
3. **pelican-change-control** — how any change gets in, gated, and backported; the four non-negotiables.
4. Then load task-specific skills as their triggers fire (below).

## The sixteen skills

### Core knowledge
| Skill | Load it when… |
|---|---|
| **pelican-architecture-contract** | changing server code; you need the load-bearing invariants (I-1..I-10), the actor map, the XRootD-vs-Go data-plane matrix, or the trust/advertisement model. |
| **pelican-federation-domain-reference** | you hit unfamiliar terms or protocol behavior — `pelican://` vs `osdf:///`, WLCG/scitokens2 profiles, scopes, JWKS, TPC, cmsd, pfc/pss, geo-sort, the registry key-sign challenge, broker reversal. |
| **pelican-config-and-flags** | adding/deprecating a parameter, editing `docs/parameters.yaml`, running `go generate`, or hitting the `param.Refresh()` stale-snapshot trap; config precedence and `PELICAN_*`/`OSDF_*` env mapping. |

### Build, test, run
| Skill | Load it when… |
|---|---|
| **pelican-build-and-env** | building from scratch or setting up a dev env; "build constraints exclude all Go files", GoReleaser v2, `.goreleaser.dev.yml`, blank web UI, XRootD pin locations. |
| **pelican-testing-and-qa** | writing/running/debugging tests; build-tag matrix, `NewFedTest`/`ResetTestState`, the CI workflow table, the no-`time.Sleep`/no-`TLSSkipVerify` evidence bar. |
| **pelican-run-and-operate** | starting/deploying services or a fed-in-a-box; ports (8444/8443/8442), `/etc/pelican` layout, systemd/RPM/containers, health endpoints, the ops CLI. |
| **pelican-diagnostics-and-tooling** | you must MEASURE — race detector like CI, pprof, Prometheus scrape/query, runtime log-level, pin-drift; ships `goroutine_diff.sh`, `flaky_hunt.sh`, `check_xrootd_pins.sh`. |
| **pelican-docs-and-writing** | editing docs of record (`parameters.yaml`, `error_codes.yaml`, `scopes.yaml`, swagger, headers, `docs/app/**`); the sibling docs-site pipeline; house style; AGENTS.md drift. |

### History and process
| Skill | Load it when… |
|---|---|
| **pelican-change-control** | preparing/reviewing/backporting a change; a red CI check; bumping XRootD/a dependency; renaming a JSON field or metric; changing a default; interpreting rc tags. |
| **pelican-failure-archaeology** | something looks "obviously fixable"; you see a symptom matching a past incident (XRootD SIGABRT, director OOM, `database is locked`, typo'd metrics, a revert you don't understand). |
| **pelican-ecosystem-and-upstreams** | deciding WHERE to file a bug outside this repo — the XRootD fork and plugins, OSG/OSDF infra, the docs repo, external deps, or before claiming "Pelican supports X". |

### Advanced (the frontier layer)
| Skill | Load it when… |
|---|---|
| **pelican-director-reliability-campaign** | the hardest live problem — director at scale (serverAds/ttlcache locking, OOM, HA cascade, eviction-handler deadlock, clock-skew). A decision-gated, numbered campaign. |
| **pelican-concurrency-and-shutdown-proofs** | proving the costliest failure class — goroutine leaks, data races, shutdown ordering, ABBA deadlocks, `sync.Once` staleness (the nightly-only `-race` findings). Proof recipes with worked examples. |
| **pelican-research-frontier** | "what should we work on next" — six open reliability/self-healing problems, each with repo assets, first three steps, and a falsifiable milestone. |
| **pelican-research-methodology** | turning a hunch into an accepted result — the evidence bar, predict-numbers-first, the idea lifecycle, adversarial refutation, an investigation template. |

## The four non-negotiables (stated fully in pelican-change-control)

1. **Never casually bump XRootD/plugin versions** — pins are hand-synced across multiple files and must be qualified.
2. **Wire formats are frozen ABI** — `server_structs` JSON, Prometheus metric names/labels, director↔server APIs: add, never rename.
3. **Test discipline is sacred** — no `time.Sleep` (use `require.Eventually`), never `TLSSkipVerify` in committed fed tests, always `ResetTestState`.
4. **Config compatibility** — never change a default or remove a deprecated param without a deprecation cycle.

## Maintenance

When the repo drifts, run each skill's Provenance re-verification one-liners and update in place. Keep
frontmatter to exactly `name` + `description`; if a description must contain `:` or `#`, keep it as a
`>-` folded block scalar so strict YAML parsers accept it. Do not route any behavior change around
**pelican-change-control**.
