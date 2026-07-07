---
name: pelican-docs-and-writing
description: Load when maintaining Pelican's docs of record — editing docs/parameters.yaml descriptions, docs/error_codes.yaml, docs/scopes.yaml, swagger/pelican-swagger.yaml, docs/pelican-http-headers.md, or docs/app/**/page.mdx prose; when asked "where does docs.pelicanplatform.org come from", "how do I document a new endpoint/parameter/error code/scope/header", "why isn't my merged doc change on the website"; when the check-go-generate or Validate Parameters CI job fails; when mdformat mangles a table; when writing license headers, design docs, or fixing AGENTS.md drift. Contains the docs/ consumer map, the sibling-repo docs-site pipeline and its traps, numbered update checklists per artifact type, house style as-enforced vs as-written, and known AGENTS.md errors.
---

# Pelican Docs and Writing

How to maintain every documentation artifact in this repo, what actually consumes each one, and the traps between "I edited the file" and "readers can see it".

## When to use this skill

- You are adding or changing a config parameter's docs entry, an error code, a token scope, an HTTP API endpoint, an `X-Pelican-*` header, a CLI command, or user-facing prose.
- CI failed with `Check Go Generate Has Been Run` or `Validate Parameters File` and you need to know what to regenerate or fix.
- You need to know where docs.pelicanplatform.org content comes from, why a merged change is not visible there, or how to preview the site locally.
- You are creating a new file and need the license-header rule, or writing markdown and need to know what mdformat will do to it.
- You found an error in AGENTS.md or another doc of record and need to know the fix-it duty.

**When NOT to use — route to siblings:**

- Parameter *code* mechanics (param API, viper precedence, deprecation cycle, add-a-param code checklist) → **pelican-config-and-flags**. This skill covers only the docs surface.
- PR gates, branch/backport/release-tag process, the four non-negotiable rules → **pelican-change-control**.
- Toolchain, goreleaser, `make` build paths → **pelican-build-and-env**.
- Definitions of federation jargon (director, origin, scopes as a concept, token profiles) → **pelican-federation-domain-reference**.
- Test-writing idioms and CI test matrix → **pelican-testing-and-qa**.
- Whether a design idea merits a design doc / evidence bar for claims → **pelican-research-methodology**.

## 1. Consumer map: what lives in `docs/` and who reads it

All paths relative to repo root. "Tracked" = committed to git; "gitignored" = regenerated locally and never committed.

| Artifact | Hand-edited? | Consumers |
|---|---|---|
| `docs/parameters.yaml` (447 entries, 2026-07-05) | YES — source of truth | (a) `go:embed` in `docs/docs.go` → `docs.ParsedParameters` → `pelican config man`/`config get` (`cmd/config_printer/`) and unknown-key warnings in `config/config.go`; (b) `generate/param_generator.go` → tracked `param/parameters.go`, `param/parameters_struct.go`, `config/parameter_defaults.go` + gitignored `docs/parameters.json`, `web_ui/frontend/public/data/parameters.json`; (c) CI validator `.github/scripts/validate-parameters/main.py`; (d) docs-site Configuration page (via the generated JSON, see §2) |
| `docs/error_codes.yaml` (26 entries) | YES | `generate/error_code_generator.go` → tracked `error_codes/error_codes.go` + gitignored `docs/error_codes.json`, `web_ui/frontend/public/data/error_codes.json`; docs-site per-code pages `docs/app/error/code/[code]/page.tsx` |
| `docs/scopes.yaml` (36 entries) | YES | `generate/scope_generator.go` → tracked `token_scopes/token_scopes.go`; scope descriptions drive the management UI's scope picker |
| `docs/pelican-http-headers.md` | YES — fully manual | Humans/agents only. The sole in-repo pointer to it is AGENTS.md ("Documentation" section). Nothing generates it, nothing checks it — see checklist §3.5 |
| `docs/app/` | YES (prose) except `commands-reference/` (generated) | Source tree of docs.pelicanplatform.org (Nextra 4, Next.js App Router — `docs/app/layout.tsx` imports `nextra-theme-docs`). Built by the sibling repo, see §2 |
| `docs/app/commands-reference/` (245 tracked files) | NO — generated | `go:generate` directives in `cmd/main.go` (generator: `generateCLIDocs` in `cmd/doc_gen.go`) |
| `docs/public/` | YES | Static assets for the docs site (screenshots, `origin-dashboard-template.json`). Copied to `public/pelican/` in the sibling repo; referenced from `.mdx` as `<ExportedImage src="/pelican/..."/>` |
| `docs/images/` | YES | Screenshots used only by `CONTRIBUTE.md` (e.g. `./docs/images/docker-startup.png`). Not on the website |
| `docs/docs.go` | YES (code) | Embeds + parses `parameters.yaml` at init for in-binary parameter help |
| `docs/parameters.json`, `docs/error_codes.json` | NO — generated AND **gitignored** (`.gitignore` lines 3–4) | Consumed by the docs-site build, which regenerates them itself (§2). Never commit these |
| `docs/collections-design.md`, `docs/user-group-design.md`, `docs/aup-example.md` | YES | Maintainer-facing design docs / example policy. NOT rendered on the website (only `docs/app/` is) |
| `swagger/pelican-swagger.yaml` (8308 lines) | YES — no generator | Copied by `GenSwaggerDoc` (`generate/next_generator.go`) to gitignored `web_ui/frontend/app/api/docs/pelican-swagger.yaml`, rendered by SwaggerUI in the admin web UI at `/api/docs`; also fetched raw from GitHub `main` by the public docs site (§2 trap) |
| `features/resources/feature-version-compatibility.yaml` | YES | `generate/server_features_generator.go` → tracked `features/features.go` |

Key correction to older notes you may find: the generated JSONs and the swagger copy under `web_ui/` are **gitignored, not committed**. You commit YAML + regenerated `.go` files (+ regenerated `commands-reference/` mdx) only.

## 2. The docs-site pipeline and its traps

**docs.pelicanplatform.org is built from the sibling repo [PelicanPlatform/docs](https://github.com/PelicanPlatform/docs), which pulls THIS repo in as a git submodule.** Authoritative prose lives HERE in `docs/app/`. Never edit page content in the docs repo. (External-repo facts below verified via `gh api` against PelicanPlatform/docs on 2026-07-05.)

How the build works (`.github/workflows/nextjs.yml` in the docs repo):

1. Triggers: push to the docs repo's `main`, manual dispatch, and a **daily cron at 12:00 UTC**.
2. It lists this repo's tags and builds **one site per minor version ≥ v7.18.0**, checking out the pelican submodule at the **highest patch tag of each minor** — including `vX.Y.Z-docs.N` tags, which sort above `vX.Y.Z` (real examples: `v7.21.5-docs.1`, `v7.25.1-docs.0`). "latest" = the highest tag overall, served at the site root; other minors under `/vX.Y/`.
3. In the submodule it runs `make generate USE_DOCKER=1`, then copies `docs/parameters.json` and `docs/error_codes.json` into the site's `public/static/` — that is how the gitignored JSONs reach `docs/app/parameters/page.mdx` (`import parameters from '/public/static/parameters.json'`) and `docs/app/error/code/[code]/page.tsx`.
4. The site's `prebuild` script (`scripts/setup.mjs`) copies `docs/app/` → `app/` and `docs/public/` → `public/pelican/`. Site-side React components (`Parameters.tsx`, `ErrorCodePage`, `Terminal.tsx`, …) live in the docs repo's `components/` — component changes go THERE; prose changes go HERE.

**TRAP — publication delay:** the site builds from *tags*, not `main`. Prose merged to `main` appears on the public site only once it is contained in a release tag (or a docs-republish tag `vX.Y.Z-docs.N` cut on a release branch) AND the site workflow runs. If docs must ship without a code release, ask a maintainer to cut a `-docs.N` tag (tagging process → **pelican-change-control**).

**TRAP — API docs page is different:** `docs/app/api-docs/page.mdx` fetches the swagger spec at build time from `https://raw.githubusercontent.com/PelicanPlatform/pelican/main/swagger/pelican-swagger.yaml`. So the public API reference always reflects **`main` at the moment the site last built** — regardless of which version's site you view, and your branch's swagger edits appear only after merge to main + a site rebuild.

**TRAP — the docs repo README is stale:** it still says the authoritative copy lives under `/docs/pages`. This repo migrated to `docs/app/` (Nextra 4 App Router) in commit `10e8f36b` "Update docs to v4" (2025-06-12). Trust the README's *workflow* description, not its paths.

**Note:** the docs repo's submodule pointer is bumped manually (`update-submodules.yml`, `workflow_dispatch` only), but the pointer barely matters for content — the build re-checkouts the submodule at each tag anyway.

### Local preview of docs/app changes

From the docs repo README (verified 2026-07-05; requires node ≥ 14.15):

```bash
# in a scratch directory, with this repo checked out as a sibling named "pelican"
git clone https://github.com/PelicanPlatform/docs.git
cd docs
echo "PELICAN_PATH=../pelican" > .env.local   # point at YOUR checkout
npm i           # FAILS if PELICAN_PATH is wrong
npm run dev     # live preview at http://localhost:3000, hot-reloads on docs/ edits
```

`_meta.js` throws `Missing required env variable VERSIONS` only when `NODE_ENV` is not `development`, so `npm run dev` works without `VERSIONS`.

## 3. Update checklists

All regeneration goes through ONE entry point. From repo root:

```bash
make generate        # touches the gitignored JSON stubs, then runs: go generate ./...
```

Expected (derived from the Makefile and CI, not executed here — the command rewrites generated files): a `$(info ...)` line about website rebuild files, then silence on success; failures panic with the offending YAML entry. It runs the 7 generators in `generate/main.go` (`GenParamEnum, GenParamStruct, GenDefaults, GenSwaggerDoc, GenTokenScope, GenErrorCodes, GenServerFeatures`) plus the two `go:generate` directives in `cmd/main.go` (commands-reference). Generators use `../docs/...` relative paths, so they only work via `go generate` (package cwd), never `go run ./generate` from root. CI gate: `.github/workflows/check-go-generate.yml` reruns `go generate ./...` and fails on any `git diff` — **a YAML edit without the regenerated tracked files fails CI**.

### 3.1 New/changed config parameter (docs surface only; code side → pelican-config-and-flags)

1. Edit `docs/parameters.yaml` (multi-document YAML, entries separated by `---`). Read the ~120-line header comment first — it is the authoritative spec for naming, `${Param}` references, default tiers (`default`/`root_default`/`osdf_default`/`client_default`/`server_default`), and which defaults must stay in Go.
2. Required keys (enforced by `.github/scripts/validate-parameters/main.py`): `name`, `description`, `type`, `default`, `components`.
   - `type` must be one of: `bool, byterate, duration, filename, int, object, string, stringSlice, url`.
   - `components` entries must be from: `*, broker, cache, client, director, localcache, origin, plugin, registry`. Tag every component that reads the param; `["*"]` for global.
3. Description quality bar (conventions observed across the file): complete sentences; say what it does, its units, and interactions with other params; backtick param names and literal values; Markdown renders on the docs site (block scalars `>-` or `|+` are both used). This description IS the public reference page and the `pelican config man <param>` output — write it for an operator.
4. `type: object` params additionally require the param name to be listed in `VERIFIED_OBJECT_STRUCTURES` inside `.github/scripts/validate-parameters/main.py`, which asserts the web UI can render it — otherwise the validator fails. Coordinate with a web-UI developer before adding one.
5. Optional keys: `hidden: true` (exclude from public docs), `deprecated: true` + `replacedby: <name-or-"none">` (deprecation mechanics and the never-break-prod-config rule → **pelican-config-and-flags**), `runtime_configurable: true`.
6. Run `make generate` from repo root.
7. Commit: `docs/parameters.yaml` + regenerated `param/parameters.go`, `param/parameters_struct.go`, `config/parameter_defaults.go`. Do NOT commit the JSONs (gitignored).
8. CI gates that will check you: `validate-parameters.yml`, `check-go-generate.yml`.

Local pre-flight (what CI runs; needs `pyyaml`):

```bash
# from repo root
python3 -m pip install pyyaml    # or use a venv
python3 .github/scripts/validate-parameters/main.py && echo OK
```

Expected: `OK` and exit 0 (verified 2026-07-05 on a clean tree); on error it raises `RuntimeError` listing every offending entry.

### 3.2 New error code

1. Edit `docs/error_codes.yaml`. Its header comment defines the 4-digit scheme — quote, verbatim semantics:
   - 1st digit: the type of error (1xxx Parameter, 2xxx Resolution, … — follow the section banners in the file).
   - 2nd digit: "Nothing yet" (reserved).
   - 3rd digit: 1 if the user/submitter can modify something to fix the error, 0 otherwise.
   - 4th digit: the sub-type of the error.
2. Required keys per entry (enforced by `generate/error_code_generator.go`, which panics if missing): `type`, `code`, `clientExitCode`, `description`, `retryable`.
   - `type` is dotted CamelCase, subtype after the dot: e.g. `Resolution.Timeout` (the generator converts to snake-case display names).
   - `clientExitCode`: the process exit code the client uses for this family.
   - `retryable`: true iff a whole-job HTCondor retry could plausibly succeed (different cache/site, or same site in a better state).
3. Place the entry under the matching `####` section banner, keeping codes sorted.
4. `make generate`; commit `docs/error_codes.yaml` + `error_codes/error_codes.go`. JSONs are gitignored.
5. The docs site gets a per-code page automatically from the JSON (`docs/app/error/code/[code]/page.tsx`) — no prose page needed.

### 3.3 New token scope

1. Edit `docs/scopes.yaml` (multi-document YAML). Naming convention from its header: `<resource_name>.<action_name>`, snake case (e.g. `pelican.director_advertise`).
2. Required keys (generator `GenTokenScope` in `generate/scope_generator.go` panics if missing): `name`, `description`, `issuedBy`, `acceptedBy`. Optional: `userGrantable: true` (assignable to users/groups via the management UI), `pathBearing: true` (composes with a path suffix via `TokenScope.Path()`).
3. Prefix routing inside the generator: names starting `wlcg.`/`scitokens.`/`lot` are emitted into separate scope categories; everything else is a Pelican scope. Put the entry under the matching section banner.
4. `make generate`; commit `docs/scopes.yaml` + `token_scopes/token_scopes.go`.
5. The description is user-visible in the management UI's scope picker — write it as "what am I granting".

### 3.4 New/changed HTTP API endpoint

1. Hand-edit `swagger/pelican-swagger.yaml` **in the same PR** as the handler change. Per AGENTS.md ("API Documentation", verbatim): the spec "is **hand-edited** — there are no code annotations and no generator."
2. AGENTS.md conventions (its tag list is slightly stale — the file's actual `tags:` block, 2026-07-05, is: `auth, common, metrics, registry_ui, director_ui, director, origin_ui, cache_ui, collections, groups, users, me, invites, scopes, aup, issuer-admin`):
   - Pick the right tag.
   - OpenAPI 2.0 has no cookie-auth scheme, so authorization is contract-by-prose: note it in the description with the existing inline tags `` `Authentication Required` ``, `` `Admin privilege Required` ``, `` `User Admin Required` ``.
   - Define request/response shapes under `definitions:` and use `$ref`; reuse existing shapes only when the contract genuinely matches.
   - Reflect security-relevant behavior accurately (e.g. behavior differing for admin vs owner vs anonymous-token-bearer).
3. `make generate` copies the file into the admin web UI (`web_ui/frontend/app/api/docs/` — gitignored, nothing extra to commit).
4. Remember the §2 trap: the public API docs page shows `main`'s swagger at site-build time; verify your rendering locally in the admin UI at `/api/docs` or with any SwaggerUI viewer.
5. Wire-format discipline applies to the API itself: add, never rename (→ **pelican-architecture-contract**).

### 3.5 New/changed `X-Pelican-*` header

1. Hand-edit `docs/pelican-http-headers.md`. **Nothing generates, checks, or reminds you about this file** — grep confirms the only in-repo reference is AGENTS.md. If you add a custom header in code and skip this, the docs silently rot.
2. Follow the existing entry template exactly: `### X-Pelican-Foo` with **Direction**, **Purpose**, **Format**, **Description**, **Example** fields, and add the header to the Table of Contents at the top (Request / Response / Other sections).
3. It is a plain `.md` file, so the mdformat hook WILL rewrite it on commit (§4) — run `pre-commit run mdformat --files docs/pelican-http-headers.md` and re-check that tables/lists survived.

### 3.6 User-facing prose (website)

1. Edit or add `docs/app/<section>/.../page.mdx` in THIS repo. One directory per URL segment; the page file is always named `page.mdx` (App Router layout).
2. New page: create the directory + `page.mdx`, then add an entry to the parent directory's `_meta.js` for sidebar title/ordering.
3. Images: put the file under `docs/public/<section>/` and reference it as `<ExportedImage width={...} height={...} src={"/pelican/<section>/<name>.png"} alt={"..."} />` (the `/pelican/` prefix is where the docs-repo build mounts `docs/public/`).
4. Internal links: relative paths that keep the `.mdx` extension work, e.g. `[text](../getting-data-with-pelican/client.mdx#anchor)`.
5. Available components: standard Nextra imports (e.g. `import { Callout } from 'nextra/components'`) plus docs-repo components (`Terminal`, `ImageRow`, …) — the latter are defined in PelicanPlatform/docs `components/`, not here.
6. `.mdx` is NOT touched by any formatter (§4). Follow one-sentence-per-line manually.
7. Publication: merged prose is invisible on docs.pelicanplatform.org until a tag contains it and the site rebuilds (§2). For the impatient: local preview (§2), or request a `-docs.N` tag.

### 3.7 CLI command changes (commands-reference)

1. Any change to a cobra command (name, flags, help text) changes the generated command reference. The `go:generate` directives in `cmd/main.go` run `go run -tags client . generate-docs docs/app/commands-reference/pelican` and `go run -tags server . generate-docs docs/app/commands-reference/pelican-server`.
2. `make generate` regenerates the trees; the generator (`cmd/doc_gen.go`) renders cobra docs to `page.mdx` + `_meta.js` files, escapes MDX-hostile angle brackets, and honors a `hiddenFromDocs` list for unlisted commands.
3. These 245 files ARE tracked — commit the regenerated diff, or `check-go-generate.yml` fails your PR.

## 4. House style: as written vs as enforced

| Rule | As written | As enforced (reality) |
|---|---|---|
| One sentence per line | AGENTS.md (lines 60 and 286, 2026-07-05): "use one sentence per line for markdown files" in `docs/` | The pre-commit mdformat hook (`.pre-commit-config.yaml`, mdformat rev 1.0.0 + `mdformat-simple-breaks` + `mdformat-gfm`, `--wrap no`, `files: \.md$`) enforces one-**paragraph**-per-line on `.md` only — it joins each paragraph onto a single line (`docs/aup-example.md` has 655-char lines). `.mdx` — i.e. the entire website — is formatted by nothing |
| Tables in `.md` | (unwritten) | Historically mdformat without GFM support collapsed pipe tables into one unreadable line; `mdformat-gfm` was added to stop that (see the comment in `.pre-commit-config.yaml`: "without it mdformat does not recognize pipe tables and, with --wrap no, collapses each table into a single unreadable line"). A live casualty survives: the "Supported Versions" table in `SECURITY.md` is still mangled onto one line (line 7, 2026-07-05) |
| Spelling | (unwritten) | `typos` pre-commit hook (crate-ci/typos) **auto-fixes** what it thinks are typos in your files — review its edits, it can be wrong |
| License headers | AGENTS.md Code Conventions #1: every Go file gets the Apache-2.0 block, "use current year" | **No automated enforcement**: no `goheader` linter in `.golangci.yaml`, no hook, no workflow. Years across the tree vary (2024/2025/2026) and are not policed |

History of the sentence rule, for context: commit `911bbbc8` added the mdformat hook (named "one sentence per line") for `.md` and `.mdx`; commit `bb4957bd` (2026-01-14) excluded `.mdx` — commit message, verbatim: "Sigh, looks like mdformat works for .md but not .mdx".

**Practical rules to follow:**

1. In any `.md` under `docs/` (or root-level docs): write one sentence per line, then let `pre-commit run mdformat --files <file>` rewrite it however it wants. Never hand-fight the hook — CI (`pre-commit-linter.yml`) runs the same hooks and will flip your formatting back.
2. After the hook runs on a table-containing `.md`, eyeball the table. If it got collapsed, the file probably has non-GFM table syntax — fix the table, don't disable the hook.
3. In `.mdx`: no tool will help or hurt you; follow one-sentence-per-line by hand.
4. New file of any language: copy the Apache-2.0 header block verbatim from AGENTS.md ("Code Conventions" → "License Headers"), substituting the current year for `{YEAR}`. Use `//`-comment framing for Go (the `/*…*/` box in AGENTS.md), `#` framing for YAML/Python/Makefile (see the top of `docs/parameters.yaml` for the canonical `#` form). Do not churn the year in files you merely edit — nothing requires it and it bloats diffs.

## 5. Commit and PR conventions (summary — owner: pelican-change-control)

- Observed subject style: lower-case `component:` prefix (`director:`, `database:`, `web_ui:`, `fed_test_utils:`) — convention, not enforced.
- CI-enforced (`enforce-PR-labelling.yml`): every PR needs ≥1 label AND a linked issue (`Fixes #N` / `Closes #N` in the body, or the sidebar). Also `check-rebase-on-main.yml` requires your branch to be a literal rebase onto `origin/main`. Details, backports, release trains → **pelican-change-control**.
- CONTRIBUTE.md requires PRs to "Include documentation in the repo under the docs folder" — reviewers do read this.

## 6. AGENTS.md maintenance

AGENTS.md is the agent-facing doc of record; when it and reality disagree, reality wins and **you must fix AGENTS.md in the same PR that exposed the drift** (repo write rules of your session permitting — otherwise file an issue).

Known errors/drift, verified 2026-07-05:

1. **`make validate-parameters` does not exist** (AGENTS.md line 382, "Useful Commands"). There is no such Makefile target (`grep '^validate' Makefile` → nothing). The real check is `python3 .github/scripts/validate-parameters/main.py` from repo root (needs `pyyaml`), which is exactly what CI's `validate-parameters.yml` runs.
2. **The swagger tag list is incomplete** (AGENTS.md "API Documentation"): the actual `tags:` block in `swagger/pelican-swagger.yaml` also contains `scopes` and `aup`, which AGENTS.md omits.
3. **"One sentence per line" overstates enforcement** — see §4; treat it as a writing convention, not a tooling guarantee.
4. Adjacent orphan (not in AGENTS.md but you will trip on it near #1): `.github/scripts/validate-defaults/main.py` is **dead** — it reads `config/resources/defaults.yaml`/`osdf.yaml`, which were deleted in commit `29eb3899` "Wire up generated defaults and SourceTracker in config init" (2026-06-17; defaults now come from `parameters.yaml` via generated `config/parameter_defaults.go`). Running it crashes with `FileNotFoundError` (verified). `validate-parameters.yml` still installs its requirements but never runs it. If you touch that workflow, remove the leftovers.

## 7. Design docs

There is no ADR/RFC system. Convention: an ad-hoc `*design*.md` living next to its subject. The complete in-tree set (2026-07-05, `find . -iname "*design*"` excluding node_modules):

| Doc | Subject |
|---|---|
| `docs/collections-design.md` | Collections feature design |
| `docs/user-group-design.md` | User/group model design |
| `client_agent/DESIGN-CLIENT-API-SERVER.md` | Client-agent REST API design |

Notes: these are maintainer-facing — files in `docs/` outside `docs/app/` never reach the website. They are `.md`, so mdformat applies; they are table-heavy (the reason `mdformat-gfm` exists, per the `.pre-commit-config.yaml` comment). Write a new one when a change spans subsystems or freezes an interface others must honor; the decision criteria and evidence bar for design claims → **pelican-research-methodology**. Numbered invariants extracted from designs → **pelican-architecture-contract**.

## Provenance and maintenance

Facts verified 2026-07-05 against `main@289fd41b` (this repo) and, where marked, the live PelicanPlatform/docs repo via read-only `gh api`. Line numbers drift — prefer the symbol names given. Re-verify volatile facts cheaply:

| Volatile fact | Re-verification command (from repo root) |
|---|---|
| Param entry count (447) | `grep -c '^name:' docs/parameters.yaml` |
| Error code count (26) | `grep -c '^type:' docs/error_codes.yaml` |
| Scope count (36) | `grep -c '^name:' docs/scopes.yaml` |
| Commands-reference tracked file count (245) | `git ls-files docs/app/commands-reference/ \| wc -l` |
| Generated JSONs still gitignored | `git check-ignore docs/parameters.json docs/error_codes.json web_ui/frontend/app/api/docs/pelican-swagger.yaml` |
| Generator list (7 funcs) | `sed -n '/func main/,/}/p' generate/main.go` |
| Scope required keys | `grep -nE 'requiredScopeKeys\|missing the name attribute' generate/scope_generator.go` (`name` is enforced by a separate up-front panic, not the array) |
| Error-code required keys | `grep -nE "requiredErrorKeys\|'type' attribute" generate/error_code_generator.go` (`type` is enforced by a separate panic, not the array) |
| Validator key/enum lists | `sed -n '1,50p' .github/scripts/validate-parameters/main.py` |
| `make validate-parameters` still missing | `grep -n 'validate' Makefile` (expect no target) |
| validate-defaults still orphaned | `grep -rn 'validate-defaults/main.py' .github/workflows/` (expect only the pip install line) |
| mdformat hook scope (`.md` only, `--wrap no`) | `grep -n -A13 'mdformat' .pre-commit-config.yaml` |
| SECURITY.md table still mangled | `sed -n '7p' SECURITY.md` (one giant line = still broken) |
| Swagger tag list | `grep -n '^  - name:' swagger/pelican-swagger.yaml` |
| AGENTS.md one-sentence/validate-parameters lines | `grep -n 'sentence per line\|validate-parameters' AGENTS.md` |
| cmd go:generate directives | `grep -n 'go:generate' cmd/main.go` |
| Docs-site build recipe (tags ≥ v7.18, cron, `make generate USE_DOCKER=1`, raw-main swagger fetch) | `gh api repos/PelicanPlatform/docs/contents/.github/workflows/nextjs.yml --jq '.content' \| base64 -d` |
| Docs repo README still says `docs/pages` | `gh api repos/PelicanPlatform/docs/readme --jq '.content' \| base64 -d \| head -12` |
| `-docs.N` republish tags in use | `git tag -l '*docs*'` |
| Design-doc set | `find . -iname '*design*' -not -path '*/node_modules/*' -not -path '*/.git/*'` |

Commit anchors cited (stable): `10e8f36b` (docs → Nextra v4 App Router, 2025-06-12), `911bbbc8` (mdformat hook added), `bb4957bd` (.mdx excluded from mdformat, 2026-01-14), `29eb3899` (defaults.yaml deleted; generated defaults wired in, 2026-06-17).

OPEN QUESTIONS (unverifiable from the repos; ask a maintainer):

- Who is authorized to cut `vX.Y.Z-docs.N` republish tags, and what is the request path?
- Is one-sentence-per-line still intended policy for `.mdx` (unenforceable by mdformat), or quietly dropped?
- Is there a policy on bumping copyright years when substantially rewriting an existing file? (Observed: nobody does.)
