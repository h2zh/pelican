---
name: pelican-config-and-flags
description: Load when working with Pelican configuration parameters — adding/renaming/deprecating a param, editing docs/parameters.yaml, running go generate, debugging why param.X.GetString() returns a stale/empty value after viper.Set, mapping PELICAN_*/OSDF_*/STASH_* env vars, understanding config precedence (web UI vs flags vs env vs files vs defaults), default "none"/IsSet semantics, ${Param} interpolation, or the pelican config dump/get/describe/summary CLI. Contains the full parameters.yaml anatomy, the codegen pipeline, the param-API stale-snapshot trap with a runnable proof, the deprecation lifecycle, a dangerous-params table, and a verified add-a-param checklist.
---

# Pelican Configuration and Flags: the Parameter System End-to-End

Everything below was verified by execution or direct source reading on `main@289fd41b` (2026-07-05). Line numbers drift; every `path:line` is paired with a symbol name — search for the symbol if the line is off.

## When to use this skill

- You are adding, renaming, or deprecating a configuration parameter.
- You are editing `docs/parameters.yaml` or any file under `generate/`.
- `param.X.GetY()` returns a stale, zero, or empty value and you don't know why.
- You need the precedence order: web-UI config vs CLI flag vs env var vs config file vs default.
- You need to know what `PELICAN_SERVER_WEBPORT` (or an `OSDF_`/`STASH_` variable) maps to, or why an `OSDF_*` variable is being ignored.
- CI failed on `check-go-generate` or `validate-parameters`.
- You want to inspect a running/configured Pelican's effective config (`pelican config dump|get|describe|summary`).
- You hit `viper.IsSet` behaving unexpectedly (true for defaults), or need "did the user set this?" logic.

**When NOT to use — route to siblings:**
- Build tags, toolchain versions, goreleaser, XRootD pins → **pelican-build-and-env**
- Test isolation (`ResetTestState`, fed tests), test build-tag matrix → **pelican-testing-and-qa**
- Change classification, the four non-negotiable discipline rules, backports → **pelican-change-control**
- Ports/paths/endpoints/systemd of a running server → **pelican-run-and-operate**
- Federation jargon (director, registry, discovery, token profiles) → **pelican-federation-domain-reference**
- serverAds locking, wire-format freeze, launch ordering invariants → **pelican-architecture-contract**
- Docs-site pipelines and house style → **pelican-docs-and-writing**

## 1. Mental model (60 seconds)

```
docs/parameters.yaml  (ONE multi-doc YAML, the single source of truth, 447 entries)
        │  go generate ./...   (run from repo ROOT)
        ▼
param/parameters.go            typed singletons: param.Server_WebPort = IntParam{"Server.WebPort"}
param/parameters_struct.go     the Config struct (one field per param)
config/parameter_defaults.go   SetParameterDefaults / ApplyDerivedDefaults / Apply{Client,Server}Defaults
        │  at process startup (initConfigInternalImpl in config/config.go)
        ▼
global viper instance  ←── defaults, config files, env vars, CLI flags, viper.Set
        │  param.Refresh() decodes viper.AllSettings() into a *Config
        ▼
atomic snapshot (atomic.Pointer[Config] in param/param.go)  ←── ALL param getters read THIS, not viper
```

The single most important fact: **getters read the atomic snapshot, not live viper**. Mutating viper without rebuilding the snapshot yields stale reads (section 4).

## 2. `docs/parameters.yaml` anatomy

One `---`-separated multi-document YAML file. **447 entries, all five required fields present on all of them** (counted 2026-07-05). The file opens with a ~95-line design comment (lines 17–111) that documents naming, tiers, seed params, and interpolation — **read it before editing the file**; it is the best single doc in the repo.

### Field vocabulary with counts (2026-07-05)

| Field | Count | Meaning |
|---|---|---|
| `name` | 447 (required) | Dot-separated CamelCase: `<Component>.<Field>`, e.g. `Server.WebPort`. Top-level names allowed (`ConfigBase`, `Debug`, `TLSSkipVerify`). |
| `description` | 447 (required) | YAML block scalar (`\|+`). Rendered on docs site and by `pelican config describe`. |
| `type` | 447 (required) | See type table below. |
| `default` | 447 (required) | Base default. The literal string `"none"` means "no default" (see below). |
| `components` | 447 (required) | List drawn from the enum below. |
| `hidden` | 60 (58 `true`, 2 explicit `false`) | Hide from public docs. THE experimental-flag convention (section 7). |
| `deprecated` | 24 (all `true`) | Generator skips its `SetDefault`; runtime migration applies (section 6). |
| `replacedby` | 24 | Required whenever `deprecated: true` — generator panics otherwise (`GenParamEnum` in `generate/param_generator.go`, "is deprecated but missing 'replacedby' key"). Value: a name, a list, or `"none"`. |
| `root_default` | 22 | Overrides `default` when running as root (UID 0); FHS paths like `/run/pelican`. |
| `runtime_configurable` | 18 (17 `true`; `TLSSkipVerify` is the sole explicit `false`) | Changes intended to take effect without restart. All 17 `true` entries are `Logging.*` (section 7). |
| `osdf_default` | 10 | Overrides `default`/`root_default` in OSDF mode (binary named `osdf*`/`stash*`). |
| `direct_access` | 4 (all `false`) | Only the four `Federation.*Url` params. Generates an `OpaqueParam` (metadata methods, **no getters**) because values are computed by federation discovery. See `OpaqueParam` in `param/parameters.go`. |
| `server_default` | 1 (`Logging.Level: info`) | Applied only for server commands. |
| `client_default` | 1 (`Logging.Level: warn`) | Applied only for client commands. |

### Type vocabulary with counts (2026-07-05)

| type | count | | type | count |
|---|---|---|---|---|
| string | 103 | | int | 54 |
| bool | 85 | | stringSlice | 34 |
| duration | 72 | | url | 25 |
| filename | 64 | | object | 9 |
| | | | byterate | 1 |

Every `object`-typed param must be in the hand-verified allowlist `VERIFIED_OBJECT_STRUCTURES` in `.github/scripts/validate-parameters/main.py` (9 entries) or CI fails. The single `byterate` param is hidden `Origin.TransferRateLimit` (parses "10MB/s", "100Mbps"; see `byte_rate/byte_rate.go`).

### Components enum

From `ENUMERATIONS["components"]` in `.github/scripts/validate-parameters/main.py`:
`*, broker, cache, client, director, localcache, origin, plugin, registry`

(The header comment's own components list at parameters.yaml:107 is a stale subset — the validator script is authoritative.)

### Default tiers and precedence

Highest wins: **`client_default` / `server_default` > `osdf_default` > `root_default` > `default`** (parameters.yaml header, lines 97–98; implemented by generated `SetParameterDefaults`/`ApplyClientDefaults`/`ApplyServerDefaults` in `config/parameter_defaults.go`). Root/OSDF context comes from `defaultTierContext` in `config/config.go` (root = `IsRootExecution()`; OSDF = binary name prefix, section 5).

### `default: "none"` semantics — the IsSet contract

For a param whose default is the literal string `none`, the generator **emits no `v.SetDefault` call**, so `viper.IsSet` stays `false` until a user sets it. **90 params have `default: none`** (2026-07-05). This is the only YAML-native way to distinguish "not configured" from "set to default", because **`viper.IsSet` returns `true` for defaults** (stated in the `handleDeprecatedConfig` comment in `config/config.go`). For everything else, use the SourceTracker (section 5).

### `${Param}` interpolation

- Defaults may reference other params: `default: ${ConfigBase}/certificates/tls.crt` (33 lines reference `${ConfigBase}`; 45 default-tier lines interpolate some `${...}`, 2026-07-05). Bare `$ENV_VAR` (e.g. `$XDG_RUNTIME_DIR`) resolves via `os.Getenv` instead.
- The generator builds a dependency graph and topologically sorts with Kahn's algorithm (`topoSortParams` in `generate/param_generator.go`). A **cycle is a build-failing panic** in `GenDefaults` ("cycle detected in parameter defaults dependency graph").
- `validateNoTierShadowing` (same file) rejects interpolating any param that itself declares a `client_default`/`server_default` tier — the tier override would be silently ignored by the interpolation. Fold the override into the base default instead.
- "Seed" params — `ConfigBase`, `Server.Hostname` (set in `SetBaseDefaultsInConfig`, `config/config.go`) and `RuntimeDir` (set in `ensureRuntimeDir` during server init) — need runtime calls, so their defaults live in Go, not YAML. Other params may reference them via `${ConfigBase}` etc.; the topo sort treats seeds as pre-satisfied.

## 3. The codegen pipeline

**Run from the repo root** (directives live in per-package files, so `go generate ./...` must see them all):

```bash
cd <repo-root>
go generate ./...       # or: make generate  (pre-touches the gitignored .json files)
```

`generate/main.go` carries `//go:generate go run ../generate` and its `main()` runs, in order:
`GenParamEnum, GenParamStruct, GenDefaults, GenSwaggerDoc, GenTokenScope, GenErrorCodes, GenServerFeatures`.
Generators execute with cwd `generate/`; all output paths are `../`-relative.

A **second, independent directive set** in `cmd/main.go` (`//go:generate go run -tags client . generate-docs docs/app/commands-reference/pelican` and the `-tags server` twin) regenerates the Cobra CLI reference MDX for the in-repo docs site — 245 committed files under `docs/app/commands-reference/` (2026-07-05). A param-only change won't touch these, but CLI flag changes will.

### Outputs: committed vs gitignored

| Output | Git status | Producer |
|---|---|---|
| `param/parameters.go` | **committed** | GenParamEnum |
| `param/parameters_struct.go` | **committed** | GenParamStruct |
| `config/parameter_defaults.go` | **committed** | GenDefaults |
| `token_scopes/token_scopes.go` | **committed** | GenTokenScope (from `docs/scopes.yaml`) |
| `error_codes/error_codes.go` | **committed** | GenErrorCodes (from `docs/error_codes.yaml`) |
| `features/features.go` | **committed** | GenServerFeatures (from `features/resources/feature-version-compatibility.yaml`) |
| `docs/app/commands-reference/**/*.mdx` | **committed** | cmd generate-docs |
| `docs/parameters.json` | gitignored (`.gitignore:3`) | GenParamEnum |
| `web_ui/frontend/public/data/parameters.json` | gitignored (`.gitignore:5`) | GenParamEnum (copy for web-UI config page) |
| `web_ui/frontend/app/api/docs/pelican-swagger.yaml` | gitignored (`.gitignore:7`) | GenSwaggerDoc (copies `swagger/pelican-swagger.yaml`) |

**Stale-artifact trap (observed live 2026-07-05):** gitignored artifacts rot silently. On the machine this was written on, `docs/parameters.json` held **432** entries while the YAML held **447** — nothing complains, because git ignores the file and `GenParamEnum` skips rewriting it only when content is identical. If a doc/web-UI build shows missing params, regenerate; never trust an existing `parameters.json`. Check with:

```bash
jq length docs/parameters.json ; grep -c '^name:' docs/parameters.yaml   # must match
```

### Enforcement

`.github/workflows/check-go-generate.yml` runs `go generate ./...` on every PR and fails if `git diff` is non-empty. **This is what forces you to commit the regenerated Go files with every parameters.yaml change.** The generator itself panics loudly on: missing required keys, unknown type, deprecated-without-replacedby, `${}` cycles, tier shadowing.

`.github/workflows/validate-parameters.yml` runs `python3 .github/scripts/validate-parameters/main.py` (required keys, component/type enums, object-type allowlist). Note it also pip-installs `.github/scripts/validate-defaults/requirements.txt`, but the `validate-defaults` script targets `config/resources/defaults.yaml`, **which no longer exists** — that install is vestigial (verified 2026-07-05: `config/resources/` absent; workflow has no step executing validate-defaults).

Generator behavior itself is unit-tested: `go test ./generate/` (fast; passes on main@289fd41b) and `param/all_parameter_names_test.go`.

## 4. The `param` API — and THE CENTRAL TRAP

Each YAML entry becomes a typed singleton in `param/parameters.go` (447 of them, matching the YAML count):

```go
param.Server_WebPort.GetInt()          // dots → underscores in the Go name
param.Server_WebPort.GetName()         // "Server.WebPort"  (the viper key)
param.Server_WebPort.GetEnvVarName()   // "PELICAN_SERVER_WEBPORT"
param.Server_WebPort.IsSet()           // viper.IsSet under a mutex — true for defaults too!
param.Server_WebPort.IsRuntimeConfigurable()
param.Server_WebPort.Set(9999)         // typed setter → MultiSet (safe)
```

Name→env mapping (`paramNameToEnvVar` in `param/parameters.go`): dots→underscores, uppercase, prefix `PELICAN_`. The mapping is lossy (CamelCase boundaries vanish): `Origin.EnableCmsd` ↔ `PELICAN_ORIGIN_ENABLECMSD`.

### The trap: getters read an atomic snapshot, not viper

`GetString()/GetInt()/...` read from `atomic.Pointer[Config]` via accessor maps (see `getOrCreateConfig` and `stringAccessors` in `param/param.go` / `param/parameters.go`). A raw `viper.Set` updates viper but **not** the snapshot.

```go
// WRONG — the getter keeps returning the old value:
viper.Set("Server.WebPort", 9999)
port := param.Server_WebPort.GetInt()      // STALE (previous value)

// RIGHT (preferred) — typed setter updates viper AND the snapshot atomically:
err := param.Server_WebPort.Set(9999)      // → MultiSet, under configMutex

// RIGHT (bulk):
err := param.MultiSet(map[string]any{"Server.WebPort": 9999, "Logging.Level": "debug"})

// RIGHT (when third-party/legacy code must mutate viper directly):
viper.Set("Server.WebPort", 9999)
_, err := param.Refresh()                  // rebuild the snapshot from viper
```

Runnable proof (executed 2026-07-05; all four printed lines are real output). Start from the repo root:

```bash
REPO=$(git rev-parse --show-toplevel); DEMO=$(mktemp -d); cd "$DEMO"
cat > go.mod <<EOF
module staledemo
go 1.25.0
require github.com/pelicanplatform/pelican v0.0.0
replace github.com/pelicanplatform/pelican => $REPO
EOF
cat > main.go <<'EOF'
package main

import (
	"fmt"
	"github.com/spf13/viper"
	"github.com/pelicanplatform/pelican/param"
)

func main() {
	viper.Set("Server.WebPort", 8444)
	_, _ = param.Refresh()
	fmt.Println("initial GetInt():", param.Server_WebPort.GetInt())
	viper.Set("Server.WebPort", 9999) // WRONG pattern
	fmt.Println("after raw viper.Set  -> GetInt():", param.Server_WebPort.GetInt())
	_, _ = param.Refresh()
	fmt.Println("after param.Refresh() -> GetInt():", param.Server_WebPort.GetInt())
	_ = param.Server_WebPort.Set(7777) // RIGHT pattern
	fmt.Println("after param...Set()   -> GetInt():", param.Server_WebPort.GetInt())
}
EOF
go mod tidy && go run .
```

Expected output:

```
initial GetInt(): 8444
after raw viper.Set  -> GetInt(): 8444     <-- STALE
after param.Refresh() -> GetInt(): 9999
after param...Set()   -> GetInt(): 7777
```

Related facts, all in `param/param.go`:

- `MultiSet` holds `configMutex`, calls `viper.Set` per key, fires `SetHook` (registered by the config package so the SourceTracker records `SourceDynamic`), then re-decodes `viper.AllSettings()` into a fresh snapshot and invokes registered `ConfigCallback`s **in goroutines**.
- `viperIsSet`/`viperUnmarshalKey` wrap viper calls in `configMutex` because **viper's internal path cache panics under concurrent access**. Never call `viper.IsSet` directly from concurrent code; use `param.X.IsSet()`.
- `IsSet()` is `true` for values set by `SetDefault` — only `default: "none"` params reliably report "user didn't configure this" via IsSet.
- `BindAllParameters` binds every known key so env-only values appear in `AllSettings()` and hence in the snapshot; without it, `PELICAN_*`-only values would be invisible to getters.
- One subtle grace: if no snapshot exists yet, `getOrCreateConfig` lazily decodes from viper — so the stale-read bug only bites *after* config init, which in practice is always.
- **Never use raw `viper.GetString("Some.Key")` in new code** — it bypasses the accessor cache, the unknown-key validation (`validateConfigKeys` in `config/config_validation.go`), and compile-time key safety.

## 5. Precedence and configuration sources

Effective precedence, highest first (viper's documented order; Pelican mechanisms mapped):

| Rank | Source | Pelican mechanism |
|---|---|---|
| 1 | `viper.Set` | Web-UI overrides: `SetWebConfigOverride` in `config/config.go` reads `Server.WebConfigFile` (default `${ConfigBase}/web-config.yaml`) and calls `v.Set(key, ...)` per key **precisely so it outranks env vars**; also `param.Set/MultiSet` and legacy client env shims (`bindLegacyClientEnv`). |
| 2 | CLI flags | `viper.BindPFlag` in `cmd/` — e.g. `serve --port` → `Server.WebPort` (cmd/fed.go, init), `origin serve --mode` → `Origin.StorageType` (cmd/origin.go), `--default-response` → `Director.DefaultResponse` (cmd/director.go). `cmd/flag_binding_refresh_test.go` proves flags reach param getters. |
| 3 | Env vars | `SetEnvPrefix("pelican")` + `AutomaticEnv()` + `SetEnvKeyReplacer(".", "_")` in `initConfigInternalImpl`: `PELICAN_ORIGIN_ENABLECMSD` → `Origin.EnableCmsd`. |
| 4 | Config files | Main file, then `<PREFIX>_CONFIG_FILE` merge, then `ConfigLocations` (later merges win). |
| 5 | Defaults | Generated `SetParameterDefaults` + seeds + `ApplyDerivedDefaults` + hand-set deprecated defaults. |

Verified live (2026-07-05, repo root):

```bash
$ PELICAN_SERVER_WEBPORT=9000 go run -tags server ./cmd config get Server.WebPort
server.webport: 9000
```

### Config-file resolution order (`initConfigInternalImpl` in `config/config.go`)

1. `--config <file>` (bound to viper key `config` in `cmd/root.go`) — if set, it is THE config file.
2. Otherwise `pelican.yaml` in `ConfigBase` (`~/.config/pelican` non-root; `/etc/pelican` root), with `/etc/pelican` added as a **fallback search path for non-root** users. Viper takes the first file found, not a merge.
3. `PELICAN_CONFIG_FILE` (or `OSDF_CONFIG_FILE`/`STASH_CONFIG_FILE` per prefix) is then **merged over** the main file.
4. `ConfigLocations` (a param: list of directories): every `*.yaml`/`*.yml` in each directory is merged in **directory-scoped lexicographic order, last wins** (`handleContinuedCfg`). Name files `01-base.yaml`, `10-site.yaml`, … to control order.
5. `ApplyDerivedDefaults` then re-resolves every `${...}`-interpolated default against the *user-set* dependency values (e.g. you set `Cache.StorageLocation` ⇒ `Cache.DataLocations` default follows), **skipping keys the SourceTracker says the user set explicitly**; then `param.Refresh()`; then `handleDeprecatedConfig()`; then `validateConfigKeys()` warns on unrecognized keys.

### OSDF/STASH legacy prefixes

`GetPreferredPrefix` (`config/config.go`): prefix is `OSDF` iff the **binary name** (arg0) starts with `osdf`/`stash`, else `PELICAN`. Consequences, often misunderstood:

- `OSDF_*`/`STASH_*` env vars are bound **only when the binary is named osdf*/stash*** (`bindNonPelicanEnv` in `config/env.go` early-returns for the pelican prefix). Setting `OSDF_FOO` against a binary named `pelican` does nothing.
- OSDF mode also flips the `osdf_default` tier (`defaultTierContext`).
- Bound legacy vars log: "Environment variables with OSDF prefix will be deprecated in the next feature release."
- Grandfathered client oddballs (`OSG_DISABLE_HTTP_PROXY`, `NEAREST_CACHE`, `*_DIRECTOR_URL`, …) are handled in `bindLegacyClientEnv` — those use `viper.Set`, i.e. rank 1.

### SourceTracker: provenance of every key

`config/source_tracker.go` records, per lowercased key, one of: `SourceDefault`, `SourceConfigFile` (+file path), `SourceEnvVar` (+var name), `SourceWebConfig` (+file path), `SourceDynamic` (programmatic `Set`). It is what `handleDeprecatedConfig` and `ApplyDerivedDefaults` consult for "did the user really set this?" — the reliable replacement for `IsSet`.

### Inspecting effective config: the `pelican config` command

Subcommands (source: `cmd/config_printer/config_printer_root.go`; all executed 2026-07-05 via `go run -tags server ./cmd config ...` from repo root):

| Command | What it does | Verified output shape |
|---|---|---|
| `pelican config dump [-o yaml\|json]` | Full effective config, defaults included | Nested YAML: `Cache:\n    DbLocation: /Users/.../cache.sqlite` … |
| `pelican config get [patterns] [-m module] [--include-hidden] [--include-deprecated] [--exact-match] [-v]` | Case-insensitive substring match on names/values, flattened grep-friendly output | `server.webport: 8444` |
| `pelican config describe <param>` (aliases: `desc`, `man`, `doc`) | Renders the parameters.yaml docs for one param | `Parameter: Server.WebPort / Type: int / Default: 8444 / Modules: [...]` + description |
| `pelican config summary [-o yaml\|json]` (alias `sum`) | Only values differing from defaults | On a clean machine, just runtime-computed keys, e.g. `RuntimeDir: /var/.../pelican-xrootd-…` |

Persistent flags: `--with-discovery` (include discovered federation values), `-s/--service` (evaluate as origin/cache/etc.). There is no `pelican config set` — runtime changes go through the admin web UI (which writes `web-config.yaml`).

## 6. Deprecation lifecycle

Mechanism, end to end (all verified by execution):

1. In YAML: `deprecated: true` + `replacedby: <NewName | [names] | "none">`. Missing `replacedby` ⇒ generator panic.
2. `GenDefaults` **skips `SetDefault`** for deprecated params, so `viper.IsSet(deprecated)` is false unless a user actually set it. `GenParamEnum` emits the `param.GetDeprecated()` map (old → replacements) in `param/parameters.go`.
3. Because the generator skips them, any default a deprecated param still needs is **hand-maintained in `SetServerDefaults`** (`config/config.go`, look for the comment "Deprecated param defaults: excluded from generated SetParameterDefaults"): currently `IssuerKey` and the three `{Cache,Director,Registry}.DbLocation` root/non-root pairs. The "GUIDANCE FOR DEVELOPERS" comment right above `SetServerDefaults` defines the only three categories of defaults allowed in Go: deprecated params, runtime-computed values, conditional federation URLs.
4. At startup `handleDeprecatedConfig` (`config/config.go`) runs once: for each set deprecated key it warns, then **copies the old value onto each replacement via `param.SetRaw` — unless the SourceTracker shows the user explicitly set the replacement**, in which case the deprecated value is ignored with a distinct warning.
5. Special case: `Debug` (bool) can't copy onto `Logging.Level` (string); `setLoggingInternal` maps it, and `handleDeprecatedConfig` only warns.

Live demos (executed 2026-07-05, repo root):

```bash
$ PELICAN_CACHE_LOCALROOT=/tmp/demo go run -tags server ./cmd config get Cache.StorageLocation
cache.storagelocation: "/tmp/demo"
# warning: 'Cache.LocalRoot' is deprecated ... Will use the value of deprecated config key ...

$ PELICAN_CACHE_LOCALROOT=/tmp/demo PELICAN_CACHE_STORAGELOCATION=/tmp/real \
    go run -tags server ./cmd config get Cache.StorageLocation
cache.storagelocation: "/tmp/real"
# warning: ... The value from its replacement "Cache.StorageLocation" will be used instead ...

$ PELICAN_DEBUG=true go run -tags server ./cmd config get Logging.Level
logging.level: "debug"
# warning: The configuration key "Debug" is being deprecated ...
```

The 24 currently deprecated params (2026-07-05) — list them anytime with
`awk '/^name:/{n=$2} /^deprecated: true/{print n}' docs/parameters.yaml`:
Debug, IssuerKey, Logging.DisableProgressBars, DisableHttpProxy, DisableProxyFallback, MinimumDownloadSpeed, Origin.{ExportVolume, NamespacePrefix, EnableWrite, EnableFallbackRead, EnableDirListing, Mode, S3ServiceName}, Cache.{LocalRoot, DataLocation, DbLocation}, Director.{DbLocation, EnableStat}, Registry.{DbLocation, AdminUsers}, Server.TLSCertificate, Xrootd.{Port, RunLocation}, Lotman.DbLocation.

### Checklist: deprecating a param

1. Add `deprecated: true` and `replacedby: <new name or "none">` to its YAML block; prepend `[Deprecated]` guidance to the description (house pattern — see the `Debug` entry).
2. If the old param still needs a default for the migration window, move it into `SetServerDefaults`/`SetClientDefaults` by hand (category 1 of the guidance comment).
3. `go generate ./...` from repo root; commit YAML + regenerated trio together.
4. If value semantics differ between old and new (like Debug bool → level string), the generic copy in `handleDeprecatedConfig` won't work: add a special case there and document it with a YAML comment like Debug's.
5. Add/extend a test exercising the migration (pattern: env-var of old key, assert new key's value — see `config/` package tests).
6. **Never remove a deprecated param or change a shipped default without a deprecation cycle** — this is one of the four non-negotiables; rationale and history in **pelican-change-control**.

## 7. Hidden params, runtime_configurable, and what features/ is NOT

- **`hidden: true` is the experimental-flag convention** (58 params, 2026-07-05): hides the param from public docs while it bakes. Sharp-edged toggles (e.g. `Client.EnableOverwrites`, `Origin.TransferRateLimit`, `Cache.EnableChaosAPI`) live here. `pelican config get --include-hidden` reveals them.
- **`runtime_configurable: true`** (17 params, all `Logging.*`): declares that changing it should not require a full restart. Exposed as `param.X.IsRuntimeConfigurable()` and in the generated `parameters.json`. As of 2026-07-05 no non-test Go code consumes `IsRuntimeConfigurable` — treat it as intent metadata; actual hot-reload of logging goes through `logging/level_manager.go` and the XRootD-restart list in `logging/xrootd.go` (`xrootdOriginLoggingAccessors`).
- **`features/` is NOT feature flags.** It is inter-version capability negotiation (one feature today: `CacheAuthz`, NotBeforePelican v7.16) compiled from `features/resources/feature-version-compatibility.yaml`; the director uses it to filter caches by advertised version. See **pelican-architecture-contract**.

## 8. Dangerous params — in-file warnings, quoted

All quotes verbatim from `docs/parameters.yaml` descriptions (2026-07-05). Grep for more anytime: `grep -n -i 'WARNING\|sharp edge\|undefined behavior\|testing purposes' docs/parameters.yaml`.

| Param | The warning |
|---|---|
| `Client.EnableOverwrites` (hidden) | "WARNING: This is an extremely sharp edge. Careless use of overwrites could cause havoc for regular users." |
| `Cache.StorageLocation` | "The default value of /var/run/pelican should _never_ be used for production caches, as this directory is typically cleared on system restarts" (root default is `/run/pelican/cache` — tmpfs!). |
| `Cache.NamespaceLocation` | "`Cache.DataLocations` and `Cache.MetaLocations` are NOT [to be] subdirectories of `Cache.NamespaceLocation` … which is undefined behavior." (Same warning on DataLocations/MetaLocations.) |
| `Origin.DisableDirectClients` | "WARNING: This currently breaks the Origin's ability to receive PUT requests, as caches are not yet able to proxy writes." |
| `TLSSkipVerify` | "allows a 'man in the middle' attack on the connection … Intended for developers." **Never in fed tests** — test-discipline rule; see pelican-testing-and-qa. |
| `Debug` | Deprecated; "NOTE: this will override whatever is set within your configuration file under Logging.Level!" |
| `Client.PreferredCaches` | "*bypasses the Director and any of its potential logic for cache selection* … should only be used for testing or for preferring an on- or near-premises cache." (`+` must be last element or error.) |
| `Cache.EnablePrefetch` (hidden) | Disabling is "provided solely for testing purposes and is not advised … in production". |
| `Origin.TransferRateLimit` (hidden, the sole byterate) | "intended for testing purposes to simulate slow storage backends". |
| `Xrootd.ConfigFile` | "should only be used by admins" — full XRootD config override. |

## 9. ADD-A-PARAM checklist (verified against a real change)

Reference implementation: commit `e7548a18` ("CacheV2: give the cache its own transfer worker count", 2026-07-03) added `Cache.WorkerCount` and is the canonical shape — one commit touching `docs/parameters.yaml` (+12), `param/parameters.go` (+5), `param/parameters_struct.go` (+2), `config/parameter_defaults.go` (+2), the consuming code, and a test. Inspect it: `git show --stat e7548a18`.

1. **Write the YAML block** in `docs/parameters.yaml` under the right component section, `---`-separated. Required: `name`, `description` (`|+` block), `type` (from the 9-type enum), `default`, `components` (from the 9-component enum). Optional as needed: `root_default`/`osdf_default`/tier keys, `hidden: true` (new experimental params should usually start hidden), `runtime_configurable`.
   - Runtime-computed default? Use `default: "none"` and set it in Go (`SetServerDefaults` category 2, or compute at use-site guarded by `IsSet()`) — the seed-param pattern (parameters.yaml header lines ~27–42).
   - `type: object`? You must also add the name to `VERIFIED_OBJECT_STRUCTURES` in `.github/scripts/validate-parameters/main.py` (coordinate with web-UI owners) or CI fails.
2. **Generate** from repo root: `go generate ./...` (or `make generate`). No network needed. It panics with a precise message on any YAML mistake.
3. **Commit the generated trio together with the YAML**: `param/parameters.go`, `param/parameters_struct.go`, `config/parameter_defaults.go`. `check-go-generate` CI rejects the PR otherwise.
4. **Use `param.Component_Field.GetXxx()`** in code — never raw viper keys.
5. **Optionally run the validator locally.** DOCUMENTED DISCREPANCY: `AGENTS.md` (line ~382) says `make validate-parameters`, but **no such Makefile target exists** (`grep -i validate Makefile` → no matches; verified 2026-07-05). Run the script directly; it needs PyYAML and prints nothing on success:
   ```bash
   # repo root; verified 2026-07-05 (system python3 lacked yaml — use a venv):
   python3 -m venv /tmp/pv && /tmp/pv/bin/pip install -q -r .github/scripts/validate-parameters/requirements.txt
   /tmp/pv/bin/python3 .github/scripts/validate-parameters/main.py && echo OK
   ```
6. **Test.** Generator invariants are covered by `go test ./generate/` and `param/all_parameter_names_test.go`; add a behavior test for your param (env-override pattern: set `PELICAN_<NAME>` with `t.Setenv`, assert the getter — but follow the isolation idioms in **pelican-testing-and-qa**, especially `ResetTestState`).
7. Sanity-check end to end:
   ```bash
   go run -tags server ./cmd config describe Your.NewParam    # docs render
   PELICAN_YOUR_NEWPARAM=x go run -tags server ./cmd config get Your.NewParam
   ```

## Provenance and maintenance

All facts verified 2026-07-05 against `main@289fd41b`, by execution where an "Expected output"/"Verified" is shown, otherwise by direct source reading. Commands below are one-liners from the repo root to re-check every volatile fact.

| Volatile fact | Value (2026-07-05) | Re-verify with |
|---|---|---|
| Total param entries | 447 | `grep -c '^name:' docs/parameters.yaml` |
| Generated singletons match | 447 | `grep -cE '= (String\|StringSlice\|Int\|Bool\|Duration\|Object\|ByteRate\|Opaque)Param\{' param/parameters.go` |
| Field vocabulary counts | see §2 table | `grep -hoE '^[a-z_]+:' docs/parameters.yaml \| sort \| uniq -c \| sort -rn` |
| Type counts | see §2 table | `grep -E '^type: ' docs/parameters.yaml \| sort \| uniq -c` |
| Components/type enums | 9 + 9 values | `sed -n '1,40p' .github/scripts/validate-parameters/main.py` |
| `default: none` params | 90 | `grep -cE '^default: "?none"?\s*$' docs/parameters.yaml` |
| `${...}` default-tier interpolations | 45 (33 use `${ConfigBase}`) | `grep -cE '^(default\|root_default\|osdf_default\|client_default\|server_default): .*\$\{' docs/parameters.yaml` |
| hidden:true / runtime_configurable:true | 58 / 17 | `grep -c '^hidden: true' docs/parameters.yaml ; grep -c '^runtime_configurable: true' docs/parameters.yaml` |
| deprecated params | 24 | `awk '/^name:/{n=$2} /^deprecated: true/{print n}' docs/parameters.yaml \| wc -l` |
| Header comment span | lines 17–111 | `sed -n '17,111p' docs/parameters.yaml \| head` |
| Generator order (7 generators) | see §3 | `sed -n '27,35p' generate/main.go` |
| Committed generated files | 6 Go files + CLI MDX | `git ls-files param/parameters.go param/parameters_struct.go config/parameter_defaults.go token_scopes/token_scopes.go error_codes/error_codes.go features/features.go` |
| Gitignored artifacts | 3 | `sed -n '1,8p' .gitignore` |
| `parameters.json` fresh vs YAML (after `make generate`) | counts equal | `test $(jq length docs/parameters.json) -eq $(grep -c '^name:' docs/parameters.yaml) && echo fresh` |
| `make generate` behavior | pre-touches JSONs | `sed -n '60,80p' Makefile` |
| check-go-generate enforcement | diff-fail | `cat .github/workflows/check-go-generate.yml` |
| AGENTS.md discrepancy | `make validate-parameters` nonexistent | `grep -n 'validate-parameters' AGENTS.md Makefile` |
| validate-defaults vestigial | `config/resources/` gone | `ls config/resources` (fails) |
| Deprecated hand-set defaults anchor | `SetServerDefaults` | `grep -n 'Deprecated param defaults' config/config.go` |
| SourceTracker types (5) | see §5 | `sed -n '30,45p' config/source_tracker.go` |
| `pelican config` subcommands | dump/get/describe/summary | `go run -tags server ./cmd config --help` |
| Stale-snapshot trap demo | output in §4 | rerun the §4 demo script |
| Deprecation demos | output in §6 | rerun the §6 one-liners |
| Reference add-a-param commit | `e7548a18` | `git show --stat e7548a18` |
| Features (not flags) | 1 feature: CacheAuthz | `grep -v '^#' features/resources/feature-version-compatibility.yaml \| head` |
