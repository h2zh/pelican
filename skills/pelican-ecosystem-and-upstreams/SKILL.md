---
name: pelican-ecosystem-and-upstreams
description: The external world map for the Pelican repo. Load when you need to decide WHERE to file a bug or make a change outside github.com/PelicanPlatform/pelican — e.g. a C++ stack trace in XrdPfc/XrdHttp/cmsd, a cache pulling wrong or stale data, "Failed to deserialize SciToken", a missing RPM in OSG yum repos, a docs-site rendering bug, questions about the PelicanPlatform/xrootd fork and its vX.Y.Z-pelican patch branches, OSDF/stashcp/osdf-compat/Topology legacy integration, MaxMind/CILogon/OA4MP external dependencies, WLCG/SciTokens/RFC 3230 spec URLs, or before claiming "Pelican supports X". Contains the repo constellation table, version-pin locations, a where-to-file decision table grounded in real incidents, and the external-claim evidence bar.
---

# Pelican Ecosystem and Upstreams

Pelican is one repo in a constellation. The Go code in `PelicanPlatform/pelican`
is a control plane and client; the data plane is XRootD (a C++ file server
suite) plus C/C++ plugins living in other repos, deployed on infrastructure
(OSG yum repos, Harbor, Topology) that other teams own. Fixing a symptom often
means filing or patching **somewhere else**. This skill is the map.

## When to use this skill

- You have a crash/stack trace naming `XrdPfc`, `XrdHttp`, `XrdPss`, `cmsd`,
  `libXrd*.so`, `std::length_error`, SIGABRT/SIGSEGV in a non-Go frame.
- A cache serves wrong, stale, or truncated data and you must decide:
  director bug (this repo) vs `xrdcl-pelican` bug (another repo).
- Token auth fails at an origin/cache ("Failed to deserialize SciToken",
  "Unknown error") and you must split pelican's `scitokens.cfg` generation
  from the `scitokens-cpp` library.
- A container build fails on `dnf install` / a pinned RPM version vanished
  from `osg-testing` / you see release strings like `1.1.osg25.el9`.
- You are asked to bump `XROOTD_VER`, `XRDCL_PELICAN_VER`, or any pin in
  `images/Dockerfile` or `github_scripts/osx_install.sh` and need to know
  what those repos are and how bumps are qualified.
- Anything involving `osdf://`, `stashcp`, `stash_plugin`, `pelican-osdf-compat`,
  Topology (`topology.opensciencegrid.org`), CILogon login, MaxMind GeoLite2,
  or the embedded OA4MP Java issuer.
- You need the canonical URL for WLCG JWT profile, SciTokens, RFC 3230,
  or OpenID discovery, or you're about to claim "Pelican is compatible with X".

### When NOT to use

- XRootD bump **policy**, backport/release-train mechanics, PR gates →
  `pelican-change-control`.
- Toolchain versions, goreleaser mechanics, how to build the containers →
  `pelican-build-and-env`.
- What a token profile / discovery endpoint / broker actually *is* →
  `pelican-federation-domain-reference`.
- The incident *stories* behind the examples cited here (full chronology) →
  `pelican-failure-archaeology`.
- Docs house style and codegen checklists → `pelican-docs-and-writing`.
- Triage of a live failure where you don't yet know the component →
  `pelican-debugging-playbook` first; come back here once the trail leaves
  this repo.

## 1. The repo constellation

All repos verified to exist 2026-07-05 via `gh repo view <org>/<repo>`.
"Pin (2026-07-05)" = value on `main@289fd41b`; release branches may differ
(v7.25.x pins XRootD 5.9.1, main pins 5.9.2 — see `pelican-failure-archaeology`).

| Repo | What it is | Pin + where | When a Pelican engineer touches it |
|---|---|---|---|
| `PelicanPlatform/pelican` | This repo: Go control plane (director, registry, web UI, launchers, config gen) + client | — | Default home for everything not listed below |
| `PelicanPlatform/docs` | Nextra static site for the docs website; **submodules this repo** (path `pelican`, branch `main` in its `.gitmodules`) and copies `docs/app` + `docs/public` out of it via its `scripts/setup.mjs` | — | Site build/rendering/nav bugs only; page *content* lives HERE in `docs/app` (see §2 row 5) |
| `PelicanPlatform/xrootd` | Fork of `xrootd/xrootd` carrying Pelican's patch series ahead of upstream releases (see §1.2) | Branch `v5.9.2-pelican` built from source by `github_scripts/osx_install.sh` (macOS CI only) | Adding/rebasing a patch XRootD upstream hasn't shipped yet |
| `PelicanPlatform/xrdcl-pelican` | XrdCl client plugin (`libXrdClPelican.so`, `libXrdN2NPrefix.so`): how a cache fetches from the federation — the cache's upstream is `pss.origin pelican://<federation>` resolved through this plugin | `XRDCL_PELICAN_VER=1.7.1` in `images/Dockerfile` (RPM install, `SRC_BUILD=false`); `--branch v1.7.1` in `osx_install.sh` | Cache→origin transfer bugs: redirects, retries, timeouts, header handling (see §2 row 2) |
| `PelicanPlatform/xrdhttp-pelican` | XrdHttp plugin (`libXrdHttpPelican.so`): Pelican↔XRootD control surface (e.g. authfile/scitokens.cfg "transplant" when unprivileged) | `XRDHTTP_PELICAN_VER=0.0.11` both places | Bugs in the in-process control channel between pelican and xrootd |
| `PelicanPlatform/xrootd-s3-http` | Storage-backend plugins: `libXrdS3`, `libXrdOssHttp`, `libXrdOssGlobus`, `libXrdOssPosc`, `libXrdHTTPServer`, `libXrdOssFilter` | `XROOTD_S3_HTTP_VER=0.6.7`, **`SRC_BUILD=true`** (built from source tag `v0.6.7` in the container) | S3/HTTP/Globus origin backend bugs (e.g. its issue #146 "PROPFIND broken on S3 backed Origin") |
| `opensciencegrid/xrootd-multiuser` | **Note the org.** `libXrdMultiuser.so`: lets XRootD write as the requesting Unix user | `XROOTD_MULTIUSER_VER=2.2.1` (RPM install) | Multiuser-origin permission/segfault bugs |
| `PelicanPlatform/lotman` | LotMan C++ library — "lots" = storage-quota groups for caches | `LOTMAN_VER=0.1.0`, `SRC_BUILD=true` | Lot accounting/policy bugs |
| `PelicanPlatform/xrootd-lotman` | XRootD cache-purge plugin (`libXrdPurgeLotMan.so`) driving purge from LotMan policy | `XROOTD_LOTMAN_VER=0.1.0`, `SRC_BUILD=true` | Cache purge-order/purge-crash bugs when Lotman enabled |
| `PelicanPlatform/classad` | Go ClassAd-language parser | `go.mod`: `github.com/PelicanPlatform/classad v0.0.5` | HTCondor plugin ClassAd parse/emit bugs |
| `scitokens/scitokens-cpp` | C++ SciTokens/WLCG token validation library loaded by XRootD (`libXrdAccSciTokens.so`) | macOS CI builds `v1.4.1` (`osx_install.sh`); Linux gets it via XRootD RPM deps | Token-validation library bugs (see §2 row 3) |
| `xrootd/xrootd` | The real upstream XRootD (home: xrootd.slac.stanford.edu) | Installed as OSG RPMs: `XROOTD_VER=5.9.2`, `XROOTD_RELEASE="1.1.osg${OSG_SERIES}.${BASE_OS}"` in `images/Dockerfile` | Any XRootD bug not caused by a fork patch (see §2 row 1) |
| `opensciencegrid/topology` | Data behind topology.opensciencegrid.org (legacy OSDF site/resource registry) | — | Fixing OSDF resource/downtime *data*, not code (see §4.4) |
| `opensciencegrid/xrootd-monitoring-shoveler` | Monitoring-message shoveler embedded in pelican's `metrics/` | `go.mod`: `v1.3.0` | Shoveler forwarding bugs |
| `htcondor/htcondor` | HTCondor itself (file-transfer plugin *caller*) | — | Only if the plugin protocol itself misbehaves on the Condor side |

### 1.1 Version-pin sync rules (the trap)

Three places must be kept in sync **by hand** — the comment above
`XRDCL_PELICAN_SRC_BUILD` in `images/Dockerfile` says so explicitly:

1. `images/Dockerfile` — `ARG *_VER` / `*_RELEASE` / `*_SRC_BUILD` block
   (around the `LOTMAN_SRC_BUILD` ARG) plus `ARG XROOTD_VER` in the
   `xrootd-software-init` stage.
2. `github_scripts/osx_install.sh` — macOS CI clones and builds the same
   components from source at pinned tags/branches.
3. `xrootd/version.go` — `MinXrootdVersion = "5.8.2"` (runtime-enforced via
   `xrootd -v`), mirrored by the `pelican-server` RPM dependency
   `xrootd-server >= 1:5.8.2` in `.goreleaser.in.yml`.

Historical failure: commit `57e3bb82` reverted xrootd-s3-http to v0.6.1 in
`osx_install.sh` but to 0.6.0 in the Dockerfile — a real desync. Never bump
one location without grepping the other two. Bump *policy* (whether you may
bump at all): `pelican-change-control`.

### 1.2 The PelicanPlatform/xrootd fork: branches, not tags

- The patch lines are **branches** named `vX.Y.Z-pelican` (`v5.7.2-pelican`
  … `v6.1.0-pelican` as of 2026-07-05). There are **no** `-pelican` tags —
  verify with:

  ```
  # anywhere
  git ls-remote --heads https://github.com/PelicanPlatform/xrootd.git | grep pelican
  ```

  Expected output: lines ending in `refs/heads/v5.9.2-pelican` etc.
  (`osx_install.sh` does `git checkout v5.9.2-pelican`, which resolves the
  remote branch.)

- Each branch = the upstream tag + a rebased patch series. As of 2026-07-05,
  `v5.9.2-pelican` is 8 commits ahead / 0 behind `v5.9.2`; patches include
  hostname env-var override, multi-token XrdSciTokens setups, PROPFIND
  resourcetype, cache write-through mode, S3 proxy protocol, TPC worker
  pool, PKCS#11 integration. Inspect the live series with:

  ```
  # anywhere
  gh api 'repos/PelicanPlatform/xrootd/compare/v5.9.2...v5.9.2-pelican' \
    --jq '{ahead: .ahead_by, behind: .behind_by, commits: [.commits[].commit.message | split("\n")[0]]}'
  ```

- Patch commits are titled `[#N] …` where `#N` is a **fork** issue; each
  upstream release gets a rebase issue (e.g. fork issue #53 "Update patches
  for XRootD 5.9.6"). The fork's issue tracker is active — use it.

- Who consumes what: **macOS CI** builds the fork branch from source
  (`osx_install.sh`). **Linux containers** install OSG-built XRootD RPMs
  pinned from `osg-testing` (§3.2). Whether a given OSG RPM build includes
  the fork patch series is **not visible in this repo** — commit `2e2004ea`
  ("Install custom XRootD directly from Kojihub RPMs … while we wait for
  certain riskier patches to be ingested upstream (either by XRootD itself
  or by the OSG repos)") implies OSG sometimes ingests them, but the
  mechanism is OPEN (ask the OSG software team).

### 1.3 Mapping a crashing `.so` to its repo

`pluginPackageMap` in `xrootd/plugin_check.go` is the authoritative in-repo
map from plugin library basename → providing package. Summary of its keys (the
repo also ships libraries that are NOT map keys — e.g. `libXrdOssHttp`,
`libXrdOssFilter` — listed in the §1 constellation table):

| Library in stack trace | Package | Repo |
|---|---|---|
| `libXrdClPelican`, `libXrdN2NPrefix` | xrdcl-pelican | PelicanPlatform/xrdcl-pelican |
| `libXrdHttpPelican` | xrdhttp-pelican | PelicanPlatform/xrdhttp-pelican |
| `libXrdS3`, `libXrdOssGlobus`, `libXrdOssPosc`, `libXrdHTTPServer` | xrootd-s3-http | PelicanPlatform/xrootd-s3-http |
| `libXrdMultiuser` | xrootd-multiuser | opensciencegrid/xrootd-multiuser |
| `libXrdPurgeLotMan` | xrootd-lotman | PelicanPlatform/xrootd-lotman |
| `libXrdThrottle`, `libXrdMacaroons`, anything `XrdPfc`/`XrdHttp`/`XrdPss`/`cmsd` | xrootd-server-libs | xrootd/xrootd (or the fork, §2 row 1) |
| `libXrdAccSciTokens` | xrootd-scitokens | scitokens/scitokens-cpp |

## 2. Where to file: decision table

| # | Symptom | File at | How to decide | Grounding (real history) |
|---|---|---|---|---|
| 1 | Crash/abort with C++ frames in `XrdPfc`, `XrdHttp`, `cmsd`, `XrdOss` | `xrootd/xrootd` upstream — unless the bug is in a fork patch or you need a fix shipped before the next upstream release, then `PelicanPlatform/xrootd` fork issue + patch on the `vX.Y.Z-pelican` branch | Diff the crashing function against the fork patch series (§1.2 compare command). Untouched by patches → upstream. Pelican-side only if the crash is at startup from a bad *generated* config (`xrootd/` package here) | `xrootd/xrootd#2808` — `std::length_error` in `ResourceMonitor::perform_purge_check()`, filed upstream by a Pelican dev from a Pelican cache's captured stack trace (XRootD 5.9.5). Same failure class as the `XrdPfc::File::ReadOpusCoalescere` abort documented in v7.25.x commit `fe785866` that drove the 5.9.x downgrade ladder |
| 2 | Cache pulls wrong/stale/truncated data, bad redirects on cache→origin fetch | Split: *selection* (which server was chosen, dead-server redirect) → director, **this repo**; *transfer* (wrong bytes/headers/URL resolution once the server is chosen) → `PelicanPlatform/xrdcl-pelican` | The cache's upstream is the whole federation via `pss.origin pelican://…` resolved by `libXrdClPelican` — anything after the director handed back a URL is plugin territory. Reproduce with `pelican object get` (client path, this repo) vs through a cache (plugin path) | `xrdcl-pelican#116` (host-relative redirect `Location` resolved against the wrong URL); `xrdcl-pelican#103` fixed a directory-listing bug, then pelican PR #3217 bumped the pin AND un-skipped `TestCacheProxyDirectoryListing` (`e2e_fed_tests/posixv2_test.go`) that had been skip-guarded on that release |
| 3 | Origin/cache rejects a token that validates fine elsewhere | Split: generated `scitokens.cfg` wrong/missing issuer → **this repo** (`xrootd/authorization.go` generates it); config correct but intermittent "Failed to deserialize SciToken: Unknown error" → `scitokens/scitokens-cpp` | First read the rendered `scitokens.cfg` in the xrootd run dir and check the `[Issuer …]` sections; deterministic-miss = generation bug here, intermittent-under-load = library | Commit `4ccd3c73` (2026-07-04): root cause was a SQLite rollback-journal race inside scitokens-cpp v1.4.1's JWKS keycache; pelican shipped a workaround (pre-flip WAL before xrootd starts, in `xrootd/xrootd_config.go`) rather than waiting on the library |
| 4 | Container build fails on `dnf install`; pinned RPM version gone; repo 404 | **OSG software team — outside GitHub.** The yum repos (`osg-testing`, `osg-development`, `osg-contrib`, …) are documented at https://osg-htc.org/docs/common/yum/ and owned by OSG packaging | If `dnf` can't find `xrootd-5.9.2-1.1.osg25.el9`, the package moved or was pulled from `osg-testing` — nothing in this repo can fix that; adjust the pin or the `--enablerepo` list and coordinate with OSG | `e497639b` removed `osg-upcoming` ("changes in upstream build targets … preventing container builds"); `0e982404` reverted an earlier removal of `osg-development` after builds broke. The repo list changes underneath you |
| 5 | Docs website mis-renders, bad nav, params page wrong | `PelicanPlatform/docs` for *site machinery*; **this repo** (`docs/app/`) for page *content* | The docs repo submodules pelican and copies `docs/app` + `docs/public` at build time — if the Markdown is wrong, fix it here; if correct Markdown renders wrong, it's the site | docs repo issue #45 "Params page does not hide 'hidden' knobs" (site); content moved `docs/pages` → `docs/app` in `10e8f36b` (2025-06-12) — the docs repo README still says `docs/pages`, a **documented stale reference**. See `pelican-docs-and-writing` |
| 6 | Everything else: client, director, registry, config, web UI, launchers | `PelicanPlatform/pelican` | Always pass `-R PelicanPlatform/pelican` to `gh` — `origin` on dev checkouts is often a personal fork | PR gates (mandatory label + linked issue): see `pelican-change-control` |

## 3. OSG infrastructure

### 3.1 Harbor container registry

Release and dev images are pushed by `.github/workflows/build-and-test.yml`
to **`hub.opensciencegrid.org/pelican_platform`** using the
`PELICAN_HARBOR_ROBOT_USER`/`PELICAN_HARBOR_ROBOT_PASSWORD` secrets. Push
rules (workflow header comment): PRs never push; pushes to `main` push only
`pelican-dev`/`pelican-test`; semver tags push all release images —
`client, cache, director, origin, registry, osdf-{cache,director,origin,registry},
pelican-dev, pelican-test`. Policy for what may be tagged/pushed:
`pelican-change-control`.

### 3.2 OSG yum repos (the repo list is owned by OSG, not you)

- Containers install OSG's release RPM from
  `https://repo.osg-htc.org/osg/${OSG_SERIES}-main/osg-${OSG_SERIES}-main-${BASE_OS}-release-latest.rpm`
  with `OSG_SERIES=25`, `BASE_OS=el9` (Dockerfile ARGs, 2026-07-05).
- XRootD is installed **pinned** (`name-VER-RELEASE`) with
  `--enablerepo=osg-testing`, then `dnf versionlock "xrootd*"` freezes it.
  Rationale (commit `c2dd8f0e`): osg-testing packages "have at least gone
  through the OSG VMU smoke tests".
- Source-build toolchain deps come from `osg-contrib`; plugin RPM fallback
  installs enable `epel-testing` + `osg-development` + `osg-testing`.
- History shows this list churns under external pressure (§2 row 4).

### 3.3 What is honestly NOT in this repo

- **Koji / RPM distribution.** `grep -rn koji` over docs/workflows finds
  nothing current; only git history (`2e2004ea`) shows a past direct-Kojihub
  phase. How pelican RPMs reach OSG yum repos, who submits koji builds, and
  who picks the `XROOTD_RELEASE` numbers is invisible here — OPEN, ask OSG.
- **`XROOTD_RELEASE` strings** like `1.1.osg25.el9` (pattern
  `N.M.osg<series>.el<Y>`) are OSG build release numbers. This repo only
  *selects* one in the Dockerfile ARG; it never generates them.
- Whether OSG's XRootD builds carry the `PelicanPlatform/xrootd` patch
  series: UNVERIFIED from this repo (§1.2).

## 4. OSDF specifics

OSDF = Open Science Data Federation, the flagship deployment
(see `pelican-federation-domain-reference` for domain terms).

### 4.1 Hard-coded discovery

`osdf://` and `stash://` URLs always discover the federation from
**`osg-htc.org`** — constant `OsdfDiscoveryHost` in `pelican_url/discovery.go`.
Consequence for tests: never let a unit test hit the live OSDF; the `mock`
package (`mock/mockups.go`) serves canned discovery JSON
(`osdf-director.osg-htc.org` etc.) and an embedded
`resources/topology-namespace.json`.

### 4.2 The `osdf_default` parameter tier

`docs/parameters.yaml` supports per-mode defaults with precedence
(header comment, ~lines 80-99):

```
client_default / server_default  >  osdf_default  >  root_default  >  default
```

OSDF mode is activated by **binary name**: `GetPreferredPrefix` in
`config/config.go` returns the OSDF prefix when `argv[0]` (uppercased)
starts with `OSDF` or `STASH`. That's the whole mechanism behind the
`osdf-*` container images — e.g. the `osdf-director` stage in
`images/Dockerfile` is just `FROM director` plus
`ln -s pelican-server /usr/local/sbin/osdf-server` and an entrypoint that
execs `osdf-server`. Example osdf_defaults: `Federation.DiscoveryUrl` →
`https://osg-htc.org`; the three Topology URLs below. Param mechanics:
`pelican-config-and-flags`.

### 4.3 Binary renames and the HTCondor plugin

Project lineage: **stashcp → osdf → pelican** (comment on `GetAllPrefixes`
in `config/config.go`; the first Go stashcp commit is `ca50faed`,
2021-03-18). Compatibility is shipped as the **`pelican-osdf-compat`** meta
package (`.goreleaser.in.yml`, id `pelican-osdf-compat`):

- Symlinks: `/usr/bin/osdf`, `/usr/bin/stashcp` → `pelican`;
  `/usr/libexec/condor/stash_plugin` → the pelican binary.
- RPM `provides`/`replaces`: `stashcache-client`, `osdf-client`, `stashcp`,
  `condor-stash-plugin` (`< 7`).
- Installs `/etc/condor/config.d/10-stash-plugin.conf` (source:
  `client/resources/10-stash-plugin.conf`) which sets
  `STASH_PLUGIN = $(LIBEXEC)/stash_plugin` and appends it to
  `FILETRANSFER_PLUGINS`.
- Postinstall `scripts/postinstall-plugin.sh` runs `condor_reconfig` if a
  `condor_startd` is running.

Invocation-name dispatch lives in `cliDispatchHook` in `cmd/main_client.go`
(client build tag): names starting `stash_plugin`/`osdf_plugin`/
`pelican_xfer_plugin`/`pelican_plugin` run the HTCSS file-transfer plugin
(`stashPluginMain`, `cmd/plugin.go` — emits result ClassAds with
`TransferSuccess`/`TransferError`/`TransferRetryable`); a name starting
`stashcp` runs the copy command. `pelican plugin stage`
(`cmd/plugin_stage.go`) parses `TransferInput` from a job ClassAd on stdin.
ClassAd parsing uses `github.com/PelicanPlatform/classad`.

### 4.4 Topology: the legacy OSDF integration

Topology (`topology.opensciencegrid.org`, data repo
`opensciencegrid/topology`) predates the Pelican registry and is still live
in OSDF mode:

| Endpoint (param, all `osdf_default`) | Used for | Consumer code |
|---|---|---|
| `Federation.TopologyUrl` = `https://topology.opensciencegrid.org`, fetched at `/<cache|origin>/Authfile?fqdn=<Server.Hostname>` | Extra authfile entries merged with generated ones | `xrootd/authorization.go` |
| `Federation.TopologyNamespaceUrl` = `…/osdf/namespaces?production=1` | Legacy namespace ads for director + registry collision checks | `director/`, `registry/registry_db.go` |
| `Federation.TopologyDowntimeUrl` = `…/rgdowntime/xml` | Downtime aggregation in the director | `director/` |

Behavioral consequences, verified in code:

- Server ads carry a `FromTopology` flag (`server_structs/director.go`).
  In `getAdsForPath` (`director/sort.go`), a Pelican-registered origin
  **replaces** a topology-sourced origin for the same namespace prefix, and
  topology-only caches are excluded from serving non-public namespaces.
- Registering a prefix that collides with a topology super/subspace requires
  identity info and registry-admin approval (`registry/registry.go`).
- Opt-outs exist: `Topology.DisableDowntime`, `Topology.DisableCacheX509`,
  `Topology.DisableOriginX509` (docs/parameters.yaml).
- **Sunset date: OPEN.** The params are labeled "a legacy integration" but
  nothing in the repo schedules removal; which deployments still depend on
  the Topology endpoints is a question for OSG/OSDF operations.

## 5. Standards bodies and specs (canonical URLs)

| Spec | Canonical URL | Where Pelican implements it |
|---|---|---|
| WLCG Common JWT Profile | https://github.com/WLCG-AuthZ-WG/common-jwt-profile/blob/master/profile.md | `wlcg` token profile in `token/token_create.go`; any-audience `https://wlcg.cern.ch/jwt/v1/any`; referenced in AGENTS.md and `cmd/origin.go` |
| SciTokens | https://scitokens.org/technical_docs/Claims and https://scitokens.org/technical_docs/Verification | `scitokens2` profile (`ver` = `scitokens:2.x`, audience literal `ANY`); cited in `cmd/origin.go`, `client/acquire_token.go` |
| RFC 3230 (HTTP instance digests) | https://datatracker.ietf.org/doc/html/rfc3230 | Checksums via `Want-Digest`/`Digest` headers: `wantDigestValue` / `parseDigestHeader` in `client/handle_http.go`. (RFC 3230 was obsoleted by RFC 9530; Pelican and XRootD speak the 3230 style — don't "modernize" it unilaterally, it's a wire format) |
| OpenID Connect Discovery | https://openid.net/specs/openid-connect-discovery-1_0.html | `GetIssuerMetadata` in `config/issuer_metadata.go` appends `/.well-known/openid-configuration`; the director serves its own (`director/discovery.go`) |
| HTCondor file-transfer plugin protocol | https://htcondor.readthedocs.io (HTCondor manual); source github.com/htcondor/htcondor | §4.3: `cmd/plugin.go`, `cmd/plugin_stage.go`, `client/resources/10-stash-plugin.conf` |

Token/profile semantics and Pelican's own
`/.well-known/pelican-configuration` discovery: see
`pelican-federation-domain-reference`.

## 6. Other external dependencies

### 6.1 MaxMind GeoLite2 (director geo-sorting)

- `downloadDB` in `director/maxmind.go` fetches the GeoLite2-City DB from
  `download.maxmind.com` using a license key read from the file at
  `Director.MaxMindKeyFile`; DB lands at `Director.GeoIPLocation`
  (root_default `/var/cache/pelican/maxmind/GeoLite2-City.mmdb`).
- GeoLite2 requires a (free) MaxMind account + license key under MaxMind's
  license — the key is an operator-supplied external credential, never
  committed. Param description links
  https://dev.maxmind.com/geoip/docs/databases/city-and-country.
- Without a key the director still runs but geo-sort degrades: unresolvable
  client IPs are assigned a random coordinate inside a contiguous-US
  bounding box, cached ~20 min (`director/sort_utilities.go`). Full
  geo-redirection semantics: see `pelican-federation-domain-reference`.

### 6.2 CILogon (registry web-login OAuth)

- The registry's OIDC login defaults to CILogon endpoints —
  `config/parameter_defaults.go` sets `https://cilogon.org/authorize`,
  `/oauth2/token`, `/oauth2/userinfo`, `/oauth2/device_authorization`,
  issuer `https://cilogon.org`.
- Operators must register an OIDC client at
  https://cilogon.org/oauth2/register and supply
  `OIDC.ClientID(File)`/`OIDC.ClientSecretFile` (see the `OIDC.ClientIDFile`
  description in `docs/parameters.yaml`). Other providers work by overriding
  the endpoint params — except Globus, which the registry explicitly rejects
  (`web_ui/oauth2_client.go`).

### 6.3 OA4MP (embedded Java token issuer)

- Origins can embed the OA4MP issuer (https://oa4mp.org) run under Tomcat;
  pins in `images/Dockerfile` (2026-07-05): `OA4MP_VER=6.2.3`,
  `TOMCAT_VER=9.0.115`, `JAVA_VER=17`.
- Config templates track upstream via `.upstream` sibling files —
  `oa4mp/resources/oa4mp-config/{web.xml,cfg.xml}` +
  `tomcat-config/server.xml`, each with a `*.upstream` snapshot of the
  version they were derived from. **Upgrade procedure is documented in
  `oa4mp/resources/README.md`**: bump Dockerfile versions → build the
  `origin` image → copy the three shipped configs out of the container over
  the `.upstream` files → `git diff` each `.upstream` → port the delta into
  the template. Follow it; don't hand-edit templates blind.

## 7. External-claim discipline

Before writing "Pelican supports X" / "compatible with XRootD X.Y" anywhere
(docs, release notes, issue replies), meet this evidence bar:

1. **An e2e test in this repo** exercising the claim (`e2e_fed_tests/`,
   31 test files as of 2026-07-05), or
2. **A documented soak** in a production federation.

The XRootD 5.9.x history shows why the bar is layered — each pin bump is a
compatibility claim qualified as:

- **osg-testing** membership = passed OSG VMU smoke tests (`c2dd8f0e`);
- **CI**: container builds + e2e suites on the pinned version;
- **production canary**: real federation caches/origins.

And even that can fail late: XRootD 5.9.2 passed the first two layers yet
core-dumped the UWDF production cache (~27 restarts/5 days; v7.25.x commit
`fe785866`), forcing the downgrade ladder 5.9.5→5.9.3→5.9.2→5.9.1 on the
release branch; separately, PR #3497 reverted 5.9.5 on main ("We've
discovered issues with 5.9.5 and removed it from the osg-testing repos"). Corollary: **never casually bump XRootD or plugin pins**
(rule owner: `pelican-change-control`).

Working patterns to copy:

- **Fix upstream, then bump + prove**: PR #3217 bumped xrdcl-pelican to the
  release containing the fix (xrdcl-pelican#103) and un-skipped the e2e test
  that had been skip-guarded on exactly that release, in the same PR.
- **Bump with a named bug**: PR #3531 (xrdcl-pelican 1.7.1) states the
  specific bug fixed and carries `create-patch` for backporting.
- Anything weaker than the bar: label it **experimental** — the release
  train has a channel for that (`v7.27.0-experimental.N` tags exist).

When the claim is about release mechanics, see `pelican-change-control`;
about build reproduction, see `pelican-build-and-env`.

## Provenance and maintenance

All facts verified 2026-07-05 against `main@289fd41b` of
PelicanPlatform/pelican, plus read-only `gh` queries against the live
GitHub orgs the same day. Version pins, repo lists, and OSG repo names are
volatile; re-verify before acting:

| Volatile fact | Re-verification command (run at repo root) |
|---|---|
| XRootD + plugin pins in containers | `grep -n 'ARG XROOTD_VER\|ARG .*_VER=' images/Dockerfile` |
| macOS CI source pins (fork branch, scitokens-cpp, plugins) | `grep -n 'git checkout v\|--branch v' github_scripts/osx_install.sh` |
| Minimum runtime XRootD version | `grep -n 'MinXrootdVersion' xrootd/version.go` |
| Fork patch branches exist (branches, not tags) | `git ls-remote --heads https://github.com/PelicanPlatform/xrootd.git \| grep pelican` |
| Fork patch series contents | `gh api 'repos/PelicanPlatform/xrootd/compare/v5.9.2...v5.9.2-pelican' --jq '.ahead_by'` |
| Each constellation repo still exists / org unchanged | `gh repo view opensciencegrid/xrootd-multiuser --json owner --jq .owner.login` (repeat per repo) |
| docs repo still submodules pelican | `gh api repos/PelicanPlatform/docs/contents/.gitmodules --jq .content \| base64 -d` |
| `.so` → package map | `grep -n -A15 'pluginPackageMap = map' xrootd/plugin_check.go` |
| Hard-coded OSDF discovery host | `grep -n 'OsdfDiscoveryHost' pelican_url/discovery.go` |
| osdf_default tier + precedence | `sed -n '80,100p' docs/parameters.yaml` |
| Topology params + osdf_defaults | `grep -n -B2 -A6 'name: Federation.Topology' docs/parameters.yaml` |
| osdf-compat package contents | `grep -n -A20 'id: pelican-osdf-compat' .goreleaser.in.yml` |
| Binary-name dispatch list | `sed -n '25,40p' cmd/main_client.go` |
| Harbor registry + push rules | `sed -n '1,30p' .github/workflows/build-and-test.yml && grep -n 'hub.opensciencegrid.org' .github/workflows/build-and-test.yml` |
| OSG yum repo bootstrap + series | `grep -n 'repo.osg-htc.org\|OSG_SERIES=' images/Dockerfile` |
| CILogon default endpoints | `grep -n 'cilogon.org' config/parameter_defaults.go` |
| MaxMind download URL + key param | `grep -n 'download.maxmind.com\|MaxMindKeyFile' director/maxmind.go` |
| OA4MP/Tomcat/Java pins | `grep -n 'OA4MP_VER\|TOMCAT_VER\|JAVA_VER' images/Dockerfile` |
| OA4MP `.upstream` convention intact | `ls oa4mp/resources/oa4mp-config/ oa4mp/resources/tomcat-config/` |
| Go-module external deps (classad, shoveler, jwx) | `grep -n 'PelicanPlatform/classad\|xrootd-monitoring-shoveler\|lestrrat-go/jwx' go.mod` |
| e2e test file count | `ls e2e_fed_tests/*.go \| wc -l` |
| Experimental release channel still in use | `git tag -l '*experimental*' \| tail -3` |

Open questions carried in this skill: OSG koji/RPM submission mechanics and
`XROOTD_RELEASE` numbering ownership (§3.3); whether OSG XRootD builds carry
the fork patch series (§1.2); Topology sunset plan (§4.4).
