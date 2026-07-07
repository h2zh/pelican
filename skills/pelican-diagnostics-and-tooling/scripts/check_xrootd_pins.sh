#!/usr/bin/env bash
# check_xrootd_pins.sh — report every place the XRootD stack version is pinned and flag drift.
#
# Usage: ./check_xrootd_pins.sh          (run from the pelican repo root)
#
# Read-only: greps four files, prints a table, exits 1 if any cross-file
# mismatch is detected, 0 otherwise.
#
# Pins compared:
#   images/Dockerfile            ARG XROOTD_VER / XRDCL_PELICAN_VER / XRDHTTP_PELICAN_VER
#                                (Linux container images; installed from OSG RPMs)
#   github_scripts/osx_install.sh  git checkout tags for the same components
#                                (macOS CI; built from source — must match by hand)
#   xrootd/version.go            MinXrootdVersion (runtime floor enforced at startup)
#   .goreleaser.in.yml           RPM dependency floor "xrootd-server >= 1:X.Y.Z"
#
# Interpretation:
#   - Dockerfile vs osx_install.sh mismatch: macOS CI tests a different XRootD
#     than Linux CI/production. This is exactly the drift the Dockerfile comment
#     warns about ("If you update this version, you must also update ...").
#   - version.go vs .goreleaser.in.yml mismatch: the RPM will install on hosts
#     the binary refuses to run against (or vice versa). The .goreleaser.in.yml
#     comment says to keep them in sync.
#   - MinXrootdVersion is a FLOOR; it is expected to be <= the pinned build
#     version. Do not "fix" that difference.

set -u
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 2

fail=0
val() { [ -n "$1" ] && echo "$1" || echo "<NOT FOUND>"; }

# --- images/Dockerfile ---
DOCKER_XROOTD=$(sed -n 's/^ARG XROOTD_VER="\([^"]*\)".*/\1/p' images/Dockerfile | head -1)
DOCKER_XRDCL=$(sed -n 's/^ARG XRDCL_PELICAN_VER=\(.*\)/\1/p' images/Dockerfile | head -1)
DOCKER_XRDHTTP=$(sed -n 's/^ARG XRDHTTP_PELICAN_VER=\(.*\)/\1/p' images/Dockerfile | head -1)
DOCKER_S3HTTP=$(sed -n 's/^ARG XROOTD_S3_HTTP_VER=\(.*\)/\1/p' images/Dockerfile | head -1)
DOCKER_LOTMAN=$(sed -n 's/^ARG XROOTD_LOTMAN_VER=\(.*\)/\1/p' images/Dockerfile | head -1)
DOCKER_MULTIUSER=$(sed -n 's/^ARG XROOTD_MULTIUSER_VER=\(.*\)/\1/p' images/Dockerfile | head -1)

# --- github_scripts/osx_install.sh (source-build tags) ---
OSX_XROOTD_TAG=$(grep -A3 'PelicanPlatform/xrootd.git' github_scripts/osx_install.sh | sed -n 's/^git checkout \(.*\)/\1/p' | head -1)
OSX_XROOTD=${OSX_XROOTD_TAG#v}; OSX_XROOTD=${OSX_XROOTD%-pelican}
OSX_XRDCL_TAG=$(sed -n 's/.*--branch \(v[0-9.]*\) .*xrdcl-pelican.git.*/\1/p' github_scripts/osx_install.sh | head -1)
OSX_XRDCL=${OSX_XRDCL_TAG#v}
OSX_XRDHTTP_TAG=$(grep -A3 'xrdhttp-pelican.git' github_scripts/osx_install.sh | sed -n 's/^git checkout \(.*\)/\1/p' | head -1)
OSX_XRDHTTP=${OSX_XRDHTTP_TAG#v}
OSX_S3HTTP_TAG=$(sed -n 's/.*--branch \(v[0-9.]*\) .*xrootd-s3-http.git.*/\1/p' github_scripts/osx_install.sh | head -1)
OSX_S3HTTP=${OSX_S3HTTP_TAG#v}
OSX_SCITOKENS_TAG=$(grep -A3 'scitokens-cpp.git' github_scripts/osx_install.sh | sed -n 's/^git checkout \(.*\)/\1/p' | head -1)

# --- xrootd/version.go and .goreleaser.in.yml (minimum-version floor) ---
MIN_GO=$(sed -n 's/.*MinXrootdVersion = "\([^"]*\)".*/\1/p' xrootd/version.go | head -1)
MIN_RPM=$(sed -n 's/.*"xrootd-server >= 1:\([0-9.]*\)".*/\1/p' .goreleaser.in.yml | head -1)

printf '%-28s %-22s %s\n' "PIN" "FILE" "VALUE"
printf '%-28s %-22s %s\n' "XRootD build version" "images/Dockerfile" "$(val "$DOCKER_XROOTD")"
printf '%-28s %-22s %s\n' "XRootD build version" "osx_install.sh" "$(val "$OSX_XROOTD") (tag: $(val "$OSX_XROOTD_TAG"))"
printf '%-28s %-22s %s\n' "xrdcl-pelican" "images/Dockerfile" "$(val "$DOCKER_XRDCL")"
printf '%-28s %-22s %s\n' "xrdcl-pelican" "osx_install.sh" "$(val "$OSX_XRDCL")"
printf '%-28s %-22s %s\n' "xrdhttp-pelican" "images/Dockerfile" "$(val "$DOCKER_XRDHTTP")"
printf '%-28s %-22s %s\n' "xrdhttp-pelican" "osx_install.sh" "$(val "$OSX_XRDHTTP")"
printf '%-28s %-22s %s\n' "xrootd-s3-http" "images/Dockerfile" "$(val "$DOCKER_S3HTTP")"
printf '%-28s %-22s %s\n' "xrootd-s3-http" "osx_install.sh" "$(val "$OSX_S3HTTP")"
printf '%-28s %-22s %s\n' "xrootd-lotman" "images/Dockerfile" "$(val "$DOCKER_LOTMAN")"
printf '%-28s %-22s %s\n' "xrootd-multiuser" "images/Dockerfile" "$(val "$DOCKER_MULTIUSER")"
printf '%-28s %-22s %s\n' "scitokens-cpp (source tag)" "osx_install.sh" "$(val "$OSX_SCITOKENS_TAG")"
printf '%-28s %-22s %s\n' "Min XRootD (runtime floor)" "xrootd/version.go" "$(val "$MIN_GO")"
printf '%-28s %-22s %s\n' "Min XRootD (RPM floor)" ".goreleaser.in.yml" "$(val "$MIN_RPM")"
echo

if [ "$DOCKER_XROOTD" != "$OSX_XROOTD" ]; then
  echo "MISMATCH: XRootD build version differs: Dockerfile=$DOCKER_XROOTD osx_install.sh=$OSX_XROOTD"; fail=1
fi
if [ "$DOCKER_XRDCL" != "$OSX_XRDCL" ]; then
  echo "MISMATCH: xrdcl-pelican differs: Dockerfile=$DOCKER_XRDCL osx_install.sh=$OSX_XRDCL"; fail=1
fi
if [ "$DOCKER_XRDHTTP" != "$OSX_XRDHTTP" ]; then
  echo "MISMATCH: xrdhttp-pelican differs: Dockerfile=$DOCKER_XRDHTTP osx_install.sh=$OSX_XRDHTTP"; fail=1
fi
if [ "$DOCKER_S3HTTP" != "$OSX_S3HTTP" ]; then
  echo "MISMATCH: xrootd-s3-http differs: Dockerfile=$DOCKER_S3HTTP osx_install.sh=$OSX_S3HTTP"; fail=1
fi
if [ "$MIN_GO" != "$MIN_RPM" ]; then
  echo "MISMATCH: minimum XRootD floor differs: version.go=$MIN_GO .goreleaser.in.yml=$MIN_RPM"; fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "OK: all cross-file pins consistent"
fi
exit "$fail"
