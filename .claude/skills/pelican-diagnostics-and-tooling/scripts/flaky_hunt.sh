#!/usr/bin/env bash
# flaky_hunt.sh — adjudicate a suspected flaky Go test by running it N times under the race detector.
#
# Usage:   ./flaky_hunt.sh <package> <test-regex> [iterations] [build-tags]
# Example: ./flaky_hunt.sh ./director 'TestDirectorRegistration' 20 server
#
# Run from the pelican repo root. Read-only with respect to the repo (only the Go
# build/test cache is written). Exits 0 if every run passed, 1 if any run failed.
# Logs of failing runs are kept in a temp dir and their paths printed.
#
# Interpretation:
#   0/N failures  -> no evidence of flake at this N; raise N (>=50) before declaring stable.
#   some failures -> genuinely flaky; grep the kept logs for "WARNING: DATA RACE" to decide
#                    whether it is a race (route to pelican-concurrency-and-shutdown-proofs)
#                    or an ordering/timeout flake (fix with require.Eventually, never time.Sleep).
#   N/N failures  -> not flaky: deterministically broken. Debug it directly.

set -u

PKG="${1:?usage: flaky_hunt.sh <package> <test-regex> [iterations] [build-tags]}"
TEST_RE="${2:?usage: flaky_hunt.sh <package> <test-regex> [iterations] [build-tags]}"
N="${3:-10}"
TAGS="${4:-server}"

OUTDIR="$(mktemp -d "${TMPDIR:-/tmp}/flaky_hunt.XXXXXX")"
fails=0

echo "Running ${TEST_RE} in ${PKG} ${N}x with -race -tags=${TAGS}"
for i in $(seq 1 "$N"); do
    log="${OUTDIR}/run-${i}.log"
    if go test -race -count=1 -timeout 10m -tags "$TAGS" -run "$TEST_RE" "$PKG" >"$log" 2>&1; then
        printf 'run %2d: PASS\n' "$i"
        rm -f "$log"
    else
        printf 'run %2d: FAIL (log: %s)\n' "$i" "$log"
        if grep -q 'WARNING: DATA RACE' "$log"; then
            printf '        ^ contains a DATA RACE report\n'
        fi
        fails=$((fails + 1))
    fi
done

echo "----------------------------------------"
echo "result: ${fails}/${N} runs failed"
if [ "$fails" -gt 0 ]; then
    echo "failing logs kept under: ${OUTDIR}"
    exit 1
fi
rmdir "$OUTDIR" 2>/dev/null || true
exit 0
