#!/usr/bin/env bash
# goroutine_diff.sh — dump-and-diff goroutine profiles from a running Pelican server
# to find goroutine leaks (grow-only stacks).
#
# Usage:
#   PELICAN_TOKEN=$(cat /path/to/admin.tok) \
#     ./goroutine_diff.sh <server-web-url> [interval-seconds]
#
#   <server-web-url>    e.g. https://my-director.example.com:8444
#   [interval-seconds]  time between the two dumps (default 60)
#
# Environment:
#   PELICAN_TOKEN  admin bearer token (required: the pprof routes sit behind
#                  AuthHandler+AdminAuthHandler). See SKILL.md for how to mint one.
#   PPROF_PATH     override the profile path (default /api/v1.0/debug/pprof/goroutine;
#                  set to /debug/pprof/goroutine for a stock net/http/pprof server)
#   CURL_EXTRA     extra curl flags, e.g. "-k" for a throwaway self-signed test server
#
# Requires: Server.EnablePprof=true on the target (default is false).
# Read-only: performs two HTTP GETs; writes dumps to a temp dir only.
#
# Interpretation:
#   Stacks whose goroutine count GREW between dumps are printed with the delta.
#   - Steady growth across repeated invocations = leak. Grab the matching stack
#     from the raw dumps (paths printed) and route root-causing to
#     pelican-concurrency-and-shutdown-proofs.
#   - A one-off jump in net/http.(*conn).serve just means concurrent requests.
#   - Healthy: deltas hover around 0; totals stable within a few dozen.
set -u

URL="${1:?usage: goroutine_diff.sh <server-web-url> [interval-seconds]}"
INTERVAL="${2:-60}"
PPROF_PATH="${PPROF_PATH:-/api/v1.0/debug/pprof/goroutine}"
TOKEN="${PELICAN_TOKEN:-}"
CURL_EXTRA="${CURL_EXTRA:-}"

OUTDIR=$(mktemp -d "${TMPDIR:-/tmp}/goroutine_diff.XXXXXX")
HDR=()
[ -n "$TOKEN" ] && HDR=(-H "Authorization: Bearer $TOKEN")

fetch() { # $1 = output file
    # debug=1 gives the text format: "N @ pc pc ..." followed by "#\tpc\tfunc+off\tfile:line"
    # ${HDR[@]+...} keeps `set -u` happy on bash 3.2 (macOS) when HDR is empty
    if ! curl -sf ${CURL_EXTRA} ${HDR[@]+"${HDR[@]}"} "${URL%/}${PPROF_PATH}?debug=1" -o "$1"; then
        echo "ERROR: failed to fetch ${URL%/}${PPROF_PATH}?debug=1" >&2
        echo "       (is Server.EnablePprof=true? is the token an admin token?)" >&2
        exit 1
    fi
}

# Collapse a debug=1 dump into "count<TAB>leaf-function" lines, one per stack.
signatures() {
    awk '
        /^[0-9]+ @/ { count = $1; want = 1; next }
        want && /^#/ { print count "\t" $3; want = 0 }
    ' "$1" | awk -F'\t' '{ sum[$2] += $1 } END { for (s in sum) print sum[s] "\t" s }'
}

fetch "$OUTDIR/dump1.txt"
TOTAL1=$(head -1 "$OUTDIR/dump1.txt")
echo "dump 1: $TOTAL1"
echo "sleeping ${INTERVAL}s ..."
sleep "$INTERVAL"
fetch "$OUTDIR/dump2.txt"
TOTAL2=$(head -1 "$OUTDIR/dump2.txt")
echo "dump 2: $TOTAL2"
echo

signatures "$OUTDIR/dump1.txt" | sort -t$'\t' -k2 > "$OUTDIR/sig1.txt"
signatures "$OUTDIR/dump2.txt" | sort -t$'\t' -k2 > "$OUTDIR/sig2.txt"

echo "stacks that grew (delta / before -> after / leaf function):"
join -t$'\t' -a2 -e0 -o '1.1,2.1,2.2' -12 -22 "$OUTDIR/sig1.txt" "$OUTDIR/sig2.txt" \
  | awk -F'\t' '$2 > $1 { printf "  +%-5d %5d -> %-5d %s\n", $2-$1, $1, $2, $3 }' \
  | sort -rn -k1
GREW=$(join -t$'\t' -a2 -e0 -o '1.1,2.1' -12 -22 "$OUTDIR/sig1.txt" "$OUTDIR/sig2.txt" | awk -F'\t' '$2 > $1' | wc -l | tr -d ' ')
[ "$GREW" -eq 0 ] && echo "  (none)"
echo
echo "raw dumps kept: $OUTDIR/dump1.txt $OUTDIR/dump2.txt"
