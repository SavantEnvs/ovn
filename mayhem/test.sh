#!/usr/bin/env bash
#
# mayhem/test.sh — RUN OVN's lflow-language known-answer tests (built by mayhem/build.sh with normal
# flags as mayhem/_build/test/ovn/tests/ovstest). Cases and expected outputs come from upstream's
# tests/ovn.at ("expression parser", "expression annotation", "action parsing"); each case's output
# from `ovstest test-ovn <cmd>` must equal upstream's expected output. Emits CTRF.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

OVSTEST="$SRC/mayhem/_build/test/ovn/tests/ovstest"
if [ ! -x "$OVSTEST" ]; then
  echo "test runner $OVSTEST missing — run mayhem/build.sh first" >&2
  emit_ctrf "ovn-test-ovn" 0 1
  exit 1
fi

out="$(python3 -I "$SRC/mayhem/test_ovn_cases.py" "$OVSTEST" "$SRC/tests/ovn.at")"
echo "$out" | grep '^FAIL' || true
read -r passed failed < <(echo "$out" | sed -n 's/^COUNTS //p')
: "${passed:=0}" "${failed:=1}"
# A run that produced no PASS lines at all (runner neutered / no output) is a failure.
[ "$passed" -gt 0 ] || failed=$(( failed > 0 ? failed : 1 ))
emit_ctrf "ovn-test-ovn" "$passed" "$failed"
