#!/usr/bin/env bash
# The structure-aware head-to-head: naive byte mutation vs the grammar-aware
# LLVMFuzzerCustomMutator, on the SAME target, seeds, run budget and seed. Reports
# runs-to-first-crash and unique bugs found by each. This is the core contribution
# measured, the same move as Basalt (vectorized vs row-at-a-time).
#
# Uses the STANDALONE engine so both mutators are driven by the same runner (real
# libFuzzer picks its own mutator). Requires a runnable ASan binary (Linux).
#
#   scripts/compare_mutators.sh [runs] [seed]
set -euo pipefail

RUNS="${1:-200000}"
SEED="${2:-1}"
BUILD="build-standalone"

cmake -S . -B "${BUILD}" -DTRIAGE_ENGINE=standalone >/dev/null
cmake --build "${BUILD}" --target mferf_fuzz >/dev/null
BIN="${BUILD}/mferf_fuzz"

export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0"

run_one () {  # $1 = naive|structured
  local mut="$1" out="cmp-${1}"
  rm -rf "${out}"; mkdir -p "${out}"
  "${BIN}" --mutate "${RUNS}" --seeds corpus/mferf --out "${out}" \
           --mutator "${mut}" --seed "${SEED}"
  # count unique bugs among the collected crashes
  local uniq
  uniq=$(python3 -m triage "${out}" --binary "${BIN}" --json "${out}/t.json" 2>/dev/null \
         | grep -c '^' || true)
  python3 - "$out" <<'PY'
import json,sys,glob,os
d=sys.argv[1]
p=os.path.join(d,"t.json")
try:
    j=json.load(open(p)); print(f"{d}: unique_bugs={len(j.get('bugs',[]))}")
except Exception:
    print(f"{d}: unique_bugs=?")
PY
}

echo "=== naive ===";       run_one naive
echo "=== structured ===";  run_one structured
echo
echo "Compare the 'runs_to_first_crash' and 'unique_bugs' lines above. Structured"
echo "should reach the deep record handlers (and thus more distinct bugs) far"
echo "sooner, because naive mutation mostly corrupts the MFR1 magic and bounces."
