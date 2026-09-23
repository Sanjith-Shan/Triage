#!/usr/bin/env bash
# The structure-aware head-to-head: naive byte mutation vs the grammar-aware
# LLVMFuzzerCustomMutator, on the SAME target, seeds, budget and seed. Reports
# crash yield (and reach rate) for each. This is the core contribution measured,
# the same move as Basalt (vectorized vs row-at-a-time).
#
# Uses the STANDALONE engine's --reach mode so the number needs no coverage
# runtime and no per-crash re-triage (fast). Real libFuzzer picks its own mutator;
# the coverage-guided version of this comparison is a campaign-vs-campaign run.
#
#   scripts/compare_mutators.sh [runs] [seed]
set -euo pipefail

RUNS="${1:-100000}"
SEED="${2:-1}"
BUILD="build-standalone"

# Plain (no sanitizer) is enough for the crash-yield number and runs anywhere;
# the silent-corruption bugs only widen the gap under ASan on Linux.
cmake -S . -B "${BUILD}" -DTRIAGE_ENGINE=standalone -DTRIAGE_SANITIZE="" >/dev/null
cmake --build "${BUILD}" --target mferf_fuzz >/dev/null
BIN="${BUILD}/mferf_fuzz"

echo "== structure-aware head-to-head (${RUNS} runs, seed ${SEED}) =="
"${BIN}" --reach "${RUNS}" --seeds corpus/mferf --mutator naive      --seed "${SEED}"
"${BIN}" --reach "${RUNS}" --seeds corpus/mferf --mutator structured --seed "${SEED}"
echo
echo "Compare the crashes= counts. The structure-aware mutator reaches the deep"
echo "record handlers (boundary lengths, vulnerable types) far more often, so it"
echo "finds many more crashes at equal budget; naive mutation mostly nibbles bytes"
echo "that don't matter. Under ASan on Linux the gap widens, because the silent"
echo "heap bugs become detectable and they live behind exactly those fields."
