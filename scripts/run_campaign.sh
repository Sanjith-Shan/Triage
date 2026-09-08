#!/usr/bin/env bash
# Run a real libFuzzer campaign against a target, then triage the crashes.
# Linux (or any clang with the libFuzzer runtime). See docs/BUILD.md.
#
#   scripts/run_campaign.sh <target-binary> <seed-corpus-dir> [seconds]
#
# Produces campaigns/<target>/crashes/ and a triage table on stdout.
set -euo pipefail

BIN="${1:?usage: run_campaign.sh <target-binary> <seed-corpus> [seconds]}"
SEEDS="${2:?need a seed corpus dir}"
SECS="${3:-60}"
NAME="$(basename "$BIN")"
OUT="campaigns/${NAME}"
mkdir -p "${OUT}/crashes" "${OUT}/corpus"
cp -f "${SEEDS}"/* "${OUT}/corpus/" 2>/dev/null || true

DICT_ARG=()
[ -f "dict/${NAME%%_*}.dict" ] && DICT_ARG=(-dict="dict/${NAME%%_*}.dict")

export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:dedup_token_length=3"

echo ">> libFuzzer campaign: ${NAME} for ${SECS}s"
# libFuzzer saves reproducers as crash-* / oom-* / timeout-* under -artifact_prefix.
"${BIN}" "${OUT}/corpus" \
  "${DICT_ARG[@]}" \
  -max_total_time="${SECS}" \
  -artifact_prefix="${OUT}/crashes/" \
  -print_final_stats=1 || true

echo ">> triaging crashes"
python3 -m triage "${OUT}/crashes" \
  --binary "${BIN}" --minimize \
  --markdown "${OUT}/triage.md" --json "${OUT}/triage.json" || true
echo ">> wrote ${OUT}/triage.md"
cat "${OUT}/triage.md" 2>/dev/null || echo "(no crashes)"
