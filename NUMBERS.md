# Numbers ledger

Every number here is measured, with its machine and the exact command. Nothing is estimated or
extrapolated. Numbers that require the Linux campaign box (ASan runtime + libFuzzer) are marked
**pending** with the command that produces them — the same discipline the rest of the portfolio
uses. An unmeasured number is not a number.

## Test suite (measured 2026-09-23, Apple M3 Pro, macOS 26)

`python -m pytest -q tests` → **80 passed, 9 skipped**.

| Suite | Tests | Notes |
|---|---|---|
| `tests/triage` | 33 | ASan/UBSan report parsing, stack-hash dedup, classification, ddmin |
| `tests/detect` | 34 | invariant rules, YARA/Suricata gen, anti-overfit validation |
| `tests/http_diff` | 10 | two-parser divergence + memory safety (UBSan locally, ASan on CI) |
| `tests/mferf` | 3 run / 9 skipped | plain-build regressions run; ASan regressions run on Linux CI |

The 9 skips are the ASan-only MFERF assertions; they run on Linux CI (see `docs/BUILD.md`).

## Detection generator — anti-overfit thesis (measured 2026-09-23)

On 50 held-out mutated request-smuggling triggers, scored by the same harness:

| Rule | True-positive rate | False-positive rate (benign corpus) |
|---|---|---|
| **Invariant-based** (Content-Length + Transfer-Encoding coexist) | **100.0%** | 0.0% |
| Byte-sequence (literal PoC bytes) | **0.0%** | — |

This is the whole point of the detection stage: the payload-independent invariant generalizes;
the atomic-of-one PoC signature collapses. `tests/detect/test_...anti_overfit...`.

## Structure-aware mutator — head-to-head (measured 2026-09-23)

Apple M3 Pro, macOS 26, **standalone engine, no sanitizer**, MFERF target, seeds
`corpus/mferf`, fork-per-input. Command:

```
build-plain/mferf_fuzz --reach 100000 --seeds corpus/mferf --mutator {naive|structured} --seed S
```

**Crash yield at equal budget (100,000 runs):**

| Seed | naive | structure-aware | ratio |
|---|---|---|---|
| 1 | 121 | 1,335 | 11.0× |
| 2 | 118 | 1,366 | 11.6× |
| 3 | 124 | 1,247 | 10.1× |

The structure-aware mutator finds **~10–12× more crashes** at equal budget, because it drives
length fields to the integer boundaries (`0xFFFFFFFF`, 32, 64, …) and flips record types
straight into the vulnerable handlers, where naive byte-flipping mostly nibbles at bytes that
don't matter.

**Reach rate** (fraction of mutants that get past the MFR1 header into the record loop, 50,000
runs, seed 1): naive **0.9469**, structure-aware **0.9868**. Reach is a weak differentiator on
this target because the naive mutator is single-byte-oriented and rarely lands on the 4 magic
bytes; **crash yield is the honest headline**, and it is where the structure model shows.

**Caveat, stated plainly.** These are *plain-build* crashes — stack-protector aborts
(MFERF-001-class) and recursion SIGSEGV (MFERF-005). The three silent-corruption bugs
(MFERF-002/003/004) do not fault without a sanitizer, so this no-ASan number is a **lower bound
on the gap**: under ASan on Linux the structure-aware advantage is larger, because those bugs
become detectable and they live behind exactly the length/type fields the structure model
targets.

## Campaign numbers — pending (Linux + libFuzzer)

These need the ASan runtime and libFuzzer, which do not run on the dev Mac (see
`docs/BUILD.md`). They run in CI (`.github/workflows/ci.yml`, `campaign` job) and on the Linux
campaign box. Commands recorded so they are reproducible:

- **Distinct bugs from raw crash count** on MFERF under real libFuzzer, e.g. "N crashes → 5
  distinct bugs" — `scripts/run_campaign.sh build/mferf_fuzz corpus/mferf 60` then
  `python -m triage campaigns/mferf_fuzz/crashes --binary build/mferf_fuzz --minimize`.
- **Reached-edge coverage** per target (proves the fuzzer entered the parser) — libFuzzer
  `-print_coverage=1` / `llvm-cov`.
- **Structure-aware vs naive under libFuzzer** — real edge coverage and time-to-first-crash,
  the coverage-guided version of the head-to-head above.
- **External-target findings** (libcoap / CBOR / JOSE) and the **FreeType CVE-2025-27363
  seeded rediscovery** — `docs/EXTERNAL_TARGETS.md`.

None of the pending numbers may reach a resume until measured and recorded here with the
machine and target version.
