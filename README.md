# Triage — Fuzzing and Exploitability Analysis for Real-World C Parsers

Triage is a coverage-guided, **structure-aware** fuzzing and **crash-triage** instrument for
memory-unsafe C/C++ parsers. Its value is not a crash count — it is the structure-aware
mutation that reaches deep parser code, the triage that collapses tens of thousands of raw
crashes into a handful of classified, root-caused bugs, the conservative exploitability
analysis that says what each bug actually gives an attacker, the invariant-based detection
signatures it emits for each finding, and the coordinated disclosure that turns a finding into
a verifiable outcome.

> **One sentence:** *I built a fuzzing and exploitability-triage instrument and used it to
> find and characterize real memory-safety bugs in widely-used C libraries, and I disclosed
> what I found the way a professional does.*

The instrument is the contribution. Anyone can produce crashes; the rare and honest part is
turning a crash count into a set of classified, rated findings — and being precise about the
difference between "a crash" and "an exploit."

---

## What it demonstrates, and the honest ceiling on each claim

Triage is the memory-safety half of security engineering, and it reaches four adjacent areas
honestly **at the parser layer**. It does not pretend to do more. Claim the middle column;
never claim past the right column.

| Area | What Triage does | Ceiling — not claimed past here |
|---|---|---|
| Memory-corruption / vuln research | structure-aware fuzz → triage → primitive → patch → regression test | the core; claimed fully |
| Network protocols | fuzz CoAP / DNS / HTTP wire parsers; differential HTTP framing | parser-layer, not secure network *design* |
| Web application security | HTTP request-smuggling / desync via parser differentials | **server/proxy desync only** — not browser, not XSS/SQLi |
| Applied cryptography / protocols | ASN.1 / X.509 / JOSE **message** parsing, differential accept/reject | **parsing crypto messages** — NOT implementing or breaking crypto |
| Authentication control | fuzz a C JWT/JOSE library + a logic oracle for alg-confusion | memory fuzzing finds parse bugs; **logic bugs need the oracle** |
| Intrusion detection | invariant-based YARA/Suricata rules per bug, FP/FN-validated | detects **known-bug-class attempts**; not a novel IDS, not generalized |
| SDLC / tooling | CI fuzzing, regression gates, coordinated disclosure, CVE process | claimed fully |

A crash is not an exploit. Automated "likely exploitable" output is a heuristic hint, not a
demonstration. Every writeup states the class from sanitizer evidence and the exact rung it
reached on the ladder *crash → likely-exploitable → PoC-to-primitive → weaponized* — and
claims no higher. See [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).

---

## The pipeline

```
 seeds ─▶ [ fuzz ] ─▶ crashes ─▶ [ triage ] ─▶ unique bugs ─▶ [ classify ] ─▶ [ detect ] ─▶ [ disclose ]
          libFuzzer            dedup (stack     conservative      YARA/Suricata    CVE / GHSA
          / AFL++ /            hash) + ddmin    class + primitive  (invariant-       90-day
          standalone           minimize                            based, FP/FN)
             ▲
             └── structure-aware LLVMFuzzerCustomMutator (grammar per format)
```

- **`targets/`** — fuzz targets. `mferf/` is a self-contained demonstration target (below);
  `http_diff/` is the HTTP request-smuggling differential; `external/` holds drivers for the
  real under-fuzzed libraries (libcoap, TinyCBOR) and the FreeType seeded-rediscovery.
- **`triage/`** — the Python triage pipeline: ASan/UBSan report parsing, ASLR-normalized
  stack-hash bucketing, conservative classification, ddmin minimization, the triage table.
- **`detect/`** — the detection-signature generator: turns a confirmed bug into an
  **invariant-based** YARA/Suricata rule (not a PoC-byte overfit) and validates its
  true-positive rate on held-out mutated triggers and false-positive rate on a benign corpus.
- **`mutators/`, `dict/`, `corpus/`** — structure models, dictionaries, and seed corpora.
- **`scripts/`** — `run_campaign.sh` (libFuzzer campaign + triage), `compare_mutators.sh`
  and the runner's `--reach` mode (the structure-aware head-to-head), `mferf_pack.py`.

## `mferf` is a teaching target, not a finding

The whole pipeline runs end to end, in CI, with no network, against **`targets/mferf/`** — a
self-authored "Mini Extensible Record Format" TLV parser with five *planted, documented*
memory bugs (stack overflow, integer-overflow→heap overflow, OOB read, use-after-free,
unbounded recursion), each with a reproducer and a patched build for regression tests.
**Nothing found in `mferf` is a real-world finding, and no resume or writeup treats it as
one.** It exists to prove the instrument works. The real targets are the external libraries;
see [`docs/EXTERNAL_TARGETS.md`](docs/EXTERNAL_TARGETS.md).

---

## Quickstart

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install pytest

# 1. run the whole test suite (Python pipelines + C regression + differential)
python -m pytest -q tests

# 2. build the in-repo fuzz targets (engine auto-detected)
cmake -S . -B build && cmake --build build

# 3. (Linux / clang with libFuzzer) run a real campaign and triage the crashes
scripts/run_campaign.sh build/mferf_fuzz corpus/mferf 60

# 4. the structure-aware head-to-head
scripts/compare_mutators.sh
```

**Two fuzzing engines, one target contract.** Targets define `LLVMFuzzerTestOneInput` (and
optionally a structure-aware `LLVMFuzzerCustomMutator`). They build under real **libFuzzer**
(coverage-guided, Linux campaigns), **AFL++**, or a **standalone** corpus-replay / fork-mutate
runner for hosts without the libFuzzer runtime. Apple clang ships ASan but not the libFuzzer
runtime, and on macOS 26 the ASan runtime itself hangs at init — so sanitizer campaigns run on
Linux (and in CI), while the standalone runner and UBSan cover local development. Details and
the exact caveat: [`docs/BUILD.md`](docs/BUILD.md).

---

## Responsible disclosure

Any bug found in live, current code goes through coordinated disclosure: private report, a
90-day window, a CVE where warranted, and **no working exploit for unpatched live code is ever
published.** The public repo shows the harness, methodology, and findings against
already-patched or seeded-old versions. Policy and mechanics: [`SECURITY.md`](SECURITY.md) and
[`docs/DISCLOSURE.md`](docs/DISCLOSURE.md).

## Layout

| Path | What |
|---|---|
| `targets/mferf/` | demonstration target (planted bugs) + patched build |
| `targets/http_diff/` | two independent HTTP/1.1 parsers + the desync differential oracle |
| `targets/external/` | libcoap, TinyCBOR, FreeType@CVE drivers (opt-in via FetchContent) |
| `triage/` | crash-triage pipeline (Python) |
| `detect/` | detection-signature generator + validator (Python) |
| `include/triage/fuzzer.h` | the fuzz-target contract |
| `targets/standalone_main.c` | the standalone runner (replay / mutate / reach) |
| `docs/` | build, methodology, disclosure, external targets |
| `NUMBERS.md` | every measured number with its provenance and machine |

See [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) for the full method and
[`NUMBERS.md`](NUMBERS.md) for measured results.
