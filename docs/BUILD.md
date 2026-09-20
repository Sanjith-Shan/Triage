# Building and running Triage

## Engines — one target, three ways

Every target defines `LLVMFuzzerTestOneInput` and optionally `LLVMFuzzerCustomMutator`
(structure-aware) and `LLVMFuzzerReached` (a Triage extension for the mutator head-to-head).
The same source builds under:

| Engine | How | Where | Coverage-guided? |
|---|---|---|---|
| **libFuzzer** | `-DTRIAGE_ENGINE=libfuzzer` (auto-detected) | Linux, or any clang with the fuzzer runtime | yes (real edge coverage) |
| **AFL++** | `afl-clang-fast`, persistent mode | Linux campaign box | yes (+ CMPLOG) |
| **standalone** | `-DTRIAGE_ENGINE=standalone` (fallback) | anywhere ASan/UBSan compiles | no — replay + fork-mutate |

`TRIAGE_ENGINE=auto` (the default) probes whether a `-fsanitize=fuzzer` program links and
picks libFuzzer if so, else standalone.

```bash
cmake -S . -B build                 # auto engine, ASan+UBSan
cmake --build build
```

## The macOS caveat (why campaigns run on Linux)

On the dev Mac, two separate things push sanitizer campaigns to Linux:

1. **Apple clang ships ASan but not the libFuzzer runtime** (`libclang_rt.fuzzer_osx.a` is
   absent), so coverage-guided fuzzing needs Linux or a Homebrew/LLVM clang.
2. **On macOS 26 / Darwin 25 the ASan *runtime* hangs at init** — even a trivial
   `int main(){return 0;}` built with `-fsanitize=address` never reaches `main` (it spins in
   shadow-memory setup). This is an OS/runtime regression, not a code bug, and it is confirmed
   independently in this repo's history.

So locally: the **standalone runner** and **UBSan** cover development, unit tests, the HTTP
differential (its oracle is `abort()`, no sanitizer needed), and the mutator head-to-head. The
Python pipelines (`triage/`, `detect/`) run natively. The **ASan-dependent assertions
skip locally with a printed reason** (`tests/_ci_support.py`) and **run for real on Linux CI**,
where ASan works and libFuzzer is present. Nothing is silently dropped.

## Running things

```bash
# whole suite (Python + C regression + differential); ASan checks skip on mac, run on Linux
python -m pytest -q tests

# reproduce a planted bug locally without ASan (recursion faults on its own)
cmake -S . -B build-plain -DTRIAGE_SANITIZE=""
cmake --build build-plain --target mferf_fuzz
build-plain/mferf_fuzz tests/mferf/reproducers/crash-MFERF-005    # SIGSEGV

# real libFuzzer campaign + triage (Linux)
scripts/run_campaign.sh build/mferf_fuzz corpus/mferf 60

# structure-aware head-to-head (crash yield, no sanitizer needed)
build-plain/mferf_fuzz --reach 100000 --seeds corpus/mferf --mutator naive
build-plain/mferf_fuzz --reach 100000 --seeds corpus/mferf --mutator structured
```

## Enabling the real external targets

Off by default (they fetch and build third-party code). See
[`EXTERNAL_TARGETS.md`](EXTERNAL_TARGETS.md).

```bash
cmake -S . -B build -DTRIAGE_ENGINE=libfuzzer -DTRIAGE_TARGET_LIBCOAP=ON
cmake --build build --target coap_fuzz
```
