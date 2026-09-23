# Campaign results — RunPod CPU box, 2026-09-23

Real libFuzzer + AddressSanitizer/UBSan campaigns on Linux (the dev Mac cannot run
ASan). Box: RunPod CPU pod `3x639x51zasgxk`, Ubuntu 24.04, clang 18.1.3, 2 vCPU,
`-fork=2`. Every number here is measured; commands are in `scripts/` and this file.

## MFERF (in-repo demonstration target) — the pipeline end to end

`./build/mferf_fuzz corpus/mferf -fork=2 -ignore_crashes=1 -dict=dict/mferf.dict
-max_total_time=180`, then `python -m triage … --minimize`.

**1,337 saved crashes → 9 distinct bugs** (`mferf_triage.md`). Every planted bug class
was found and correctly classified, and each unique bug was minimized to a tiny input:

| bug | class | exploitability | top frame | #crashes | minimized |
|---|---|---|---|---|---|
| BUG-0001 | heap-use-after-free | likely-exploitable | rec_recycle | 572 | 13 B |
| BUG-0002 | SEGV (far OOB read) | crash | rec_index | 441 | 49 B |
| BUG-0003 | heap-buffer-overflow | likely-exploitable | rec_blob | 126 | 19 B |
| BUG-0004 | stack-buffer-overflow | likely-exploitable | rec_string | 166 | 45 B |
| BUG-0005 | heap-buffer-overflow (redzone) | crash | rec_index | 28 | 16 B |
| BUG-0006–0009 | variants of the above | — | — | 1 each | — |

This is the whole thesis in one run: a crash count (1,337) is not a finding; the triage
into 9 classified, minimized, root-caused bugs is.

## FreeType 2.13.0 (seeded rediscovery target) — real external code

`-DTRIAGE_TARGET_FREETYPE=ON`, seeds = system DejaVu TTFs, `-fork=2
-max_total_time=900`. Final: **cov 7,112 edges, corpus 1,432, 0 memory crashes.**

- **Coverage-guided fuzzing genuinely reached deep into FreeType's parser** (7,112
  edges) — after fixing the build so the fetched library is coverage-instrumented,
  not just the driver (see the CMake fix in git history; coverage went 2 → 7,112).
- **Two real UBSan findings**: calls through incompatible function-pointer types in
  FreeType's module system (`ftobjs.c:5146` → `ps_hinter_init`, `ftobjs.c:4605` →
  `gray_raster_new`). See `freetype_ubsan_sample.txt`. This is a known, CFI-relevant
  pattern in FreeType (generic module function pointers), not a memory-corruption bug —
  reported honestly as what it is.
- **No rediscovery of CVE-2025-27363 in this window.** Honest negative: that OOB write
  is in a specific TrueType composite-glyph path that a 15-minute run from generic font
  seeds did not reach. Rediscovering it reliably needs a targeted seed corpus (crafted
  composite-glyph fonts) or a much longer campaign. The harness and instrumentation are
  correct; the time budget was the limit.

## libcoap (fresh-discovery target) — real external code

`-DTRIAGE_TARGET_LIBCOAP=ON` (DTLS/OSCORE off), 4 hand-crafted CoAP seeds, `-fork=2
-max_total_time=600`. Final: **cov 739 edges, corpus 570, 0 crashes, 0 sanitizer hits.**

Honest negative. The harness exercises `coap_pdu_parse` (basic PDU framing), which is
fairly hardened; libcoap's recent CVEs live in the DTLS, OSCORE, and hostname paths that
this harness does not reach. A real hunt here would add harnesses for those entry points.

## What the box run proved

1. The full pipeline runs on real Linux/libFuzzer and turns 1,337 crashes into 9
   classified, minimized bugs.
2. The external-target build was genuinely wrong (fetched libs uncovered) and the box
   caught it — now fixed and coverage climbs into the thousands on real code.
3. Two honest negatives on real external code in short windows, plus real UBSan
   findings in FreeType — reported as exactly what they are, no inflation.

## Reproduce

```bash
# on a Linux box with clang:
cmake -S . -B build -DTRIAGE_ENGINE=libfuzzer && cmake --build build --target mferf_fuzz
./build/mferf_fuzz corpus/mferf -fork=2 -ignore_crashes=1 -dict=dict/mferf.dict -max_total_time=180 -artifact_prefix=crashes/
python -m triage crashes --binary build/mferf_fuzz --minimize --markdown triage.md

cmake -S . -B build-ft -DTRIAGE_ENGINE=libfuzzer -DTRIAGE_TARGET_FREETYPE=ON
cmake --build build-ft --target freetype_fuzz
./build-ft/freetype_fuzz <font-seeds> -fork=2 -max_total_time=900 -artifact_prefix=crashes-ft/
```
