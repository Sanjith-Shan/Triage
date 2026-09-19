# External targets — the real surface

The in-repo `mferf` target proves the pipeline; the *findings* come from real, under-fuzzed
C/C++ libraries. Selection principle: memory-unsafe C/C++, attacker-reachable through a real
threat model, and **not already saturated by OSS-Fuzz** — because that is where a competent
effort still finds bugs in 2026. Rust libraries are memory-safe and are skipped for
memory-safety hunting (they serve only as differential oracles).

**OSS-Fuzz enrollment shifts fast. Before committing effort, confirm live status** by checking
`github.com/google/oss-fuzz/tree/master/projects/<name>` and the Introspector dashboard.

## Fresh-discovery targets (thin coverage, live CVEs, structure-aware)

| Rank | Library | Parses | Threat model | Why now |
|---|---|---|---|---|
| 1 | **libcoap** (`obgm/libcoap`, C) | CoAP messages + options | IoT off the wire / DTLS | active 2024–25 CVE stream (CVE-2025-34468, CVE-2025-65500, CVE-2024-0962); thin OSS-Fuzz; option-delta/length TLV = structure-aware win |
| 2 | **CBOR family** (`QCBOR`, `intel/tinycbor`, `PJK/libcbor`, `msgpack/msgpack-c`) | CBOR / MessagePack | COSE/CWT tokens, WebAuthn, IoT, RPC | thin/intermittent coverage; live CVE (msgpack-c CVE-2026-72854); best serialization **differential** |
| 3 | **JWT/JOSE** (`GlitchedPolygons/l8w8jwt`, `cisco/cjose`, C) | JWT / JOSE tokens | auth-token validation | not on OSS-Fuzz; high-value auth surface; differential-friendly |
| 4 | **live555** (C++) | RTSP/RTP/RTCP/SDP | media servers, IP cameras | no OSS-Fuzz (license); stateful; RCE history |
| — | **libheif**, **TagLib**, **libexif**, **ldns**, **Wakaama** | HEIF/AVIF, audio tags, EXIF, DNS, LwM2M | file/media/DNS/IoT | strong secondary picks; TagLib freshly added to OSS-Fuzz (shallow window) |

## Differential pairs (feed identical bytes, diff the decode)

1. **HTTP/1.1** — `llhttp` ↔ `nodejs/http-parser` ↔ `h2o/picohttpparser` (↔ nginx/h2o/httpd).
   The production version of `targets/http_diff/`. Divergence = request smuggling.
2. **CBOR** — `libcbor` ↔ `tinycbor` ↔ `QCBOR`.
3. **ASN.1 DER** — `libtasn1` ↔ `mbedtls asn1` ↔ `wolfssl asn` ↔ `asn1c`.
4. **DNS wire** — `ldns` ↔ `c-ares`.
5. **JWT/JOSE** — `l8w8jwt` ↔ `cjose` (alg/`crit`/`typ` confusion — logic, needs the oracle).

## Seeded rediscovery (guaranteed narrative, luck-independent)

Pin a SATURATED library to a version *before* a known fix and have the instrument rediscover,
minimize and classify the bug. This guarantees a complete find → triage → classify story even
if no novel bug appears in the fresh targets.

| Library | Pin | Bug | Class |
|---|---|---|---|
| **FreeType** | `VER-2-13-0` (fixed in 2.13.3) | CVE-2025-27363 | OOB write, TrueType subglyph, exploited in the wild |
| libarchive | pre-fix | CVE-2025-5914/5916 | — |
| libtasn1 | pre-fix | CVE-2024-12133 | quadratic-parse DoS |

**Never run a seeded target against current code and call the result a finding.** The
`freetype_fuzz` driver is pinned deliberately and documented as a rediscovery.

## Enabling a target

Each is off by default and fetched via CMake `FetchContent`:

```bash
cmake -S . -B build -DTRIAGE_ENGINE=libfuzzer -DTRIAGE_TARGET_LIBCOAP=ON
cmake --build build --target coap_fuzz
scripts/run_campaign.sh build/coap_fuzz corpus/coap 300
```

Notes:
- **libcoap** — the `GIT_TAG` in `CMakeLists.txt` is a placeholder release; pick the version
  window you intend to fuzz and confirm its OSS-Fuzz status first.
- **TinyCBOR** ships no CMake; build its `src/*.c` into an object library and link, or point
  `-DTRIAGE_TARGET_CBOR` at a small wrapper. Pin a commit before campaigning.
- **FreeType** pins `VER-2-13-0` for the seeded rediscovery.

All external drivers live in `targets/external/` and reuse the standard target contract, so
they run under libFuzzer, AFL++, or the standalone runner unchanged.
