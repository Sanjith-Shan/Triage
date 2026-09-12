# http_diff — HTTP/1.1 request-smuggling / desync differential target

A self-contained **differential fuzzing** target: two independent HTTP/1.1
request-framing parsers that are *deliberately, plausibly different*, plus a
driver that runs both on the same bytes and flags any **framing divergence**.
A divergence between two parsers on the same connection is the core primitive
behind **HTTP request smuggling / desync** attacks.

This is the "flagship differential" *demonstration*: both parsers are written
from scratch here so the whole thing is dependency-free and easy to reason
about. The production differential (real `llhttp` ↔ `picohttpparser`) is wired
separately by the parent project via FetchContent; the semantics modelled here
mirror the classes those real parsers disagree on.

## Files

| File | Role |
|------|------|
| `parser_a.c` / `parser_a.h` | **Strict-ish** parser (RFC-7230-leaning). |
| `parser_b.c` / `parser_b.h` | **Lenient** parser (permissive server/proxy). |
| `diff_driver.c` | Defines `LLVMFuzzerTestOneInput`; runs both, compares, reports+aborts on divergence. |

There is **no `main()`** in this target. It exposes only the standard libFuzzer
entry point:

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
```

so it can be driven by **real libFuzzer** (Linux) *or* by an externally-linked
**standalone corpus-replay runner** (macOS/ASan, which lacks the libFuzzer
runtime). The parent project supplies that `main` in both flavors; the pytest
in `tests/http_diff/` supplies a tiny throwaway `_test_main.c` for CI only.

## What each parser models

Each parser reads a single HTTP/1.1 request and reports, via a small result
struct, **how it frames the message body**:

- `parse_ok` — did it accept the request under its own rules?
- framing **mode** — `CONTENT_LENGTH n` | `CHUNKED` | `UNTIL_CLOSE` | `ERROR`
- **`boundary_off`** — the byte offset where this parser believes the *first*
  request ends and the *next* one begins. **This is the smuggling-relevant
  quantity:** if two nodes on a keep-alive connection compute different
  boundaries, one node's request body is the other node's next request.

### The intentional rule differences (these create the divergences)

| Aspect | `parser_a` (strict) | `parser_b` (lenient) |
|--------|---------------------|----------------------|
| Both `Content-Length` **and** `Transfer-Encoding: chunked` present | **TE wins** — chunked is authoritative (RFC 7230 §3.3.3 rule 3) | **CL wins** — uses Content-Length, ignores chunked |
| Duplicate `Content-Length` | **Reject** (hard error) | **Tolerate** — keep the first value |
| Content-Length value | must be all decimal digits, no overflow | parse leading digits, ignore trailing junk; clamp too-large CL to available bytes |
| Chunk size line | pure hex only; **chunk-extensions (`;…`) rejected**; must end in CRLF | tolerates a leading space, **ignores extensions / trailing junk**, accepts bare LF |
| Unparseable chunk size | **error** | treated as **size 0 = end of body** |
| Header line starting with SP/HTAB (obs-fold) | **reject** | **tolerate** (fold onto previous) |
| Line endings | strict CRLF | CRLF **or** bare LF |

Because A trusts TE and B trusts CL (among other differences), the same bytes
get framed two different ways — exactly the CL.TE / TE.CL / TE.TE conditions
that enable desync.

## The divergence taxonomy

The driver labels each finding (`class=…`) using the standard smuggling
vocabulary:

- **CL.TE** — one parser frames by `Content-Length`, the other by chunked
  `Transfer-Encoding`. The canonical smuggling class (front-end uses one
  header, back-end uses the other).
- **TE.CL** — the mirror image; also surfaces here as a `CL.TE`-class
  disagreement (both are a CL-vs-TE conflict, distinguished by which side is
  which — see the `A=…`/`B=…` fields of the report).
- **TE.TE** — both frame by chunked but compute different boundaries because
  one parses chunks strictly and the other sloppily (e.g. a bogus
  chunk-extension or non-hex size that one treats as end-of-body).
- **CL.CL** — both frame by Content-Length but disagree on the value (e.g. one
  rejects a duplicate that the other accepts) — included for completeness.

## The oracle: "abort == divergence found"

A differential fuzzer needs a **crash** to signal *interesting*, because a
crash is the only signal libFuzzer / a crash-replay runner records. So when
both parsers accept the request but disagree on framing mode or boundary
offset, `diff_driver.c` prints a single greppable line to **stderr** and calls
`abort()`:

```
DIVERGENCE: A=CHUNKED:0 boundary=99 | B=CL:5 boundary=93 | class=CL.TE
```

- `A=…` / `B=…` — each parser's framing mode, its resolved content-length (0 if
  N/A), and its boundary offset.
- `class=…` — the taxonomy label above.

**The abort is the finding, not a memory bug.** The parsers and the driver are
memory-safe (see below); a real ASan/UBSan memory error would be a separate,
genuine defect. If either parser *rejects* the input, there is no shared
agreement to violate, so the driver returns 0 (uninteresting).

## Memory safety

The whole point of this target is **semantic** divergence, not crashes. Both
parsers are read-only, bounds-check every access against `size`, make forward
progress on every loop iteration (so they terminate on any input), and guard
all size arithmetic against overflow. They are intended to be clean under
`-fsanitize=address,undefined -Wall -Wextra -Werror`.

## Honest ceiling (what this does and does NOT prove)

This target finds the **parser-discrepancy primitive**: two implementations
that segment the same byte stream differently. That is *necessary* for request
smuggling but **not by itself a proof of end-to-end exploitability**. Proving a
real desync requires a front-end/back-end proxy lab (a real chain such as an
edge proxy in front of an origin server), connection-reuse conditions, and a
concrete attacker/victim request pairing.

What this reproduces is a **known class** of bug. Prior art:

- **T-Reqs: HTTP Request Smuggling with Differential Fuzzing** — Jabiyev et
  al., *ACM CCS 2021*. Grammar-based differential fuzzing across HTTP servers
  and proxies.
- **HTTP Garden** — Narayana Kittur/Bright et al., arXiv:2405.17737 — a
  differential-testing harness driving many real HTTP implementations to
  surface parsing discrepancies.

The production version of *this* differential (real `llhttp` ↔
`picohttpparser`) is wired by the parent project; the two hand-written parsers
here are a faithful, dependency-free stand-in that exercises the same oracle.

## Build & run

This target has no `main`; link it against a driver `main`.

**With real libFuzzer (Linux / clang with the libFuzzer runtime):**

```sh
clang -std=c11 -g -O1 -fsanitize=address,undefined,fuzzer \
    parser_a.c parser_b.c diff_driver.c -o http_diff_fuzz
./http_diff_fuzz corpus/http_diff/        # fuzz, seeded by the corpus
```

**Standalone corpus replay (macOS/ASan, no libFuzzer runtime)** — link the
parent's standalone runner (or the test's `_test_main.c`) which calls
`LLVMFuzzerTestOneInput` once per file:

```sh
clang -std=c11 -g -O1 -fsanitize=address,undefined \
    parser_a.c parser_b.c diff_driver.c path/to/standalone_main.c -o http_diff_run
./http_diff_run corpus/http_diff/smuggle_cl_te.http   # -> DIVERGENCE + abort
./http_diff_run corpus/http_diff/benign_get.http      # -> exit 0
```

> **macOS 26 / Darwin 25 note:** the current AddressSanitizer *runtime*
> infinite-loops during shadow-memory setup on this OS (a loop in
> `__sanitizer::MemoryMappingLayout::Next`), so ASan-instrumented binaries
> hang before `main`. This is an ASan runtime regression, not a bug in this
> target. UBSan is unaffected. The pytest auto-detects this and falls back to
> `-fsanitize=undefined`; on Linux or a healthy macOS toolchain the full
> `address,undefined` build is used.

## Corpus (`corpus/http_diff/`)

| Seed | Expected |
|------|----------|
| `smuggle_cl_te.http` | **Divergence** — both `Content-Length: 5` and `Transfer-Encoding: chunked`; A frames chunked (boundary +11), B frames CL (boundary +5) → `class=CL.TE`. |
| `benign_get.http` | No divergence (no body; both `UNTIL_CLOSE`). |
| `benign_post_cl.http` | No divergence (Content-Length only; both agree). |
| `benign_chunked.http` | No divergence (well-formed chunked, no CL; both agree). |
| `benign_get_headers.http` | No divergence (extra headers, no body). |

## Test

```sh
.venv/bin/python -m pytest tests/http_diff -q
```
