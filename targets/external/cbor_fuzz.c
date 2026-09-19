/* TinyCBOR decode fuzz target — a REAL serialization surface.
 *
 * CBOR (RFC 8949) decoders parse untrusted serialized input in COSE/CWT tokens,
 * WebAuthn/FIDO, and IoT. TinyCBOR (github.com/intel/tinycbor) and its siblings
 * (QCBOR, libcbor, msgpack-c — CVE-2026-72854) have thin/intermittent OSS-Fuzz
 * coverage. The CBOR major-type/length grammar is a natural structure-aware
 * target, and libcbor <-> tinycbor <-> QCBOR is the strongest serialization
 * differential (feed identical bytes, diff the decoded structure).
 *
 * Wired OFF by default; enable with -DTRIAGE_TARGET_CBOR=ON.
 */
#include <stddef.h>
#include <stdint.h>

#include "cbor.h"

#include "triage/fuzzer.h"

/* Recursively consume a CBOR value, bounded in depth, exercising the decoder. */
static void consume(CborValue *it, int depth) {
  if (depth > 128) return;
  while (!cbor_value_at_end(it)) {
    CborType t = cbor_value_get_type(it);
    if (t == CborArrayType || t == CborMapType) {
      CborValue inner;
      if (cbor_value_enter_container(it, &inner) != CborNoError) return;
      consume(&inner, depth + 1);
      if (cbor_value_leave_container(it, &inner) != CborNoError) return;
      continue;
    }
    if (t == CborTextStringType || t == CborByteStringType) {
      size_t n = 0;
      cbor_value_calculate_string_length(it, &n); /* touches length handling */
    }
    if (cbor_value_advance(it) != CborNoError) return;
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  CborParser parser;
  CborValue it;
  if (cbor_parser_init(data, size, 0, &parser, &it) != CborNoError) return 0;
  consume(&it, 0);
  return 0;
}
