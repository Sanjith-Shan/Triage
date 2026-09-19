/* libcoap PDU-parse fuzz target — a REAL under-fuzzed network-protocol surface.
 *
 * libcoap (github.com/obgm/libcoap) parses CoAP messages off the wire for IoT
 * devices. Thin OSS-Fuzz coverage and a live 2024-2025 CVE stream (CVE-2025-34468
 * stack overflow, CVE-2025-65500 NULL deref, CVE-2024-0962 OSCORE overflow) make
 * it a strong fresh-discovery target. Option-delta/length TLV framing is exactly
 * the kind of structure a naive mutator bounces off, so a CoAP grammar model is
 * the structure-aware win here.
 *
 * Wired OFF by default; enable with -DTRIAGE_TARGET_LIBCOAP=ON (fetches and
 * builds libcoap, Linux campaign box). See docs/EXTERNAL_TARGETS.md.
 */
#include <stddef.h>
#include <stdint.h>

#include <coap3/coap.h>

#include "triage/fuzzer.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0 || size > 64 * 1024) return 0;
  coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_CON, 0, 0, (size_t)size + 16);
  if (!pdu) return 0;
  /* Parse an untrusted datagram as a CoAP PDU — the attacker-reachable path. */
  coap_pdu_parse(COAP_PROTO_UDP, data, size, pdu);
  coap_delete_pdu(pdu);
  return 0;
}
