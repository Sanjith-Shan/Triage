/* MFERF — "Mini Extensible Record Format", a deliberately vulnerable TLV parser.
 *
 * This is a SELF-AUTHORED teaching/demonstration target, not a real-world
 * library. It exists so the whole Triage pipeline (fuzz -> crash -> dedup ->
 * minimize -> classify -> detection rule -> regression test) runs end to end,
 * in CI, on any machine, with no network and no external dependencies. Its bugs
 * are PLANTED and DOCUMENTED (see mferf.c). Nothing found in mferf is a
 * real-world finding, and the README says so — real targets are the external
 * libraries wired via FetchContent (libcoap, CBOR, FreeType@CVE).
 *
 * Format (all multi-byte integers big-endian):
 *   magic[4] = "MFR1"
 *   u8  version
 *   u16 record_count
 *   record_count records, each:
 *     u8  type
 *     u32 length
 *     u8  value[length]
 *   types:
 *     0x01 STRING     value copied into a fixed name buffer   (MFERF-001)
 *     0x02 BLOB       value copied into a sized allocation     (MFERF-002)
 *     0x03 INDEX      value = u32 index, then data[]; reads data[index] (MFERF-003)
 *     0x04 RECYCLE    frees a child buffer, checksum reads it  (MFERF-004)
 *     0x10 CONTAINER  value is itself a record stream (nested) (MFERF-005)
 *
 * Build the vulnerable version by default; define MFERF_PATCHED for the fixed
 * version used by regression tests.
 */
#ifndef MFERF_H
#define MFERF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Set to 1 once a parse gets past the MFR1 header into the record loop. Used by
 * the mutator head-to-head to measure how often each mutator reaches deep code
 * instead of bouncing off the magic. Reset at the start of every mferf_parse. */
extern int mferf_reached;

/* Parse one MFERF buffer. Returns 0 on clean parse, negative on rejected input.
 * A memory-safety bug (in the unpatched build) aborts the process under ASan. */
int mferf_parse(const uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* MFERF_H */
