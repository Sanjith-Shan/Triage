/* MFERF fuzz driver + structure-aware mutator.
 *
 * LLVMFuzzerTestOneInput feeds bytes to mferf_parse. LLVMFuzzerCustomMutator is
 * a grammar-aware mutator that keeps the MFR1 framing valid while corrupting one
 * field at a time, so mutations reach the deep record handlers instead of
 * bouncing off the magic. The naive-vs-structured comparison (scripts/
 * compare_mutators.sh) measures what that buys: runs-to-first-crash and unique
 * bugs found, naive byte-flipping vs this. Same move as Basalt's vectorized-vs-
 * row-at-a-time and NanoExchange's four hash tables — the numbers pick the winner.
 */
#include <stdlib.h>
#include <string.h>

#include "mferf.h"
#include "triage/fuzzer.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  mferf_parse(data, size);
  return 0;
}

/* Reach hook (see mferf.h / standalone runner --reach mode): did the last input
 * get past the MFR1 header into the record handlers? */
int LLVMFuzzerReached(void) { return mferf_reached; }

static void wr_u32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

/* Interesting 32-bit length values: boundaries where integer bugs live. */
static const uint32_t kInteresting[] = {
  0u, 1u, 2u, 4u, 31u, 32u, 33u, 63u, 64u, 65u, 255u, 256u, 4095u, 4096u,
  0x7fffffffu, 0x80000000u, 0xfffffffeu, 0xffffffffu,
};
static const uint8_t kTypes[] = { 0x01, 0x02, 0x03, 0x04, 0x10, 0x7f };

/* Walk the record framing; on the `target`-th record, apply a mutation to its
 * type or length. Returns possibly-changed size. Framing (magic/version/count)
 * is preserved so the mutant stays a valid MFERF stream skeleton. */
size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                               unsigned int seed) {
  /* If it's not even a header, make it one so we always reach the parser body. */
  if (size < 7 || memcmp(data, "MFR1", 4) != 0) {
    if (max_size < 12) return size;
    memcpy(data, "MFR1", 4);
    data[4] = 1;           /* version */
    data[5] = 0; data[6] = 1; /* record_count = 1 */
    data[7] = kTypes[seed % (sizeof kTypes)];
    wr_u32(data + 8, kInteresting[(seed >> 3) % (sizeof kInteresting / 4)]);
    return 12;
  }

  unsigned int rng = seed;
  uint16_t count = (uint16_t)((data[5] << 8) | data[6]);

  /* Occasionally bump the record count to explore more records / nesting. */
  if ((rng & 7) == 0 && count < 0xffff) {
    count++;
    data[5] = (uint8_t)(count >> 8);
    data[6] = (uint8_t)count;
  }

  /* Walk to a random record header and mutate it. */
  size_t pos = 7;
  int target = count ? (int)(rng % count) : 0;
  int idx = 0;
  while (pos + 5 <= size && idx <= target) {
    uint8_t *hdr = data + pos;
    uint32_t length = ((uint32_t)hdr[1] << 24) | ((uint32_t)hdr[2] << 16) |
                      ((uint32_t)hdr[3] << 8) | hdr[4];
    if (idx == target) {
      int what = (rng >> 3) % 3;
      if (what == 0) {
        hdr[0] = kTypes[(rng >> 5) % (sizeof kTypes)];       /* flip type */
      } else if (what == 1) {
        wr_u32(hdr + 1, kInteresting[(rng >> 5) %            /* boundary length */
                                     (sizeof kInteresting / 4)]);
      } else if (pos + 5 + 4 <= max_size) {                  /* grow value a little */
        size_t insert = 4;
        if (size + insert <= max_size) {
          memmove(data + pos + 5 + insert, data + pos + 5, size - (pos + 5));
          memset(data + pos + 5, (int)(rng & 0xff), insert);
          size += insert;
          wr_u32(hdr + 1, length + (uint32_t)insert);
        }
      }
      break;
    }
    /* advance past this record's value (bounded by remaining bytes) */
    size_t avail = size - (pos + 5);
    pos += 5 + (length < avail ? length : avail);
    idx++;
  }
  return size;
}
