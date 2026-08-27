/* MFERF parser — see mferf.h. Vulnerable by default; MFERF_PATCHED = fixed.
 *
 * Each planted bug is marked with its ID. The vulnerable and patched paths sit
 * side by side so a regression test can build both and prove the fix: the test
 * inputs abort the process on the unpatched build and parse cleanly on the
 * patched one (the "verified against the unpatched code" discipline).
 */
#include "mferf.h"

#include <stdlib.h>
#include <string.h>

#define MFERF_MAX_DEPTH 64

static uint16_t rd_u16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd_u32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* A minimal cursor over the input. */
typedef struct {
  const uint8_t *buf;
  size_t len;
  size_t pos;
} cur_t;

static int cur_need(cur_t *c, size_t n) { return c->pos + n <= c->len; }

static int parse_records(cur_t *c, uint16_t count, int depth);

/* ---- type 0x01 STRING ---- MFERF-001 stack-buffer-overflow (WRITE) ---- */
static int rec_string(cur_t *c, uint32_t length) {
  char name[32];
  size_t avail = c->len - c->pos;
  size_t take = length < avail ? length : avail;
#ifdef MFERF_PATCHED
  if (take >= sizeof(name)) take = sizeof(name) - 1;
  memcpy(name, c->buf + c->pos, take);
  name[take] = '\0';
#else
  /* BUG MFERF-001: `take` can exceed sizeof(name); no bound before memcpy.
   * Overflows the 32-byte stack buffer. CWE-121. */
  memcpy(name, c->buf + c->pos, take);
  name[take < sizeof(name) ? take : sizeof(name) - 1] = '\0';
#endif
  c->pos += (length < avail ? length : avail);
  (void)name;
  return 0;
}

/* ---- type 0x02 BLOB ---- MFERF-002 heap-buffer-overflow via int overflow ---- */
static int rec_blob(cur_t *c, uint32_t length) {
  size_t avail = c->len - c->pos;
  size_t take = length < avail ? length : avail;
#ifdef MFERF_PATCHED
  size_t cap = (size_t)length + 1; /* size_t: no 32-bit wrap */
  uint8_t *p = (uint8_t *)malloc(cap);
  if (!p) return -1;
  memcpy(p, c->buf + c->pos, take);
  p[take] = 0;
#else
  /* BUG MFERF-002: cap computed in uint32_t. length = 0xFFFFFFFF wraps cap to 0,
   * malloc(0) returns a minimal chunk, memcpy of `take` bytes overflows it.
   * CWE-190 -> CWE-122. */
  uint32_t cap = length + 1;
  uint8_t *p = (uint8_t *)malloc(cap);
  if (!p) return -1;
  memcpy(p, c->buf + c->pos, take);
#endif
  free(p);
  c->pos += take;
  return 0;
}

/* ---- type 0x03 INDEX ---- MFERF-003 heap-buffer-overflow (READ) ---- */
static int rec_index(cur_t *c, uint32_t length) {
  if (length < 4) { c->pos += (length < (c->len - c->pos) ? length : (c->len - c->pos)); return -1; }
  size_t avail = c->len - c->pos;
  size_t take = length < avail ? length : avail;
  if (take < 4) { c->pos += take; return -1; }
  uint32_t index = rd_u32(c->buf + c->pos);
  size_t data_len = take - 4;
  uint8_t *data = (uint8_t *)malloc(data_len ? data_len : 1);
  memcpy(data, c->buf + c->pos + 4, data_len);
  volatile uint8_t sink;
#ifdef MFERF_PATCHED
  if (index < data_len)
    sink = data[index];
  else
    sink = 0;
#else
  /* BUG MFERF-003: `index` is attacker-controlled and never bounds-checked
   * against data_len. Out-of-bounds heap READ. CWE-125. */
  sink = data[index];
#endif
  (void)sink;
  free(data);
  c->pos += take;
  return 0;
}

/* ---- type 0x04 RECYCLE ---- MFERF-004 heap-use-after-free (READ) ---- */
static int rec_recycle(cur_t *c, uint32_t length) {
  size_t avail = c->len - c->pos;
  size_t take = length < avail ? length : avail;
  uint8_t *child = (uint8_t *)malloc(take ? take : 1);
  memcpy(child, c->buf + c->pos, take);
  /* "recycle": the record is dropped to save memory... */
  free(child);
  volatile uint8_t checksum = 0;
#ifdef MFERF_PATCHED
  /* Fixed: checksum computed before free, or child kept alive. Here: no read. */
  (void)child;
#else
  /* BUG MFERF-004: a trailing "integrity" pass reads the freed buffer.
   * Heap use-after-free READ. CWE-416. */
  for (size_t i = 0; i < take; i++) checksum = (uint8_t)(checksum + child[i]);
#endif
  (void)checksum;
  c->pos += take;
  return 0;
}

/* ---- type 0x10 CONTAINER ---- MFERF-005 stack-overflow (unbounded recursion) */
static int rec_container(cur_t *c, uint32_t length, int depth) {
  size_t avail = c->len - c->pos;
  size_t take = length < avail ? length : avail;
  if (take < 2) { c->pos += take; return -1; }
  uint16_t inner_count = rd_u16(c->buf + c->pos);
  cur_t inner = { c->buf + c->pos + 2, take - 2, 0 };
#ifdef MFERF_PATCHED
  if (depth + 1 >= MFERF_MAX_DEPTH) { c->pos += take; return -1; }
  parse_records(&inner, inner_count, depth + 1);
#else
  /* BUG MFERF-005: no recursion depth limit. Deeply nested containers exhaust
   * the stack. CWE-674 (uncontrolled recursion) -> stack-overflow. */
  parse_records(&inner, inner_count, depth + 1);
#endif
  c->pos += take;
  return 0;
}

int mferf_reached = 0;

static int parse_records(cur_t *c, uint16_t count, int depth) {
  mferf_reached = 1; /* got past the header into the record loop */
  for (uint16_t i = 0; i < count; i++) {
    if (!cur_need(c, 1 + 4)) return -1;
    uint8_t type = c->buf[c->pos];
    uint32_t length = rd_u32(c->buf + c->pos + 1);
    c->pos += 5;
    switch (type) {
      case 0x01: rec_string(c, length); break;
      case 0x02: rec_blob(c, length); break;
      case 0x03: rec_index(c, length); break;
      case 0x04: rec_recycle(c, length); break;
      case 0x10: rec_container(c, length, depth); break;
      default: {
        /* skip unknown record's value */
        size_t avail = c->len - c->pos;
        c->pos += (length < avail ? length : avail);
        break;
      }
    }
  }
  return 0;
}

int mferf_parse(const uint8_t *data, size_t size) {
  cur_t c = { data, size, 0 };
  if (!cur_need(&c, 4) || memcmp(data, "MFR1", 4) != 0) return -1;
  c.pos += 4;
  if (!cur_need(&c, 1)) return -1;
  c.pos += 1; /* version */
  if (!cur_need(&c, 2)) return -1;
  uint16_t count = rd_u16(c.buf + c.pos);
  c.pos += 2;
  return parse_records(&c, count, 0);
}
