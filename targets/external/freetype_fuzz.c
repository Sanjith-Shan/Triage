/* FreeType face-load fuzz target — the SEEDED REDISCOVERY.
 *
 * FreeType is saturated on OSS-Fuzz, so this is NOT a fresh-discovery target. It
 * is pinned to a version BEFORE the fix for CVE-2025-27363 (an OOB write in the
 * TrueType subglyph parser, fixed in 2.13.3, exploited in the wild) so the
 * instrument can rediscover, minimize and classify a KNOWN bug on demand. This
 * guarantees a complete find -> triage -> classify narrative independent of
 * whether a novel bug appears in the fresh targets — the honesty mitigation from
 * SECURITY_FUZZ_SPEC.md ("a novel bug on a schedule is not guaranteed").
 *
 * FT_Load_Glyph reaches the TrueType composite-glyph path where the bug lives.
 * Enable with -DTRIAGE_TARGET_FREETYPE=ON (pins FreeType 2.13.0). See
 * docs/EXTERNAL_TARGETS.md. Never run against current FreeType and call it a find.
 */
#include <stddef.h>
#include <stdint.h>

#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_MULTIPLE_MASTERS_H

#include "triage/fuzzer.h"

static FT_Library g_lib;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  return FT_Init_FreeType(&g_lib);
}

/* Exercise the variable-font (GX/`gvar`) path — where CVE-2025-27363 lives — by
 * setting design coordinates derived from the input before loading glyphs. Only
 * fires for fonts that actually declare variation axes; a no-op otherwise. */
static void drive_variations(FT_Face face, const uint8_t *data, size_t size) {
  FT_MM_Var *mm = NULL;
  if (FT_Get_MM_Var(face, &mm) != 0 || mm == NULL) return;
  FT_UInt n = mm->num_axis;
  if (n > 16) n = 16;
  FT_Fixed coords[16];
  for (FT_UInt a = 0; a < n; a++) {
    FT_Fixed def = mm->axis[a].def;
    /* nudge each axis by an input-derived amount within its declared range */
    if (size) {
      uint8_t b = data[a % size];
      FT_Fixed span = mm->axis[a].maximum - mm->axis[a].minimum;
      coords[a] = mm->axis[a].minimum + (FT_Fixed)((span / 255) * b);
    } else {
      coords[a] = def;
    }
  }
  FT_Set_Var_Design_Coordinates(face, n, coords);
  FT_Done_MM_Var(g_lib, mm);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0 || size > 1024 * 1024) return 0;
  FT_Face face;
  if (FT_New_Memory_Face(g_lib, data, (FT_Long)size, 0, &face) != 0) return 0;
  FT_Set_Pixel_Sizes(face, 0, 16);
  drive_variations(face, data, size);          /* reaches ttgxvar / gvar parsing */
  FT_Long n = face->num_glyphs;
  if (n > 512) n = 512;
  for (FT_Long i = 0; i < n; i++)
    FT_Load_Glyph(face, (FT_UInt)i, FT_LOAD_RENDER); /* reaches subglyph parsing */
  FT_Done_Face(face);
  return 0;
}
