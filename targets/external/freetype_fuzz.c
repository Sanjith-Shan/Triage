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

#include "triage/fuzzer.h"

static FT_Library g_lib;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  return FT_Init_FreeType(&g_lib);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0 || size > 1024 * 1024) return 0;
  FT_Face face;
  if (FT_New_Memory_Face(g_lib, data, (FT_Long)size, 0, &face) != 0) return 0;
  FT_Set_Pixel_Sizes(face, 0, 16);
  FT_Long n = face->num_glyphs;
  if (n > 512) n = 512;
  for (FT_Long i = 0; i < n; i++)
    FT_Load_Glyph(face, (FT_UInt)i, FT_LOAD_RENDER); /* reaches subglyph parsing */
  FT_Done_Face(face);
  return 0;
}
