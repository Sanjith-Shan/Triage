/*
 * parser_b.h -- "lenient" HTTP/1.1 request framing parser.
 *
 * This parser models a permissive server/proxy. Its rules are intentionally
 * different from parser_a so that the differential driver can surface genuine
 * CL.TE / TE.CL / TE.TE framing divergences -- the raw material of HTTP
 * request smuggling / desync. Key intentional differences vs parser_a:
 *
 *   - Prefers Content-Length even when Transfer-Encoding is also present
 *     (CL wins), the opposite of parser_a's TE-wins rule.
 *   - Accepts duplicate Content-Length headers (uses the first).
 *   - Sloppy chunk parsing: tolerates a leading space before the size,
 *     ignores chunk-extensions / trailing junk after the size, and treats an
 *     unparseable chunk size as end-of-body (size 0) rather than an error.
 *   - Tolerates an obs-fold-ish header line beginning with a space/tab.
 *
 * Like parser_a it is read-only and must be memory-safe under ASan/UBSan.
 */
#ifndef HTTP_DIFF_PARSER_B_H
#define HTTP_DIFF_PARSER_B_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    PB_MODE_ERROR = 0,
    PB_MODE_CONTENT_LENGTH,
    PB_MODE_CHUNKED,
    PB_MODE_UNTIL_CLOSE
} pb_mode_t;

typedef struct {
    bool      parse_ok;
    pb_mode_t mode;
    size_t    content_length;
    size_t    boundary_off;   /* see parser_a.h for the exact meaning */
} pb_result_t;

pb_result_t parser_b_parse(const unsigned char *data, size_t size);

#endif /* HTTP_DIFF_PARSER_B_H */
