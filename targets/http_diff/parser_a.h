/*
 * parser_a.h -- "strict-ish" HTTP/1.1 request framing parser.
 *
 * This parser models an RFC-7230-leaning implementation: when both
 * Content-Length (CL) and Transfer-Encoding (TE) are present it treats TE
 * (chunked) as authoritative, parses chunk sizes strictly, and rejects a
 * number of malformed constructs. It is one half of a DIFFERENTIAL fuzzing
 * pair; the other half (parser_b) is deliberately more permissive so that
 * the two disagree on request framing for smuggling-relevant inputs.
 *
 * The parser only *reports* how it would frame the message; it never mutates
 * or trusts the buffer beyond bounds-checked reads. It must be memory-safe
 * under ASan/UBSan for arbitrary attacker-controlled bytes.
 */
#ifndef HTTP_DIFF_PARSER_A_H
#define HTTP_DIFF_PARSER_A_H

#include <stdbool.h>
#include <stddef.h>

/* How parser A decides where the body ends. */
typedef enum {
    PA_MODE_ERROR = 0,      /* parse failed under parser A's rules      */
    PA_MODE_CONTENT_LENGTH, /* framed by a Content-Length value         */
    PA_MODE_CHUNKED,        /* framed by Transfer-Encoding: chunked     */
    PA_MODE_UNTIL_CLOSE     /* no length framing; body runs to EOF/close */
} pa_mode_t;

typedef struct {
    bool      parse_ok;      /* true iff the request parsed under A's rules */
    pa_mode_t mode;          /* resolved framing mode                       */
    size_t    content_length;/* valid only when mode == PA_MODE_CONTENT_LENGTH */
    /*
     * boundary_off: the byte offset at which parser A believes the FIRST
     * request ends and the next one (if any) begins. This is the
     * smuggling-relevant quantity: two parsers that disagree on this offset
     * disagree on how to segment a connection's byte stream.
     *
     * Only meaningful when parse_ok is true. For UNTIL_CLOSE it equals the
     * total buffer size (the request consumes the rest of the stream).
     */
    size_t    boundary_off;
} pa_result_t;

/* Parse a single HTTP/1.1 request from data[0..size). Never reads OOB. */
pa_result_t parser_a_parse(const unsigned char *data, size_t size);

#endif /* HTTP_DIFF_PARSER_A_H */
