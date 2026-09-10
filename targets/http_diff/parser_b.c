/*
 * parser_b.c -- "lenient" HTTP/1.1 request framing parser.
 *
 * Written from scratch, independent of parser_a. Also fully bounds-checked
 * and terminating. Its rules are deliberately looser so that, on smuggling
 * shaped inputs, it frames the message differently from parser_a:
 *
 *   - CL WINS: if a Content-Length is present it is used even when
 *     Transfer-Encoding: chunked is also present (opposite of parser_a).
 *   - Duplicate Content-Length is tolerated; the FIRST value is kept.
 *   - Chunk parsing is sloppy: a single leading space before the size is
 *     tolerated, anything after the hex digits up to CRLF (chunk-extensions,
 *     trailing junk) is ignored, a bare LF is accepted as a line end, and an
 *     unparseable / missing chunk size is treated as end-of-body (size 0).
 *   - An obs-fold-ish header line beginning with SP/HTAB is tolerated and
 *     folded onto the previous header (here: simply skipped).
 */
#include "parser_b.h"

static int pb_lc(int c) {
    return (c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c;
}

static bool pb_name_eq(const unsigned char *p, size_t n, const char *lit) {
    size_t i = 0;
    for (; i < n; i++) {
        if (lit[i] == '\0') return false;
        if (pb_lc(p[i]) != pb_lc((unsigned char)lit[i])) return false;
    }
    return lit[i] == '\0';
}

/* Lenient line end finder: returns the index of a line-ending byte at or
 * after `from`, treating either CRLF or a bare LF as a terminator. *lf_len is
 * set to the length of the terminator (2 for CRLF, 1 for a lone LF). Returns
 * `size` if no terminator is found. */
static size_t pb_find_eol(const unsigned char *d, size_t size, size_t from,
                          size_t *lf_len) {
    for (size_t i = from; i < size; i++) {
        if (d[i] == '\n') {
            if (i > from && d[i - 1] == '\r') {
                /* position at the '\r' so the caller sees a 2-byte CRLF */
                *lf_len = 2;
                return i - 1;
            }
            *lf_len = 1;
            return i;
        }
    }
    return size;
}

static int pb_hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/*
 * Sloppy chunked scan. Always terminates. Sets *end_out to where the lenient
 * parser thinks the chunked body ends. Returns true on a "good enough" parse.
 * The looseness here is exactly what produces TE.TE divergences against the
 * strict scanner.
 */
static bool pb_scan_chunked(const unsigned char *d, size_t size, size_t start,
                            size_t *end_out) {
    size_t pos = start;
    for (;;) {
        /* Lenient: tolerate a single leading space before the size. */
        if (pos < size && d[pos] == ' ') pos++;

        size_t lf_len = 0;
        size_t eol = pb_find_eol(d, size, pos, &lf_len);
        if (eol == size) {
            /* No line terminator: treat wherever we are as the end. */
            *end_out = size;
            return true;
        }

        /* Read leading hex digits; ignore everything else up to EOL. */
        unsigned long long csize = 0;
        int ndig = 0;
        size_t i = pos;
        while (i < eol) {
            int v = pb_hexval(d[i]);
            if (v < 0) break;                 /* stop at first non-hex byte  */
            if (csize <= (~0ULL >> 4)) {
                csize = (csize << 4) | (unsigned)v;
            }
            i++;
            ndig++;
        }
        /* Lenient: an unparseable size line is treated as the final chunk. */
        if (ndig == 0) csize = 0;

        size_t after_size_line = eol + lf_len; /* first byte after size line */

        if (csize == 0) {
            /* End of body. Consume an optional trailing empty line if the
             * very next bytes form one, otherwise stop right here. */
            size_t p = after_size_line;
            if (p + 1 < size && d[p] == '\r' && d[p + 1] == '\n') p += 2;
            else if (p < size && d[p] == '\n') p += 1;
            *end_out = p;
            return true;
        }

        /* Skip csize data bytes, but never past the end of the buffer. */
        if (csize > size - after_size_line) {
            *end_out = size;                  /* truncated: consume the rest  */
            return true;
        }
        size_t p = after_size_line + (size_t)csize;
        /* Tolerantly skip a trailing line end after the data if present. */
        if (p + 1 < size && d[p] == '\r' && d[p + 1] == '\n') p += 2;
        else if (p < size && d[p] == '\n') p += 1;
        pos = p;
    }
}

pb_result_t parser_b_parse(const unsigned char *data, size_t size) {
    pb_result_t r = {false, PB_MODE_ERROR, 0, 0};

    if (data == NULL || size == 0) return r;

    /* Request line up to the first line end (CRLF or bare LF). */
    size_t lf_len = 0;
    size_t rl = pb_find_eol(data, size, 0, &lf_len);
    if (rl == size) return r;
    size_t pos = rl + lf_len;

    bool               have_cl = false;
    unsigned long long cl_value = 0;
    bool               have_te_chunked = false;

    for (;;) {
        /* Blank line (CRLF or bare LF) ends the header block. */
        if (pos + 1 < size && data[pos] == '\r' && data[pos + 1] == '\n') {
            pos += 2;
            break;
        }
        if (pos < size && data[pos] == '\n') {
            pos += 1;
            break;
        }

        size_t hl = 0;
        size_t eol = pb_find_eol(data, size, pos, &hl);
        if (eol == size) return r;             /* unterminated headers       */

        /* Lenient obs-fold: a line starting with SP/HTAB is folded onto the
         * previous header. We simply skip it (do not re-scan for CL/TE). */
        if (data[pos] == ' ' || data[pos] == '\t') {
            pos = eol + hl;
            continue;
        }

        size_t colon = pos;
        while (colon < eol && data[colon] != ':') colon++;
        if (colon == eol) {                    /* no colon: skip the line    */
            pos = eol + hl;
            continue;
        }
        size_t name_len = colon - pos;

        size_t vstart = colon + 1;
        while (vstart < eol && (data[vstart] == ' ' || data[vstart] == '\t'))
            vstart++;
        size_t vend = eol;
        while (vend > vstart &&
               (data[vend - 1] == ' ' || data[vend - 1] == '\t'))
            vend--;

        if (name_len > 0 &&
            pb_name_eq(data + pos, name_len, "content-length")) {
            if (!have_cl) {                    /* keep the FIRST CL          */
                unsigned long long v = 0;
                /* Lenient: parse leading digits, ignore any trailing junk. */
                size_t i = vstart;
                for (; i < vend; i++) {
                    if (data[i] < '0' || data[i] > '9') break;
                    if (v <= (~0ULL - 9) / 10) v = v * 10 + (unsigned)(data[i] - '0');
                }
                have_cl = true;
                cl_value = v;
            }
        } else if (name_len > 0 &&
                   pb_name_eq(data + pos, name_len, "transfer-encoding")) {
            /* Lenient: if "chunked" appears anywhere in the value, note it. */
            for (size_t i = vstart; i + 7 <= vend; i++) {
                if (pb_name_eq(data + i, 7, "chunked")) {
                    have_te_chunked = true;
                    break;
                }
            }
        }

        pos = eol + hl;
    }

    size_t header_end = pos;

    /* Framing decision. LENIENT RULE: Content-Length WINS over chunked. */
    if (have_cl) {
        if (cl_value > size - header_end) {
            /* Lenient: clamp a too-large CL to the available bytes rather
             * than erroring, so the boundary is still defined. */
            r.parse_ok = true;
            r.mode = PB_MODE_CONTENT_LENGTH;
            r.content_length = size - header_end;
            r.boundary_off = size;
            return r;
        }
        r.parse_ok = true;
        r.mode = PB_MODE_CONTENT_LENGTH;
        r.content_length = (size_t)cl_value;
        r.boundary_off = header_end + (size_t)cl_value;
        return r;
    }
    if (have_te_chunked) {
        size_t end;
        (void)pb_scan_chunked(data, size, header_end, &end);
        r.parse_ok = true;
        r.mode = PB_MODE_CHUNKED;
        r.boundary_off = end;
        return r;
    }

    r.parse_ok = true;
    r.mode = PB_MODE_UNTIL_CLOSE;
    r.boundary_off = size;
    return r;
}
