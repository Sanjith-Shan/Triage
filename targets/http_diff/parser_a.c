/*
 * parser_a.c -- "strict-ish" HTTP/1.1 request framing parser.
 *
 * Written from scratch (no external libraries). Every buffer access is
 * bounds-checked against `size`; the parser never advances past the end of
 * the input and every loop makes forward progress, so it is memory-safe and
 * terminating for arbitrary attacker-controlled bytes.
 *
 * Strict rules (contrast with parser_b, the lenient twin):
 *   - Header names compared case-insensitively.
 *   - Duplicate Content-Length  -> hard error (RFC 7230 3.3.3 forbids it).
 *   - Content-Length value must be all decimal digits, no overflow.
 *   - If Transfer-Encoding: chunked is present, TE is AUTHORITATIVE and wins
 *     over any Content-Length (RFC 7230 3.3.3 rule 3: TE overrides CL).
 *   - Chunk sizes must be pure hex; chunk-extensions (';...') are rejected;
 *     a size line must be terminated by CRLF; each chunk's data must be
 *     followed by CRLF. Any deviation -> error.
 *   - A header line that begins with SP/HTAB (obs-fold) is rejected.
 */
#include "parser_a.h"

/* ---- small byte helpers (all bounds-safe) ------------------------------ */

static int pa_lc(int c) {
    return (c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c;
}

/* Case-insensitive compare of a header name span against a NUL-terminated
 * literal. Returns true on exact (case-insensitive) match. */
static bool pa_name_eq(const unsigned char *p, size_t n, const char *lit) {
    size_t i = 0;
    for (; i < n; i++) {
        if (lit[i] == '\0') return false;
        if (pa_lc(p[i]) != pa_lc((unsigned char)lit[i])) return false;
    }
    return lit[i] == '\0';
}

/* Find the next CRLF at or after `from`. Returns the index of the '\r' of the
 * CRLF, or `size` if none is found. Requires a literal CRLF (not a bare LF),
 * matching the strict parser's line discipline. */
static size_t pa_find_crlf(const unsigned char *d, size_t size, size_t from) {
    for (size_t i = from; i + 1 < size; i++) {
        if (d[i] == '\r' && d[i + 1] == '\n') return i;
    }
    return size;
}

static int pa_hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* ---- chunked body framing --------------------------------------------- */

/*
 * Parse a strict chunked body starting at data[start..size). On success sets
 * *end_out to the offset just past the terminating "0\r\n\r\n" and returns
 * true. Returns false (and leaves *end_out untouched) on any malformation or
 * truncation.
 */
static bool pa_scan_chunked(const unsigned char *d, size_t size, size_t start,
                            size_t *end_out) {
    size_t pos = start;
    for (;;) {
        /* Read at least one hex digit for the chunk size. */
        size_t hs = pos;
        unsigned long long csize = 0;
        int ndig = 0;
        while (pos < size) {
            int v = pa_hexval(d[pos]);
            if (v < 0) break;
            /* Guard against unsigned overflow of the running size. */
            if (csize > (~0ULL >> 4)) return false;
            csize = (csize << 4) | (unsigned)v;
            pos++;
            ndig++;
        }
        if (ndig == 0) return false;              /* no hex digits           */
        (void)hs;
        /* Strict: the size must be followed immediately by CRLF. A chunk
         * extension (';') or any other trailing byte is rejected. */
        if (pos + 1 >= size) return false;        /* need CRLF               */
        if (d[pos] != '\r' || d[pos + 1] != '\n') return false;
        pos += 2;

        if (csize == 0) {
            /* Last chunk. A single empty trailer line (CRLF) must follow. */
            if (pos + 1 >= size) return false;
            if (d[pos] != '\r' || d[pos + 1] != '\n') return false;
            pos += 2;
            *end_out = pos;
            return true;
        }

        /* Data of exactly csize bytes, then a CRLF. Bounds-check the add. */
        if (csize > size - pos) return false;     /* truncated chunk data    */
        pos += (size_t)csize;
        if (pos + 1 >= size) return false;        /* need trailing CRLF      */
        if (d[pos] != '\r' || d[pos + 1] != '\n') return false;
        pos += 2;
    }
}

/* ---- entry point ------------------------------------------------------- */

pa_result_t parser_a_parse(const unsigned char *data, size_t size) {
    pa_result_t r = {false, PA_MODE_ERROR, 0, 0};

    if (data == NULL || size == 0) return r;

    /* Request line: everything up to the first CRLF. Must exist. */
    size_t rl = pa_find_crlf(data, size, 0);
    if (rl == size) return r;                 /* no request line terminator  */
    size_t pos = rl + 2;

    bool               have_cl = false;
    unsigned long long cl_value = 0;
    bool               have_te_chunked = false;

    /* Header lines until a blank line (bare CRLF). */
    for (;;) {
        if (pos + 1 < size && data[pos] == '\r' && data[pos + 1] == '\n') {
            pos += 2;                          /* end of headers             */
            break;
        }
        size_t eol = pa_find_crlf(data, size, pos);
        if (eol == size) return r;             /* unterminated header block  */

        /* Strict: reject obs-fold (line starting with SP/HTAB). */
        if (data[pos] == ' ' || data[pos] == '\t') return r;

        /* Split "Name: Value" at the first colon within the line. */
        size_t colon = pos;
        while (colon < eol && data[colon] != ':') colon++;
        if (colon == eol) return r;            /* header without a colon     */
        size_t name_len = colon - pos;
        if (name_len == 0) return r;

        /* Trim leading OWS from the value; value span is [vstart, eol). */
        size_t vstart = colon + 1;
        while (vstart < eol && (data[vstart] == ' ' || data[vstart] == '\t'))
            vstart++;
        size_t vend = eol;
        while (vend > vstart &&
               (data[vend - 1] == ' ' || data[vend - 1] == '\t'))
            vend--;

        if (pa_name_eq(data + pos, name_len, "content-length")) {
            if (have_cl) return r;             /* duplicate CL -> reject     */
            if (vstart == vend) return r;      /* empty value                */
            unsigned long long v = 0;
            for (size_t i = vstart; i < vend; i++) {
                if (data[i] < '0' || data[i] > '9') return r; /* non-digit   */
                if (v > (~0ULL - 9) / 10) return r;           /* overflow    */
                v = v * 10 + (unsigned)(data[i] - '0');
            }
            have_cl = true;
            cl_value = v;
        } else if (pa_name_eq(data + pos, name_len, "transfer-encoding")) {
            /* Consider the last token; strict parser only understands
             * "chunked". If the value's final coding is chunked, mark it. */
            /* Find the last comma-separated token. */
            size_t tstart = vstart;
            for (size_t i = vstart; i < vend; i++) {
                if (data[i] == ',') tstart = i + 1;
            }
            while (tstart < vend &&
                   (data[tstart] == ' ' || data[tstart] == '\t'))
                tstart++;
            if (pa_name_eq(data + tstart, vend - tstart, "chunked"))
                have_te_chunked = true;
        }

        pos = eol + 2;
    }

    size_t header_end = pos;    /* first body byte offset */

    /* Framing decision. STRICT RULE: TE (chunked) takes precedence over CL. */
    if (have_te_chunked) {
        size_t end;
        if (!pa_scan_chunked(data, size, header_end, &end)) return r;
        r.parse_ok = true;
        r.mode = PA_MODE_CHUNKED;
        r.boundary_off = end;
        return r;
    }
    if (have_cl) {
        /* Body is exactly cl_value bytes. It must fit in the buffer for the
         * boundary to be well-defined; if truncated we report an error. */
        if (cl_value > size - header_end) return r;
        r.parse_ok = true;
        r.mode = PA_MODE_CONTENT_LENGTH;
        r.content_length = (size_t)cl_value;
        r.boundary_off = header_end + (size_t)cl_value;
        return r;
    }

    /* No length framing: the request body runs until the connection closes,
     * i.e. it consumes the remainder of this buffer. */
    r.parse_ok = true;
    r.mode = PA_MODE_UNTIL_CLOSE;
    r.boundary_off = size;
    return r;
}
