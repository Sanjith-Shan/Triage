/*
 * diff_driver.c -- differential fuzzing driver for HTTP/1.1 request framing.
 *
 * Defines the standard libFuzzer entry point LLVMFuzzerTestOneInput and
 * NOTHING that would collide with a `main`. The parent project provides
 * `main` separately (a standalone corpus-replay runner on macOS/ASan, or the
 * real libFuzzer runtime on Linux), so this translation unit is deliberately
 * main-free.
 *
 * THE ORACLE (important):
 *   We run two independent framing parsers (parser_a = strict, parser_b =
 *   lenient) on the SAME bytes and compare how each frames the request: its
 *   framing MODE and, crucially, the BOUNDARY OFFSET where it believes the
 *   first request ends and the next begins. If both parsed successfully but
 *   disagree, that is a request-smuggling / desync PRIMITIVE: two nodes on a
 *   connection would split the same byte stream into different requests.
 *
 *   A differential fuzzer needs a *crash* to signal "interesting", because
 *   that is the only channel libFuzzer / a crash-replay runner records. So we
 *   print a structured, greppable DIVERGENCE report to stderr and call
 *   abort(). "abort == divergence found" is an intentional convention, not a
 *   bug in this code. No divergence -> return 0 (the input is uninteresting).
 *
 * This driver is itself memory-safe: it forwards the caller's (data, size)
 * unchanged and does no unchecked indexing.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "parser_a.h"
#include "parser_b.h"

/* Human-readable framing-mode names for the report. The two enums are kept
 * separate (independent parsers) but share the same ordering. */
static const char *mode_a_name(pa_mode_t m) {
    switch (m) {
        case PA_MODE_CONTENT_LENGTH: return "CL";
        case PA_MODE_CHUNKED:        return "CHUNKED";
        case PA_MODE_UNTIL_CLOSE:    return "UNTIL_CLOSE";
        default:                     return "ERROR";
    }
}
static const char *mode_b_name(pb_mode_t m) {
    switch (m) {
        case PB_MODE_CONTENT_LENGTH: return "CL";
        case PB_MODE_CHUNKED:        return "CHUNKED";
        case PB_MODE_UNTIL_CLOSE:    return "UNTIL_CLOSE";
        default:                     return "ERROR";
    }
}

/*
 * Classify the divergence into the standard smuggling taxonomy so findings
 * are triage-friendly:
 *   CL.TE  - one parser frames by Content-Length, the other by chunked TE.
 *            (The canonical smuggling class: CL vs TE disagreement.)
 *   TE.TE  - both frame by chunked but disagree on the boundary (sloppy vs
 *            strict chunk parsing).
 *   CL.CL  - both frame by Content-Length but disagree on the value/boundary.
 *   MODE_DIFF / BOUNDARY_DIFF - any other mode or offset disagreement.
 */
static const char *classify(pa_result_t a, pb_result_t b) {
    int a_cl  = (a.mode == PA_MODE_CONTENT_LENGTH);
    int a_ch  = (a.mode == PA_MODE_CHUNKED);
    int b_cl  = (b.mode == PB_MODE_CONTENT_LENGTH);
    int b_ch  = (b.mode == PB_MODE_CHUNKED);

    if ((a_cl && b_ch) || (a_ch && b_cl)) return "CL.TE";
    if (a_ch && b_ch)                     return "TE.TE";
    if (a_cl && b_cl)                     return "CL.CL";

    /* Same mode enum value but different boundary, or any other mismatch. */
    if ((int)a.mode == (int)b.mode)       return "BOUNDARY_DIFF";
    return "MODE_DIFF";
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Both parsers are read-only and bounds-safe; pass bytes straight through.
     * A NULL/zero input is simply uninteresting. */
    pa_result_t a = parser_a_parse((const unsigned char *)data, size);
    pb_result_t b = parser_b_parse((const unsigned char *)data, size);

    /* Only compare when BOTH parsers accepted the request. If either rejects,
     * there is no shared "this is a valid request" agreement to violate, so we
     * do not treat it as a framing divergence. */
    if (!a.parse_ok || !b.parse_ok) return 0;

    int mode_diff     = ((int)a.mode != (int)b.mode);
    int boundary_diff = (a.boundary_off != b.boundary_off);
    if (!mode_diff && !boundary_diff) return 0;   /* agreement -> boring */

    /* Divergence. Emit a single-line, greppable report, then abort so the
     * runner records this input as a finding. */
    const char *cls = classify(a, b);
    fprintf(stderr,
            "DIVERGENCE: A=%s:%zu boundary=%zu | B=%s:%zu boundary=%zu | class=%s\n",
            mode_a_name(a.mode), a.content_length, a.boundary_off,
            mode_b_name(b.mode), b.content_length, b.boundary_off,
            cls);
    fflush(stderr);
    abort();

    return 0; /* unreachable; keeps some compilers/linters happy */
}
