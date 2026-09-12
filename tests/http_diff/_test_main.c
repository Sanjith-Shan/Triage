/*
 * _test_main.c -- TINY standalone runner, FOR THE PYTEST ONLY.
 *
 * The production build gets its `main` from the parent project (a crash-replay
 * runner on macOS/ASan, or real libFuzzer on Linux). This file exists solely
 * so the test can compile the target into a self-contained executable on a
 * machine that has ASan/UBSan but no libFuzzer runtime.
 *
 * It reads a single file argument, slurps its bytes, and hands them to
 * LLVMFuzzerTestOneInput exactly once. If that function aborts (a divergence
 * was found) the process dies with SIGABRT; otherwise it exits 0.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
        return 2;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\n", argv[1]);
        return 2;
    }

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 2; }
    long len = ftell(f);
    if (len < 0) { fclose(f); return 2; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return 2; }

    uint8_t *buf = NULL;
    if (len > 0) {
        buf = (uint8_t *)malloc((size_t)len);
        if (!buf) { fclose(f); return 2; }
        if (fread(buf, 1, (size_t)len, f) != (size_t)len) {
            free(buf);
            fclose(f);
            return 2;
        }
    }
    fclose(f);

    int rc = LLVMFuzzerTestOneInput(buf, (size_t)len);

    free(buf);
    return rc;
}
