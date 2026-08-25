/* Triage — fuzz target contract.
 *
 * Every fuzz target translation unit defines LLVMFuzzerTestOneInput. Optionally
 * a target may define:
 *   - LLVMFuzzerInitialize(argc, argv)        one-time setup (libFuzzer convention)
 *   - LLVMFuzzerCustomMutator(...)            a structure-aware mutator
 *
 * Both of the optional hooks use libFuzzer's own signatures, so the SAME target
 * builds three ways with no #ifdefs in the target itself:
 *   1. real libFuzzer   (clang -fsanitize=fuzzer,address ...) — Linux campaigns
 *   2. standalone runner (standalone_main.c linked in)         — macOS / ASan / CI
 *   3. AFL++            (afl-clang-fast, persistent mode)       — Linux campaigns
 *
 * The standalone runner (targets/standalone_main.c) provides main() for build
 * mode 2, and calls the same hooks. It exists because Apple clang ships ASan but
 * not the libFuzzer runtime; see docs/BUILD.md. It is a fallback for developing
 * and reproducing crashes, NOT a coverage-guided engine — coverage numbers come
 * from mode 1 on Linux.
 */
#ifndef TRIAGE_FUZZER_H
#define TRIAGE_FUZZER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Required. Return value is ignored (libFuzzer convention: return 0). */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* Optional. Weakly referenced by the standalone runner. */
int LLVMFuzzerInitialize(int *argc, char ***argv);

/* Optional structure-aware mutator (libFuzzer convention). Mutates the buffer
 * in place within max_size, returns the new size. The standalone runner calls
 * this only in --mutator structured mode; real libFuzzer calls it automatically
 * when the symbol is linked. */
size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                               unsigned int seed);

/* Optional reach hook (Triage extension, not libFuzzer): a target returns 1 if
 * the last input reached deep code past its header, 0 if it bounced, -1 if the
 * target implements no hook. Used only by the standalone runner's --reach mode. */
int LLVMFuzzerReached(void);

#ifdef __cplusplus
}
#endif

#endif /* TRIAGE_FUZZER_H */
