/* Triage — standalone fuzz runner.
 *
 * Provides main() for fuzz targets when the libFuzzer runtime is unavailable
 * (Apple clang ships ASan but not libclang_rt.fuzzer_osx.a). It replays a corpus
 * through LLVMFuzzerTestOneInput under the sanitizers, and offers a cheap
 * fork-per-input mutation loop so a real "campaign" can be run and its crashes
 * collected for the triage pipeline — without any coverage feedback.
 *
 * This is NOT a coverage-guided engine. Time-to-first-crash and crash-count
 * numbers from this runner are labelled "standalone engine"; real edge-coverage
 * numbers come from libFuzzer on Linux. See docs/BUILD.md.
 *
 * Usage:
 *   target <file|dir> [<file|dir> ...]                 replay corpus (fork per input)
 *   target --mutate N --seeds DIR --out DIR            mutation campaign
 *       [--mutator naive|structured] [--seed S] [--max-len N]
 *
 * Exit status: 0 if nothing crashed; in replay mode, non-zero if any input
 * crashed. The mutation campaign always exits 0 (crashes are saved, not fatal)
 * and prints a summary to stdout.
 */
#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "triage/fuzzer.h"

/* Weak DEFAULT definitions of the optional hooks. A target that defines a strong
 * version overrides these (works on both ELF and Mach-O); a target that does not
 * gets the no-op defaults. This is why targets need no #ifdefs. */
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc; (void)argv; return 0;
}
__attribute__((weak)) size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                                                     size_t max_size,
                                                     unsigned int seed) {
  (void)data; (void)max_size; (void)seed; return size; /* no structured mutator */
}
/* Optional: did the last input reach deep code? -1 = target has no reach hook. */
__attribute__((weak)) int LLVMFuzzerReached(void) { return -1; }

#define MAX_LEN_DEFAULT (1u << 16)

static uint8_t *read_file(const char *path, size_t *out_len) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  if (n < 0) { fclose(f); return NULL; }
  fseek(f, 0, SEEK_SET);
  uint8_t *buf = (uint8_t *)malloc((size_t)n ? (size_t)n : 1);
  size_t got = fread(buf, 1, (size_t)n, f);
  fclose(f);
  *out_len = got;
  return buf;
}

/* Run one input in a forked child so a crash does not stop the run. Returns a
 * non-zero "crash code" if the child died on a signal (the signal number) or
 * exited non-zero (128 + exit code — this is how a sanitizer error surfaces when
 * it calls _exit(1) rather than abort). Returns 0 on a clean parse. */
static int run_one_forked(const uint8_t *data, size_t size) {
  pid_t pid = fork();
  if (pid == 0) {
    LLVMFuzzerTestOneInput(data, size);
    _exit(0);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  if (WIFSIGNALED(status)) return WTERMSIG(status);
  if (WIFEXITED(status) && WEXITSTATUS(status) != 0) return 128 + WEXITSTATUS(status);
  return 0;
}

static int is_dir(const char *path) {
  struct stat st;
  return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Replay a single path (file or directory of files). Returns crash count. */
static int replay_path(const char *path) {
  int crashes = 0;
  if (is_dir(path)) {
    DIR *d = opendir(path);
    if (!d) return 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
      if (e->d_name[0] == '.') continue;
      char full[4096];
      snprintf(full, sizeof full, "%s/%s", path, e->d_name);
      if (is_dir(full)) continue;
      size_t len = 0;
      uint8_t *buf = read_file(full, &len);
      if (!buf) continue;
      int sig = run_one_forked(buf, len);
      if (sig) { fprintf(stderr, "[crash] %s (signal %d)\n", full, sig); crashes++; }
      free(buf);
    }
    closedir(d);
  } else {
    size_t len = 0;
    uint8_t *buf = read_file(path, &len);
    if (buf) {
      int sig = run_one_forked(buf, len);
      if (sig) { fprintf(stderr, "[crash] %s (signal %d)\n", path, sig); crashes++; }
      free(buf);
    }
  }
  return crashes;
}

/* ---- mutation campaign ---- */

static uint8_t **load_seeds(const char *dir, size_t **lens, int *count) {
  DIR *d = opendir(dir);
  if (!d) { *count = 0; return NULL; }
  int cap = 16, n = 0;
  uint8_t **bufs = malloc(sizeof(uint8_t *) * cap);
  size_t *ls = malloc(sizeof(size_t) * cap);
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    if (e->d_name[0] == '.') continue;
    char full[4096];
    snprintf(full, sizeof full, "%s/%s", dir, e->d_name);
    if (is_dir(full)) continue;
    size_t len = 0;
    uint8_t *buf = read_file(full, &len);
    if (!buf) continue;
    if (n == cap) { cap *= 2; bufs = realloc(bufs, sizeof(uint8_t *) * cap); ls = realloc(ls, sizeof(size_t) * cap); }
    bufs[n] = buf; ls[n] = len; n++;
  }
  closedir(d);
  *lens = ls; *count = n;
  return bufs;
}

/* A deliberately dumb naive mutator: random flips, inserts, truncations. */
static size_t naive_mutate(uint8_t *data, size_t size, size_t max_size,
                           unsigned int *rng) {
  int op = rand_r(rng) % 4;
  if (size == 0) size = 1;
  switch (op) {
    case 0: /* flip a byte */
      data[rand_r(rng) % size] ^= (uint8_t)(1 << (rand_r(rng) % 8));
      return size;
    case 1: /* set a random byte */
      data[rand_r(rng) % size] = (uint8_t)(rand_r(rng) % 256);
      return size;
    case 2: /* grow by one byte */
      if (size < max_size) { data[size] = (uint8_t)(rand_r(rng) % 256); return size + 1; }
      return size;
    default: /* shrink */
      return size > 1 ? size - 1 : size;
  }
}

static void save_crash(const char *out_dir, int idx, const uint8_t *data, size_t size, int sig) {
  char path[4096];
  snprintf(path, sizeof path, "%s/crash-%04d-sig%d", out_dir, idx, sig);
  FILE *f = fopen(path, "wb");
  if (f) { fwrite(data, 1, size, f); fclose(f); }
}

static int campaign(long runs, const char *seeds_dir, const char *out_dir,
                    int structured, unsigned int seed, size_t max_len) {
  mkdir(out_dir, 0755);
  size_t *seed_lens = NULL;
  int nseeds = 0;
  uint8_t **seeds = load_seeds(seeds_dir, &seed_lens, &nseeds);
  if (nseeds == 0) { fprintf(stderr, "no seeds in %s\n", seeds_dir); return 1; }

  unsigned int rng = seed;
  int crashes = 0, saved = 0;
  long first_crash_run = -1;
  uint8_t *buf = malloc(max_len);

  for (long r = 0; r < runs; r++) {
    int s = rand_r(&rng) % nseeds;
    size_t len = seed_lens[s] < max_len ? seed_lens[s] : max_len;
    memcpy(buf, seeds[s], len);
    if (structured)
      len = LLVMFuzzerCustomMutator(buf, len, max_len, rand_r(&rng));
    else
      len = naive_mutate(buf, len, max_len, &rng);

    int sig = run_one_forked(buf, len);
    if (sig) {
      crashes++;
      if (first_crash_run < 0) first_crash_run = r;
      save_crash(out_dir, saved++, buf, len, sig);
    }
  }

  printf("engine=standalone mutator=%s runs=%ld crashes=%d saved=%d "
         "runs_to_first_crash=%ld out=%s\n",
         structured ? "structured" : "naive", runs, crashes, saved,
         first_crash_run, out_dir);

  free(buf);
  for (int i = 0; i < nseeds; i++) free(seeds[i]);
  free(seeds); free(seed_lens);
  return 0;
}

/* --reach: measure how often each mutator produces an input that reaches deep
 * code (past the format's header) vs bounces off it. A real, sanitizer-free
 * measurement of mutator quality — the structure-aware head-to-head's cheap half.
 * Child exits 10 = reached, 11 = not reached; a signal = crash. */
static int reach_campaign(long runs, const char *seeds_dir, int structured,
                          unsigned int seed, size_t max_len) {
  size_t *seed_lens = NULL;
  int nseeds = 0;
  uint8_t **seeds = load_seeds(seeds_dir, &seed_lens, &nseeds);
  if (nseeds == 0) { fprintf(stderr, "no seeds in %s\n", seeds_dir); return 1; }
  if (LLVMFuzzerReached() == -1)
    fprintf(stderr, "note: target has no reach hook; results will be 0\n");

  unsigned int rng = seed;
  long reached = 0, crashes = 0;
  uint8_t *buf = malloc(max_len);
  for (long r = 0; r < runs; r++) {
    int s = rand_r(&rng) % nseeds;
    size_t len = seed_lens[s] < max_len ? seed_lens[s] : max_len;
    memcpy(buf, seeds[s], len);
    if (structured) len = LLVMFuzzerCustomMutator(buf, len, max_len, rand_r(&rng));
    else            len = naive_mutate(buf, len, max_len, &rng);

    pid_t pid = fork();
    if (pid == 0) {
      LLVMFuzzerTestOneInput(buf, len);
      _exit(LLVMFuzzerReached() == 1 ? 10 : 11);
    }
    int status = 0; waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) crashes++;
    else if (WIFEXITED(status) && WEXITSTATUS(status) == 10) reached++;
  }
  printf("engine=standalone mode=reach mutator=%s runs=%ld reached=%ld "
         "reach_rate=%.4f crashes=%ld\n",
         structured ? "structured" : "naive", runs, reached,
         runs ? (double)reached / (double)runs : 0.0, crashes);
  free(buf);
  for (int i = 0; i < nseeds; i++) free(seeds[i]);
  free(seeds); free(seed_lens);
  return 0;
}

int main(int argc, char **argv) {
  LLVMFuzzerInitialize(&argc, &argv);

  if (argc >= 2 && strcmp(argv[1], "--reach") == 0) {
    long runs = 20000; const char *seeds_dir = NULL; int structured = 0;
    unsigned int seed = 1; size_t max_len = MAX_LEN_DEFAULT;
    if (argc >= 3) runs = atol(argv[2]);
    for (int i = 3; i < argc; i++) {
      if (!strcmp(argv[i], "--seeds") && i + 1 < argc) seeds_dir = argv[++i];
      else if (!strcmp(argv[i], "--mutator") && i + 1 < argc) structured = !strcmp(argv[++i], "structured");
      else if (!strcmp(argv[i], "--seed") && i + 1 < argc) seed = (unsigned)atol(argv[++i]);
      else if (!strcmp(argv[i], "--max-len") && i + 1 < argc) max_len = (size_t)atol(argv[++i]);
    }
    if (!seeds_dir) { fprintf(stderr, "usage: %s --reach N --seeds DIR [--mutator naive|structured]\n", argv[0]); return 2; }
    return reach_campaign(runs, seeds_dir, structured, seed, max_len);
  }

  if (argc >= 2 && strcmp(argv[1], "--mutate") == 0) {
    long runs = 10000;
    const char *seeds_dir = NULL, *out_dir = "crashes";
    int structured = 0;
    unsigned int seed = 1;
    size_t max_len = MAX_LEN_DEFAULT;
    if (argc >= 3) runs = atol(argv[2]);
    for (int i = 3; i < argc; i++) {
      if (!strcmp(argv[i], "--seeds") && i + 1 < argc) seeds_dir = argv[++i];
      else if (!strcmp(argv[i], "--out") && i + 1 < argc) out_dir = argv[++i];
      else if (!strcmp(argv[i], "--mutator") && i + 1 < argc) structured = !strcmp(argv[++i], "structured");
      else if (!strcmp(argv[i], "--seed") && i + 1 < argc) seed = (unsigned)atol(argv[++i]);
      else if (!strcmp(argv[i], "--max-len") && i + 1 < argc) max_len = (size_t)atol(argv[++i]);
    }
    if (!seeds_dir) { fprintf(stderr, "usage: %s --mutate N --seeds DIR --out DIR [--mutator naive|structured] [--seed S] [--max-len N]\n", argv[0]); return 2; }
    return campaign(runs, seeds_dir, out_dir, structured, seed, max_len);
  }

  if (argc < 2) {
    fprintf(stderr, "usage: %s <file|dir> ...   (replay)\n"
                    "       %s --mutate N --seeds DIR --out DIR [--mutator naive|structured]\n",
            argv[0], argv[0]);
    return 2;
  }

  int crashes = 0;
  for (int i = 1; i < argc; i++) crashes += replay_path(argv[i]);
  if (crashes) { fprintf(stderr, "%d crash(es)\n", crashes); return 1; }
  return 0;
}
