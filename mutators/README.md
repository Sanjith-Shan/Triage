# Structure-aware mutators

Each target's grammar-aware mutator is implemented as `LLVMFuzzerCustomMutator` next to its
driver (libFuzzer convention), so it is picked up automatically by real libFuzzer and by the
standalone runner's `--mutator structured` mode. See `targets/mferf/driver.c` for the MFERF
TLV mutator and `docs/METHODOLOGY.md` §2 for the head-to-head method and results.

This directory holds shared grammar helpers as the target set grows (e.g. a reusable TLV /
length-prefix model, or a `libprotobuf-mutator` schema for DER). Kept separate so a mutator
can be reused across targets of the same shape.
