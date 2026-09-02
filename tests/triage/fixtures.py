"""Realistic ASan / UBSan report fixtures used across the triage test suite."""

from __future__ import annotations

# Heap-buffer-overflow, WRITE.
HEAP_BOF_WRITE = """\
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000e75 at pc 0x0000004a1b2c bp 0x7ffd1a2b3c40 sp 0x7ffd1a2b3c38
WRITE of size 1 at 0x602000000e75 thread T0
    #0 0x4a1b2b in parse_header /src/parser.c:42:9
    #1 0x4a2c3d in handle_packet /src/handler.c:88:5
    #2 0x4a3d4e in process_input /src/main.c:15:3
    #3 0x4a4e5f in LLVMFuzzerTestOneInput /src/fuzz.c:10:5
    #4 0x51aabb in __interceptor_malloc /llvm/compiler-rt/lib/asan/asan_malloc_linux.cpp:69:3
    #5 0x7f2c3d4e5083 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24083)
0x602000000e75 is located 5 bytes to the right of 10-byte region [0x602000000e70,0x602000000e7a)
allocated by thread T0 here:
    #0 0x4c1234 in __interceptor_malloc /llvm/compiler-rt/lib/asan/asan_malloc_linux.cpp:69:3
    #1 0x4a1a00 in alloc_header /src/parser.c:20:14
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:42:9 in parse_header
==12345==ABORTING
"""

# Same bug as HEAP_BOF_WRITE but every address differs (a different run under
# ASLR).  Must bucket to the SAME major hash.
HEAP_BOF_WRITE_OTHER_RUN = """\
=================================================================
==98765==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x603000abcdef at pc 0x0000005b2c3d bp 0x7ffe9988aa00 sp 0x7ffe9988a9f8
WRITE of size 1 at 0x603000abcdef thread T0
    #0 0x5b2c3c in parse_header /src/parser.c:42:9
    #1 0x5b3d4e in handle_packet /src/handler.c:88:5
    #2 0x5b4e5f in process_input /src/main.c:15:3
    #3 0x5b5f60 in LLVMFuzzerTestOneInput /src/fuzz.c:10:5
    #4 0x61bbcc in __interceptor_malloc /llvm/compiler-rt/lib/asan/asan_malloc_linux.cpp:69:3
    #5 0x7faa1122c084 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24083)
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:42:9 in parse_header
==98765==ABORTING
"""

# Different top frame (decode_body instead of parse_header) -> different bucket.
HEAP_BOF_WRITE_DIFFERENT_TOP = """\
==22222==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000f00 at pc 0x0000004a9999 bp 0x7ffd00000000 sp 0x7ffd00000008
WRITE of size 4 at 0x602000000f00 thread T0
    #0 0x4a9998 in decode_body /src/decode.c:77:11
    #1 0x4a2c3d in handle_packet /src/handler.c:88:5
    #2 0x4a3d4e in process_input /src/main.c:15:3
    #3 0x4a4e5f in LLVMFuzzerTestOneInput /src/fuzz.c:10:5
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/decode.c:77:11 in decode_body
"""

# Heap-use-after-free, READ, with three stacks (crash / freed / allocated).
HEAP_UAF_READ = """\
=================================================================
==777==ERROR: AddressSanitizer: heap-use-after-free on address 0x60300000eff0 at pc 0x0000004b1c2d bp 0x7ffc11223340 sp 0x7ffc11223338
READ of size 4 at 0x60300000eff0 thread T0
    #0 0x4b1c2c in use_object /src/obj.c:23:12
    #1 0x4b2d3e in run_objects /src/obj.c:50:3
    #2 0x4b3e4f in LLVMFuzzerTestOneInput /src/fuzz.c:12:5
freed by thread T0 here:
    #0 0x4c9000 in __interceptor_free /llvm/compiler-rt/lib/asan/asan_malloc_linux.cpp:52:3
    #1 0x4b0a00 in free_object /src/obj.c:40:5
previously allocated by thread T0 here:
    #0 0x4c1234 in __interceptor_malloc /llvm/compiler-rt/lib/asan/asan_malloc_linux.cpp:69:3
    #1 0x4b0900 in make_object /src/obj.c:12:16
SUMMARY: AddressSanitizer: heap-use-after-free /src/obj.c:23:12 in use_object
==777==ABORTING
"""

# Stack-overflow from unbounded recursion (no READ/WRITE line).
STACK_OVERFLOW_RECURSION = """\
==333==ERROR: AddressSanitizer: stack-overflow on address 0x7ffd7fabc123 (pc 0x0000004d1e2f bp 0x7ffd7fabd000 sp 0x7ffd7fabc100 T0)
    #0 0x4d1e2e in recurse /src/rec.c:8:5
    #1 0x4d1e2e in recurse /src/rec.c:9:9
    #2 0x4d1e2e in recurse /src/rec.c:9:9
    #3 0x4d1e2e in recurse /src/rec.c:9:9
    #4 0x4d3040 in LLVMFuzzerTestOneInput /src/fuzz.c:5:5
SUMMARY: AddressSanitizer: stack-overflow /src/rec.c:8:5 in recurse
"""

# SEGV on a NULL dereference.
SEGV_NULL_DEREF = """\
==444==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x0000004e2f30 bp 0x7ffd00112200 sp 0x7ffd001121f0 T0)
==444==The signal is caused by a READ memory access.
==444==Hint: address points to the zero page.
    #0 0x4e2f2f in deref_null /src/n.c:20:10
    #1 0x4e3040 in LLVMFuzzerTestOneInput /src/fuzz.c:7:5
SUMMARY: AddressSanitizer: SEGV /src/n.c:20:10 in deref_null
"""

# UBSan signed integer overflow.
UBSAN_SIGNED_OVERFLOW = """\
/src/math.c:12:9: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
    #0 0x4f1a2b in add_values /src/math.c:12:9
    #1 0x4f2b3c in LLVMFuzzerTestOneInput /src/fuzz.c:6:5
SUMMARY: UndefinedBehaviorSanitizer: signed-integer-overflow /src/math.c:12:9 in add_values
"""
