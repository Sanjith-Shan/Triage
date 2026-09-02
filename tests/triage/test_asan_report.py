"""Tests for :mod:`triage.asan_report`."""

from __future__ import annotations

import fixtures
from triage.asan_report import parse


def test_heap_buffer_overflow_write_fields():
    report = parse(fixtures.HEAP_BOF_WRITE)
    assert report.sanitizer == "AddressSanitizer"
    assert report.bug_class == "heap-buffer-overflow"
    assert report.access_type == "WRITE"
    assert report.access_size == 1
    assert report.fault_address == 0x602000000E75
    assert report.is_null_deref is False

    # Only the primary crash stack is kept (not the "allocated by" stack).
    assert report.top_frame is not None
    top = report.top_frame
    assert top.index == 0
    assert top.function == "parse_header"
    assert top.file == "/src/parser.c"
    assert top.line == 42

    functions = [f.function for f in report.frames]
    assert functions == [
        "parse_header",
        "handle_packet",
        "process_input",
        "LLVMFuzzerTestOneInput",
        "__interceptor_malloc",
        "__libc_start_main",
    ]
    # The module+offset frame is parsed into module/offset, not file/line.
    libc_frame = report.frames[-1]
    assert libc_frame.function == "__libc_start_main"
    assert libc_frame.module == "/lib/x86_64-linux-gnu/libc.so.6"
    assert libc_frame.offset == "0x24083"


def test_use_after_free_keeps_only_primary_stack():
    report = parse(fixtures.HEAP_UAF_READ)
    assert report.bug_class == "heap-use-after-free"
    assert report.access_type == "READ"
    assert report.access_size == 4
    # freed-by / allocated-by frames must NOT leak into the crash stack.
    functions = [f.function for f in report.frames]
    assert functions == ["use_object", "run_objects", "LLVMFuzzerTestOneInput"]


def test_stack_overflow_recursion():
    report = parse(fixtures.STACK_OVERFLOW_RECURSION)
    assert report.bug_class == "stack-overflow (recursion)"
    assert report.access_type is None  # no READ/WRITE line
    assert report.is_null_deref is False
    assert report.top_frame.function == "recurse"


def test_segv_null_deref():
    report = parse(fixtures.SEGV_NULL_DEREF)
    assert report.bug_class == "SEGV"
    assert report.fault_address == 0
    assert report.is_null_deref is True
    assert report.top_frame.function == "deref_null"


def test_ubsan_signed_overflow():
    report = parse(fixtures.UBSAN_SIGNED_OVERFLOW)
    assert report.sanitizer == "UndefinedBehaviorSanitizer"
    assert report.bug_class == "UBSan-signed-integer-overflow"
    assert report.access_type is None
    assert report.is_null_deref is False
    assert report.top_frame.function == "add_values"


def test_parse_never_raises_on_garbage():
    report = parse("this is not a sanitizer report at all\n")
    assert report.bug_class == "unknown"
    assert report.frames == []
    assert report.access_type is None
