"""Tests for :mod:`triage.stackhash`."""

from __future__ import annotations

import fixtures
from triage.asan_report import parse
from triage.stackhash import (
    HARNESS_FUNCTION,
    bucket,
    is_internal_frame,
    major_hash,
    significant_functions,
    top_target_frame,
)


def test_same_bug_different_addresses_same_major_hash():
    a = parse(fixtures.HEAP_BOF_WRITE)
    b = parse(fixtures.HEAP_BOF_WRITE_OTHER_RUN)
    assert bucket(a).major == bucket(b).major
    assert bucket(a).minor == bucket(b).minor


def test_different_top_frame_different_bucket():
    a = parse(fixtures.HEAP_BOF_WRITE)
    c = parse(fixtures.HEAP_BOF_WRITE_DIFFERENT_TOP)
    assert bucket(a).major != bucket(c).major


def test_different_bug_class_different_bucket():
    uaf = parse(fixtures.HEAP_UAF_READ)
    segv = parse(fixtures.SEGV_NULL_DEREF)
    assert bucket(uaf).major != bucket(segv).major


def test_internal_frames_dropped_but_harness_kept():
    report = parse(fixtures.HEAP_BOF_WRITE)
    functions = significant_functions(report)
    assert "__interceptor_malloc" not in functions
    assert HARNESS_FUNCTION in functions
    assert functions[0] == "parse_header"


def test_is_internal_frame():
    assert is_internal_frame("__asan_report_load4")
    assert is_internal_frame("__interceptor_memcpy")
    assert is_internal_frame("__ubsan_handle_add_overflow")
    assert not is_internal_frame("parse_header")
    assert not is_internal_frame(HARNESS_FUNCTION)


def test_top_target_frame_skips_harness_and_internals():
    report = parse(fixtures.HEAP_BOF_WRITE)
    target = top_target_frame(report)
    assert target is not None
    assert target.function == "parse_header"


def test_hash_is_deterministic_and_stable_width():
    report = parse(fixtures.HEAP_BOF_WRITE)
    h1 = major_hash(report)
    h2 = major_hash(report)
    assert h1 == h2
    assert len(h1) == 16
