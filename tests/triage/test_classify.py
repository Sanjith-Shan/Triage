"""Tests for :mod:`triage.classify`."""

from __future__ import annotations

import fixtures
from triage.asan_report import parse
from triage.classify import classify


def test_heap_overflow_write_is_oob_write_likely_exploitable():
    c = classify(parse(fixtures.HEAP_BOF_WRITE))
    assert c.severity == "OOB-write"
    assert c.exploitability == "likely-exploitable"
    # Conservative: we cannot prove attacker control from a bare report.
    assert c.controlled_offset is None
    assert c.controlled_value is None
    # Reached from the harness -> True.
    assert c.reachable_from_untrusted is True


def test_use_after_free_is_likely_exploitable():
    c = classify(parse(fixtures.HEAP_UAF_READ))
    assert c.severity == "use-after-free"
    assert c.exploitability == "likely-exploitable"


def test_stack_overflow_is_recursion_crash():
    c = classify(parse(fixtures.STACK_OVERFLOW_RECURSION))
    assert c.severity == "uncontrolled-recursion"
    assert c.exploitability == "crash"


def test_null_deref_segv_is_dos_crash():
    c = classify(parse(fixtures.SEGV_NULL_DEREF))
    assert c.severity == "DoS"
    assert c.exploitability == "crash"


def test_ubsan_is_other_crash():
    c = classify(parse(fixtures.UBSAN_SIGNED_OVERFLOW))
    assert c.severity == "other"
    assert c.exploitability == "crash"


def test_exploitability_never_exceeds_likely_exploitable():
    for text in (
        fixtures.HEAP_BOF_WRITE,
        fixtures.HEAP_UAF_READ,
        fixtures.STACK_OVERFLOW_RECURSION,
        fixtures.SEGV_NULL_DEREF,
        fixtures.UBSAN_SIGNED_OVERFLOW,
    ):
        c = classify(parse(text))
        assert c.exploitability in ("crash", "likely-exploitable")


def test_reachability_unknown_without_harness():
    # A crash stack with no harness frame -> reachability is unknown (None).
    text = fixtures.SEGV_NULL_DEREF.replace("LLVMFuzzerTestOneInput", "main")
    c = classify(parse(text))
    assert c.reachable_from_untrusted is None
