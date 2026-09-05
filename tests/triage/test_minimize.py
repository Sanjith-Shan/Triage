"""Tests for :mod:`triage.minimize`."""

from __future__ import annotations

from triage.minimize import minimize


def test_ddmin_shrinks_to_required_marker():
    data = b"A" * 20 + b"MAGIC" + b"B" * 20

    def still_crashes(candidate: bytes) -> bool:
        return b"MAGIC" in candidate

    result = minimize(data, still_crashes)
    assert result == b"MAGIC"


def test_ddmin_is_deterministic():
    data = b"xxMAGICyyMAGICzz"

    def still_crashes(candidate: bytes) -> bool:
        return b"MAGIC" in candidate

    first = minimize(data, still_crashes)
    second = minimize(data, still_crashes)
    assert first == second
    assert b"MAGIC" in first
    assert len(first) <= len(data)


def test_ddmin_counts_predicate_calls_and_terminates():
    calls = {"n": 0}
    data = bytes(range(64))

    def still_crashes(candidate: bytes) -> bool:
        calls["n"] += 1
        # Requires the two anchor bytes to both be present.
        return bytes([0]) in candidate and bytes([63]) in candidate

    result = minimize(data, still_crashes, max_rounds=100)
    assert bytes([0]) in result
    assert bytes([63]) in result
    assert len(result) < len(data)
    assert calls["n"] > 0  # predicate was actually exercised


def test_ddmin_returns_input_when_predicate_false():
    data = b"nothing here"

    def never(candidate: bytes) -> bool:
        return False

    assert minimize(data, never) == data


def test_ddmin_handles_empty_input():
    assert minimize(b"", lambda b: True) == b""
