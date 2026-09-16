"""Structural validity tests for the YARA and Suricata rule generators."""

import re

from detect.invariant import (
    ByteSequencePresent,
    FieldLengthExceeds,
    HeadersCoexist,
    MalformedChunkFraming,
    NestingDepthExceeds,
    der_tlv_locator,
)
from detect.suricata_gen import sid_for, to_suricata
from detect.yara_gen import to_yara

META = {
    "bug_id": "BUG-1234",
    "bug_class": "http-desync",
    "cwe": "CWE-444",
    "note": "CL and TE coexist",
}


def _yara_is_structural(text: str) -> None:
    assert re.search(r"^rule\s+\w+", text, re.MULTILINE)
    assert "meta:" in text
    assert "strings:" in text
    assert "condition:" in text
    # Balanced braces.
    assert text.count("{") == text.count("}")


def test_yara_headers_coexist_structural():
    rule = to_yara(HeadersCoexist("Content-Length", "Transfer-Encoding"), META)
    _yara_is_structural(rule)
    assert "invariant-based" in rule
    assert "CWE-444" in rule
    assert "Content-Length" in rule and "Transfer-Encoding" in rule


def test_yara_field_length_has_limitation():
    inv = FieldLengthExceeds(der_tlv_locator(), threshold=1024)
    rule = to_yara(inv, {**META, "bug_class": "overflow-on-length-field"})
    _yara_is_structural(rule)
    assert "limitation" in rule  # approximation must be disclosed


def test_yara_nesting_and_chunk_structural():
    _yara_is_structural(to_yara(NestingDepthExceeds(b"(", b")", 5), META))
    _yara_is_structural(to_yara(MalformedChunkFraming(), META))


def test_yara_bug_id_becomes_valid_identifier():
    rule = to_yara(HeadersCoexist("A", "B"), {**META, "bug_id": "BUG-99/x"})
    m = re.search(r"^rule\s+(\w+)", rule, re.MULTILINE)
    assert m is not None
    assert re.fullmatch(r"[A-Za-z_]\w*", m.group(1))


def _suricata_is_structural(text: str) -> None:
    assert text.startswith("alert ")
    assert text.rstrip().endswith(")")
    assert "msg:" in text
    assert "classtype:" in text
    assert re.search(r"sid:\d+", text)
    assert "rev:" in text
    assert "metadata:" in text
    # The option block is wrapped in (...); note payload content may itself
    # contain parens, so we check the wrapper, not a naive paren count.
    assert " (" in text
    assert text.rstrip().endswith(";)")


def test_suricata_headers_coexist_structural():
    rule = to_suricata(HeadersCoexist("Content-Length", "Transfer-Encoding"), META)
    _suricata_is_structural(rule)
    assert "http.header" in rule
    assert "invariant-based" in rule


def test_suricata_chunk_and_field_and_nesting_structural():
    _suricata_is_structural(to_suricata(MalformedChunkFraming(), META))
    _suricata_is_structural(
        to_suricata(FieldLengthExceeds(der_tlv_locator(), 1024), META)
    )
    _suricata_is_structural(to_suricata(NestingDepthExceeds(b"(", b")", 5), META))


def test_suricata_sid_is_deterministic_and_in_range():
    sid = sid_for("BUG-1234")
    assert sid == sid_for("BUG-1234")
    assert 1_000_000 <= sid < 2_000_000
    assert sid_for("BUG-1234") != sid_for("BUG-9999")


def test_suricata_approximate_rules_disclose_limitation():
    rule = to_suricata(FieldLengthExceeds(der_tlv_locator(), 1024), META)
    assert "limitation" in rule
