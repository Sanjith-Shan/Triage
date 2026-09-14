"""Correctness tests for the invariant primitives (real structural parsing)."""

from detect.invariant import (
    ByteSequencePresent,
    FieldLengthExceeds,
    HeadersCoexist,
    MalformedChunkFraming,
    NestingDepthExceeds,
    der_tlv_locator,
    der_tlv_records,
)


# --- HeadersCoexist (HTTP request smuggling / desync) ----------------------


def test_headers_coexist_matches_cl_and_te():
    inv = HeadersCoexist("Content-Length", "Transfer-Encoding")
    smuggle = (
        b"POST / HTTP/1.1\r\nHost: h\r\n"
        b"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"0\r\n\r\nGET /x"
    )
    assert inv.matches(smuggle) is True


def test_headers_coexist_rejects_cl_only():
    inv = HeadersCoexist("Content-Length", "Transfer-Encoding")
    clean = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc"
    assert inv.matches(clean) is False


def test_headers_coexist_is_case_insensitive_and_order_free():
    inv = HeadersCoexist("Content-Length", "Transfer-Encoding")
    reordered = (
        b"POST / HTTP/1.1\r\nHost: h\r\n"
        b"transfer-encoding: chunked\r\ncontent-length: 0\r\n\r\n"
    )
    assert inv.matches(reordered) is True


def test_headers_coexist_protected_regions_cover_both_lines():
    inv = HeadersCoexist("Content-Length", "Transfer-Encoding")
    data = (
        b"POST / HTTP/1.1\r\nHost: h\r\n"
        b"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    regions = inv.protected_regions(data)
    assert len(regions) == 2
    for start, end in regions:
        line = data[start:end].lower()
        assert b"content-length" in line or b"transfer-encoding" in line


# --- FieldLengthExceeds (oversized TLV / DER field overflow) ----------------


def test_field_length_exceeds_matches_oversized_tlv():
    # Tag 0x04, long-form length 0x84 => next 4 octets = 0x00010000 (65536).
    oversized = bytes([0x04, 0x84, 0x00, 0x01, 0x00, 0x00]) + b"\x41" * 4
    inv = FieldLengthExceeds(der_tlv_locator(), threshold=1024)
    assert inv.matches(oversized) is True


def test_field_length_exceeds_rejects_well_formed_tlv():
    well_formed = bytes([0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x0A])
    inv = FieldLengthExceeds(der_tlv_locator(), threshold=1024)
    assert inv.matches(well_formed) is False


def test_der_parser_decodes_long_form_length():
    oversized = bytes([0x04, 0x84, 0x00, 0x01, 0x00, 0x00])
    records = der_tlv_records(oversized)
    assert records[0].length == 65536


def test_field_length_protected_region_is_the_offending_header():
    oversized = bytes([0x04, 0x84, 0x00, 0x01, 0x00, 0x00]) + b"A" * 4
    inv = FieldLengthExceeds(der_tlv_locator(), threshold=1024)
    regions = inv.protected_regions(oversized)
    assert regions == [(0, 6)]  # tag + length octets


# --- NestingDepthExceeds (recursion / stack exhaustion) --------------------


def test_nesting_depth_exceeds_matches_deep():
    inv = NestingDepthExceeds(b"(", b")", depth=3)
    deep = b"((((x))))"
    assert inv.matches(deep) is True


def test_nesting_depth_exceeds_rejects_shallow():
    inv = NestingDepthExceeds(b"(", b")", depth=3)
    shallow = b"((x))"
    assert inv.matches(shallow) is False


def test_nesting_depth_handles_json_braces():
    inv = NestingDepthExceeds(b"{", b"}", depth=2)
    data = b'{"a":{"b":{"c":1}}}'
    assert inv.matches(data) is True


# --- MalformedChunkFraming (HTTP chunked class) ----------------------------


def test_malformed_chunk_matches_non_hex_size():
    bad = (
        b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"XYZ\r\ndata\r\n0\r\n\r\n"
    )
    assert MalformedChunkFraming().matches(bad) is True


def test_malformed_chunk_matches_trailing_junk():
    bad = (
        b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5 garbage\r\nhello\r\n0\r\n\r\n"
    )
    assert MalformedChunkFraming().matches(bad) is True


def test_malformed_chunk_accepts_valid_framing():
    good = (
        b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"4\r\nWiki\r\n0\r\n\r\n"
    )
    assert MalformedChunkFraming().matches(good) is False


def test_malformed_chunk_accepts_valid_extension():
    good = (
        b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"f;name=value\r\n123456789012345\r\n0\r\n\r\n"
    )
    assert MalformedChunkFraming().matches(good) is False


# --- ByteSequencePresent (overfit baseline) --------------------------------


def test_byte_sequence_present_matches_and_rejects():
    inv = ByteSequencePresent(b"PAYLOAD-XYZ")
    assert inv.matches(b"....PAYLOAD-XYZ....") is True
    assert inv.matches(b"....PAYLOAD-XY_....") is False
