#!/usr/bin/env python3
"""Generate MFERF corpus seeds and one crash reproducer per planted bug.

    python3 scripts/mferf_pack.py --seeds corpus/mferf --repro tests/mferf/reproducers

Seeds are benign, well-formed MFERF streams used to seed the mutator. Reproducers
each trigger exactly one documented bug (MFERF-001..005) and are used by the
regression tests, which assert they abort the unpatched build and parse cleanly
on the patched one.
"""
import argparse
import os
import struct


def rec(rtype: int, value: bytes) -> bytes:
    return bytes([rtype]) + struct.pack(">I", len(value)) + value


def rec_hdr(rtype: int, declared_len: int, value: bytes) -> bytes:
    """A record whose declared length may differ from the real value length."""
    return bytes([rtype]) + struct.pack(">I", declared_len) + value


def container(inner_records: bytes, inner_count: int) -> bytes:
    return rec(0x10, struct.pack(">H", inner_count) + inner_records)


def mferf(records: bytes, count: int, version: int = 1) -> bytes:
    return b"MFR1" + bytes([version]) + struct.pack(">H", count) + records


# ---- benign seeds --------------------------------------------------------

def seed_valid_1() -> bytes:
    r = rec(0x01, b"hello") + rec(0x02, b"\x00\x01\x02\x03") + rec(0x7f, b"skipme")
    return mferf(r, count=3)


def seed_valid_2() -> bytes:
    inner = rec(0x01, b"nested") + rec(0x02, b"\xaa\xbb")
    r = container(inner, inner_count=2) + rec(0x01, b"top")
    return mferf(r, count=2)


# ---- crash reproducers, one per planted bug ------------------------------

def repro_001() -> bytes:
    # STRING with 100-byte value overflows the 32-byte stack buffer.
    return mferf(rec(0x01, b"A" * 100), count=1)


def repro_002() -> bytes:
    # BLOB declares length 0xFFFFFFFF -> cap wraps to 0 (uint32) -> malloc(0) ->
    # memcpy of the 32 real value bytes overflows the heap chunk.
    return mferf(rec_hdr(0x02, 0xFFFFFFFF, b"B" * 32), count=1)


def repro_003() -> bytes:
    # INDEX: u32 index = 0x00100000, then 4 data bytes -> data[index] OOB read.
    value = struct.pack(">I", 0x00100000) + b"data"
    return mferf(rec(0x03, value), count=1)


def repro_004() -> bytes:
    # RECYCLE: 8-byte child freed, then read by the integrity pass (UAF).
    return mferf(rec(0x04, b"C" * 8), count=1)


def repro_005(depth: int = 100_000) -> bytes:
    # Deeply nested CONTAINERs exhaust the stack (unbounded recursion).
    cur = rec(0x01, b"")  # harmless leaf
    for _ in range(depth):
        cur = container(cur, inner_count=1)
    return mferf(cur, count=1)


REPROS = {
    "crash-MFERF-001": repro_001,
    "crash-MFERF-002": repro_002,
    "crash-MFERF-003": repro_003,
    "crash-MFERF-004": repro_004,
    "crash-MFERF-005": repro_005,
}


def write(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    print(f"wrote {path} ({len(data)} bytes)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", help="directory for benign corpus seeds")
    ap.add_argument("--repro", help="directory for crash reproducers")
    ap.add_argument("--depth", type=int, default=100_000, help="MFERF-005 nesting depth")
    args = ap.parse_args()

    if args.seeds:
        write(os.path.join(args.seeds, "seed_valid_1"), seed_valid_1())
        write(os.path.join(args.seeds, "seed_valid_2"), seed_valid_2())
    if args.repro:
        for name, fn in REPROS.items():
            data = fn(args.depth) if name.endswith("005") else fn()
            write(os.path.join(args.repro, name), data)


if __name__ == "__main__":
    main()
