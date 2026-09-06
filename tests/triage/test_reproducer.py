"""Integration test for :func:`triage.minimize.make_reproducer`.

Uses a tiny Python script as a stand-in "target binary" so the test needs no
compiled C program: the script emits a sanitizer-style report on stderr only
when the input still contains the magic marker.
"""

from __future__ import annotations

import os
import stat
import sys

from triage.asan_report import parse
from triage.minimize import make_reproducer, minimize
from triage.stackhash import bucket

_REPORT = """\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010 at pc 0x1 bp 0x2 sp 0x3
WRITE of size 1 at 0x602000000010 thread T0
    #0 0x1 in vulnerable_copy /src/vuln.c:10:5
    #1 0x2 in LLVMFuzzerTestOneInput /src/fuzz.c:3:5
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/vuln.c:10:5 in vulnerable_copy
"""

_FAKE_TARGET = f'''\
#!{sys.executable}
import sys
with open(sys.argv[1], "rb") as fh:
    data = fh.read()
if b"MAGIC" in data:
    sys.stderr.write({_REPORT!r})
    sys.exit(1)
sys.exit(0)
'''


def _write_fake_target(tmp_path):
    target = tmp_path / "fake_target.py"
    target.write_text(_FAKE_TARGET, encoding="utf-8")
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(target)


def test_make_reproducer_matches_bucket(tmp_path):
    binary = _write_fake_target(tmp_path)
    target_bucket = bucket(parse(_REPORT))
    still_crashes = make_reproducer(binary, target_bucket)

    assert still_crashes(b"....MAGIC....") is True
    assert still_crashes(b"no marker here") is False


def test_make_reproducer_drives_minimization(tmp_path):
    binary = _write_fake_target(tmp_path)
    target_bucket = bucket(parse(_REPORT))
    still_crashes = make_reproducer(binary, target_bucket)

    data = b"A" * 30 + b"MAGIC" + b"B" * 30
    minimized = minimize(data, still_crashes)
    assert minimized == b"MAGIC"
