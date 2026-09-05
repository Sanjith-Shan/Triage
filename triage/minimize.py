"""Engine-agnostic input minimization via delta debugging (ddmin).

The core :func:`minimize` shrinks a crashing byte string while a caller-injected
predicate ``still_crashes`` keeps reporting True.  The predicate is where all
target-specific knowledge lives: it runs the target on candidate bytes and
decides whether *the same bug* still reproduces.  :func:`make_reproducer` builds
such a predicate for a native binary, using the crash bucket to make sure
minimization preserves the specific bug rather than drifting to any crash.

The algorithm is deterministic and always terminates.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from typing import Callable

from .asan_report import parse
from .stackhash import CrashBucket, bucket

__all__ = ["minimize", "make_reproducer"]

Predicate = Callable[[bytes], bool]


def minimize(
    data: bytes,
    still_crashes: Predicate,
    max_rounds: int = 1000,
) -> bytes:
    """Delta-debug ``data`` down to a 1-minimal crashing input.

    ``still_crashes`` must return True for ``data`` itself; if it does not, the
    input is returned unchanged.  The result is minimal in the sense that no
    single remaining byte can be removed while the predicate still holds.

    This is the "remove complement" formulation of ddmin: at each granularity
    we try deleting one contiguous chunk at a time and keep the deletion if the
    predicate survives, doubling the granularity when nothing can be removed.
    """
    if not data or not still_crashes(data):
        return data

    n = 2
    rounds = 0
    while len(data) >= 2 and rounds < max_rounds:
        rounds += 1
        chunk_len = len(data) // n
        if chunk_len == 0:
            break

        removed = False
        for start in range(0, len(data), chunk_len):
            candidate = data[:start] + data[start + chunk_len :]
            if candidate and still_crashes(candidate):
                data = candidate
                n = max(n - 1, 2)
                removed = True
                break

        if removed:
            continue
        if n >= len(data):
            break  # already at single-byte granularity: 1-minimal
        n = min(n * 2, len(data))

    return data


def make_reproducer(
    binary_path: str,
    target_bucket: CrashBucket,
    timeout: float = 10.0,
    extra_args: tuple[str, ...] = (),
) -> Predicate:
    """Build a ``still_crashes`` predicate for a native sanitizer-built target.

    The returned closure writes candidate bytes to a temp file, runs
    ``binary_path`` on it, parses the sanitizer report from stderr, and returns
    True only when the crash lands in the *same* bucket as ``target_bucket``
    (same major hash), so minimization preserves the specific bug.
    """

    def still_crashes(candidate: bytes) -> bool:
        tmp_fd, tmp_path = tempfile.mkstemp(prefix="triage-repro-")
        try:
            with os.fdopen(tmp_fd, "wb") as handle:
                handle.write(candidate)
            try:
                proc = subprocess.run(
                    [binary_path, *extra_args, tmp_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                    check=False,
                )
            except (subprocess.TimeoutExpired, OSError):
                return False

            stderr = proc.stderr.decode("utf-8", "replace")
            report = parse(stderr)
            if not report.frames and report.bug_class == "unknown":
                return False
            return bucket(report).major == target_bucket.major
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    return still_crashes
