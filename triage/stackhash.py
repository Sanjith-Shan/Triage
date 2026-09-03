"""ASLR-normalized crash bucketing.

Two crashes belong to the same bug when their *top* stack frames match after
stripping everything that varies between runs: absolute addresses, module load
offsets, and sanitizer-internal frames.  We collapse each crash to a bucket
identified by a ``major`` hash (top few frames) and a ``minor`` hash (more
frames).  Crashes that share a ``major`` hash are treated as "the same bug".
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from .asan_report import AsanReport, StackFrame

__all__ = [
    "CrashBucket",
    "HARNESS_FUNCTION",
    "is_internal_frame",
    "significant_frames",
    "significant_functions",
    "top_target_frame",
    "major_hash",
    "minor_hash",
    "bucket",
]

#: The libFuzzer harness entry point.  It is a real frame we deliberately keep,
#: because it marks the boundary of attacker-reachable target code.
HARNESS_FUNCTION = "LLVMFuzzerTestOneInput"

#: Substrings marking sanitizer-internal / interceptor frames we drop.
_INTERNAL_SUBSTRINGS = (
    "__asan",
    "__ubsan",
    "__sanitizer",
    "__interceptor",
    "__tsan",
    "__lsan",
)

_MAJOR_FRAMES = 3
_MINOR_FRAMES = 7
_HASH_WIDTH = 16  # hex characters of the digest we keep


@dataclass(frozen=True)
class CrashBucket:
    """A crash bucket identified by two ASLR-normalized hashes."""

    major: str
    minor: str


def is_internal_frame(function: str) -> bool:
    """Return True for sanitizer-internal / interceptor frames to be dropped.

    The harness entry point is never internal even though it is not target
    code, because it anchors reachability analysis.
    """
    if not function:
        return False
    if function == HARNESS_FUNCTION:
        return False
    return any(marker in function for marker in _INTERNAL_SUBSTRINGS)


def significant_frames(report: AsanReport) -> list[StackFrame]:
    """Frames of the primary stack with sanitizer-internal frames removed."""
    return [f for f in report.frames if not is_internal_frame(f.function)]


def significant_functions(report: AsanReport) -> list[str]:
    """Function names of the significant frames (addresses/offsets stripped)."""
    return [f.function for f in significant_frames(report)]


def top_target_frame(report: AsanReport) -> Optional[StackFrame]:
    """The topmost significant frame that is target code (not the harness)."""
    for frame in significant_frames(report):
        if frame.function and frame.function != HARNESS_FUNCTION:
            return frame
    return None


def _hash(report: AsanReport, depth: int) -> str:
    functions = significant_functions(report)[:depth]
    # Include the bug class so different fault types at the same location do not
    # collapse together (heap-overflow vs use-after-free in the same function).
    payload = "\n".join([report.bug_class, *functions])
    digest = hashlib.sha1(payload.encode("utf-8", "replace")).hexdigest()
    return digest[:_HASH_WIDTH]


def major_hash(report: AsanReport, frames: int = _MAJOR_FRAMES) -> str:
    """Coarse bucket: top ``frames`` significant function names (default 3)."""
    return _hash(report, frames)


def minor_hash(report: AsanReport, frames: int = _MINOR_FRAMES) -> str:
    """Fine bucket: top ``frames`` significant function names (default 7)."""
    return _hash(report, frames)


def bucket(report: AsanReport) -> CrashBucket:
    """Compute the :class:`CrashBucket` for ``report``."""
    return CrashBucket(major=major_hash(report), minor=minor_hash(report))
