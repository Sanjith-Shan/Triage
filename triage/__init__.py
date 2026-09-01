"""Crash-triage stage for a security fuzzing instrument.

Ingests AddressSanitizer / UndefinedBehaviorSanitizer crash reports plus the
crashing inputs and turns thousands of raw crashes into a handful of classified,
deduplicated, minimized bugs.

Honest disclaimer that runs through the whole package: *a crash is not an
exploit.*  The classifier emits heuristic hints (``crash`` / ``likely-
exploitable``), never a demonstration of exploitability.
"""

from __future__ import annotations

from .asan_report import AsanReport, StackFrame, parse
from .classify import Classification, classify
from .minimize import make_reproducer, minimize
from .pipeline import Bug, TriageResult, triage_directory
from .stackhash import (
    CrashBucket,
    bucket,
    major_hash,
    minor_hash,
    significant_functions,
    top_target_frame,
)

__version__ = "0.1.0"

__all__ = [
    "AsanReport",
    "StackFrame",
    "parse",
    "CrashBucket",
    "bucket",
    "major_hash",
    "minor_hash",
    "significant_functions",
    "top_target_frame",
    "Classification",
    "classify",
    "minimize",
    "make_reproducer",
    "Bug",
    "TriageResult",
    "triage_directory",
]
