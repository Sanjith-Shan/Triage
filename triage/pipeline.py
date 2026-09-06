"""Triage orchestration: raw crash directory -> classified, deduped bugs.

:func:`triage_directory` ingests a directory of crashing inputs (optionally with
``.asan`` sidecar report files, or by re-running a target binary), buckets and
deduplicates them, classifies one representative per bucket, optionally minimizes
that representative, and returns a structured :class:`TriageResult` that can be
rendered as a Markdown triage table or JSON.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from .asan_report import AsanReport, parse
from .classify import Classification, classify
from .minimize import make_reproducer, minimize
from .stackhash import CrashBucket, bucket, top_target_frame

__all__ = ["Bug", "TriageResult", "triage_directory"]

_SIDECAR_SUFFIX = ".asan"


@dataclass
class Bug:
    """One unique bug: a crash bucket plus its classification and stats."""

    bug_id: str
    bug_class: str
    bucket: CrashBucket
    classification: Classification
    crash_count: int
    representative: str
    top_frame: str
    original_size: int
    minimized_size: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "bug_id": self.bug_id,
            "bug_class": self.bug_class,
            "bucket": {"major": self.bucket.major, "minor": self.bucket.minor},
            "classification": asdict(self.classification),
            "crash_count": self.crash_count,
            "representative": self.representative,
            "top_frame": self.top_frame,
            "original_size": self.original_size,
            "minimized_size": self.minimized_size,
        }


@dataclass
class TriageResult:
    """The full result of triaging a crash directory."""

    bugs: list[Bug] = field(default_factory=list)
    total_crashes: int = 0
    skipped: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_crashes": self.total_crashes,
            "unique_bugs": len(self.bugs),
            "skipped": self.skipped,
            "bugs": [b.to_dict() for b in self.bugs],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize the result to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_markdown(self) -> str:
        """Render the triage table as GitHub-flavoured Markdown."""

        def cell(value: Optional[bool]) -> str:
            if value is None:
                return "?"
            return "yes" if value else "no"

        def size(value: Optional[int]) -> str:
            return "-" if value is None else str(value)

        header = (
            "| bug id | class | exploitability | controlled-offset | "
            "controlled-value | reachable | top frame | #crashes | "
            "minimized size |"
        )
        divider = "| " + " | ".join(["---"] * 9) + " |"
        rows = [header, divider]
        for bug in self.bugs:
            cls = bug.classification
            rows.append(
                "| {id} | {klass} | {expl} | {off} | {val} | {reach} | "
                "{frame} | {count} | {msize} |".format(
                    id=bug.bug_id,
                    klass=bug.bug_class,
                    expl=cls.exploitability,
                    off=cell(cls.controlled_offset),
                    val=cell(cls.controlled_value),
                    reach=cell(cls.reachable_from_untrusted),
                    frame=bug.top_frame or "?",
                    count=bug.crash_count,
                    msize=size(bug.minimized_size),
                )
            )
        return "\n".join(rows) + "\n"


def _read_report_for(
    input_path: Path,
    binary_path: Optional[str],
    timeout: float,
) -> Optional[AsanReport]:
    """Obtain a parsed report for ``input_path`` via sidecar or the binary."""
    sidecar = input_path.with_name(input_path.name + _SIDECAR_SUFFIX)
    if sidecar.is_file():
        return parse(sidecar.read_text(encoding="utf-8", errors="replace"))

    if binary_path is not None:
        try:
            proc = subprocess.run(
                [binary_path, str(input_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError):
            return None
        return parse(proc.stderr.decode("utf-8", "replace"))

    return None


def _iter_crash_inputs(crashes_dir: Path) -> list[Path]:
    """Deterministically list crash input files (excluding sidecars)."""
    inputs: list[Path] = []
    for entry in sorted(crashes_dir.iterdir()):
        if not entry.is_file():
            continue
        if entry.name.endswith(_SIDECAR_SUFFIX):
            continue
        inputs.append(entry)
    return inputs


def triage_directory(
    crashes_dir: os.PathLike[str] | str,
    binary_path: Optional[str] = None,
    minimize_inputs: bool = False,
    timeout: float = 10.0,
    max_rounds: int = 1000,
) -> TriageResult:
    """Triage every crash input in ``crashes_dir``.

    Parameters
    ----------
    crashes_dir:
        Directory of raw crash inputs.  A file ``foo`` may have a sidecar
        ``foo.asan`` holding its sanitizer report.
    binary_path:
        Optional sanitizer-built target.  Used to generate reports for inputs
        lacking a sidecar, and (with ``minimize_inputs``) to minimize a
        representative per bucket.
    minimize_inputs:
        If True and ``binary_path`` is given, minimize one representative input
        per bucket while preserving its crash bucket.
    """
    crashes_dir = Path(crashes_dir)
    result = TriageResult()

    # bucket major hash -> list of (input_path, report)
    groups: dict[str, list[tuple[Path, AsanReport]]] = {}
    order: list[str] = []  # first-seen order of bucket majors, for stable ids

    for input_path in _iter_crash_inputs(crashes_dir):
        report = _read_report_for(input_path, binary_path, timeout)
        if report is None:
            result.skipped.append(str(input_path))
            continue
        result.total_crashes += 1
        crash_bucket = bucket(report)
        key = crash_bucket.major
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append((input_path, report))

    for i, key in enumerate(order, start=1):
        members = groups[key]
        rep_path, rep_report = members[0]
        crash_bucket = bucket(rep_report)
        classification = classify(rep_report)
        target = top_target_frame(rep_report)
        top_frame_name = target.function if target else (
            rep_report.top_frame.function if rep_report.top_frame else ""
        )

        original_size = rep_path.stat().st_size if rep_path.is_file() else 0
        minimized_size: Optional[int] = None
        if minimize_inputs and binary_path is not None and rep_path.is_file():
            data = rep_path.read_bytes()
            predicate = make_reproducer(binary_path, crash_bucket, timeout=timeout)
            if predicate(data):
                minimized = minimize(data, predicate, max_rounds=max_rounds)
                minimized_size = len(minimized)

        result.bugs.append(
            Bug(
                bug_id=f"BUG-{i:04d}",
                bug_class=rep_report.bug_class,
                bucket=crash_bucket,
                classification=classification,
                crash_count=len(members),
                representative=str(rep_path),
                top_frame=top_frame_name,
                original_size=original_size,
                minimized_size=minimized_size,
            )
        )

    return result
