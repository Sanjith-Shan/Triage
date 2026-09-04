"""Conservative crash classification.

Honest rule of this stage:

    A crash is not an exploit.  !exploitable-style output is a *heuristic hint*,
    not a demonstration.  This classifier only ever emits ``crash`` or
    ``likely-exploitable`` on the exploitability ladder.  Anything higher
    (``poc-to-primitive``, ``weaponized``) requires a human to actually build
    and show the primitive, and is deliberately unreachable here.

Fields we cannot know from a bare sanitizer report (e.g. whether an attacker
controls the offset or the written value) are left as ``None`` rather than
guessed.  Being wrong-optimistic here wastes analyst time, so we prefer
under-claiming.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .asan_report import AsanReport
from .stackhash import HARNESS_FUNCTION, significant_functions, top_target_frame

__all__ = [
    "Severity",
    "Exploitability",
    "Classification",
    "classify",
]

# Severity ladder labels.
Severity = str  # {DoS, OOB-read, OOB-write, use-after-free, uncontrolled-recursion, other}

# Exploitability ladder.  This stage caps at "likely-exploitable".
Exploitability = str  # {crash, likely-exploitable, poc-to-primitive, weaponized}

_EXPLOITABILITY_LADDER = (
    "crash",
    "likely-exploitable",
    "poc-to-primitive",
    "weaponized",
)
_MAX_EMITTED_EXPLOITABILITY = "likely-exploitable"


@dataclass
class Classification:
    """The conservative verdict for a single crash."""

    severity: Severity
    exploitability: Exploitability
    controlled_offset: Optional[bool]
    controlled_value: Optional[bool]
    reachable_from_untrusted: Optional[bool]
    rationale: str = ""


def _severity(report: AsanReport) -> Severity:
    bug = report.bug_class
    if bug.startswith("UBSan-"):
        return "other"
    if "use-after-free" in bug or bug == "double-free":
        return "use-after-free"
    if "buffer-overflow" in bug or "buffer-underflow" in bug:
        return "OOB-write" if report.access_type == "WRITE" else "OOB-read"
    if bug.startswith("stack-overflow"):
        return "uncontrolled-recursion"
    if bug in ("SEGV", "FPE", "ILL", "ABRT"):
        return "DoS"
    return "other"


def _cap(exploitability: Exploitability) -> Exploitability:
    """Never let this stage emit above the manual-demonstration threshold."""
    max_idx = _EXPLOITABILITY_LADDER.index(_MAX_EMITTED_EXPLOITABILITY)
    idx = _EXPLOITABILITY_LADDER.index(exploitability)
    return _EXPLOITABILITY_LADDER[min(idx, max_idx)]


def _exploitability(severity: Severity, report: AsanReport) -> Exploitability:
    if severity == "OOB-write":
        return "likely-exploitable"
    if severity == "use-after-free":
        return "likely-exploitable"
    if severity == "OOB-read":
        # An out-of-bounds read is only promoted when it is write-adjacent
        # (the faulting access is itself a write); otherwise it is an info
        # leak / crash at this conservative stage.
        return "likely-exploitable" if report.access_type == "WRITE" else "crash"
    # DoS (NULL-deref SEGV, FPE), uncontrolled-recursion, other -> crash.
    return "crash"


def _reachable_from_untrusted(report: AsanReport) -> Optional[bool]:
    """True only when the crash is inside target code reached from the harness.

    Otherwise ``None`` (unknown): we do not claim reachability we cannot see.
    """
    functions = significant_functions(report)
    if HARNESS_FUNCTION not in functions:
        return None
    if top_target_frame(report) is None:
        return None
    return True


def classify(report: AsanReport) -> Classification:
    """Produce a conservative :class:`Classification` for ``report``."""
    severity = _severity(report)
    exploitability = _cap(_exploitability(severity, report))
    reachable = _reachable_from_untrusted(report)

    # We cannot prove attacker control of the offset or written value from a
    # bare sanitizer report (that needs taint / dataflow analysis), so we stay
    # honest and report None rather than guessing.
    controlled_offset: Optional[bool] = None
    controlled_value: Optional[bool] = None

    rationale = (
        f"{report.bug_class} -> {severity}; "
        f"access={report.access_type or 'n/a'}; "
        f"null_deref={report.is_null_deref}. "
        "Heuristic hint only; not an exploit demonstration."
    )

    return Classification(
        severity=severity,
        exploitability=exploitability,
        controlled_offset=controlled_offset,
        controlled_value=controlled_value,
        reachable_from_untrusted=reachable,
        rationale=rationale,
    )
