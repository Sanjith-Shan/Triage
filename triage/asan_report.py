"""Parse AddressSanitizer / UndefinedBehaviorSanitizer crash reports.

This module turns the free-form text a sanitizer prints on ``stderr`` into a
structured :class:`AsanReport`.  It is intentionally tolerant of the many small
formatting variations found in real-world ASan/UBSan output (different
sanitizer banners, ``ERROR:`` vs ``SUMMARY:`` lines, module+offset frames,
multi-stack use-after-free reports, and so on).

Only the *primary* crash stack is captured in :attr:`AsanReport.frames`.  A
use-after-free report, for example, contains three stacks ("crash", "freed by",
"previously allocated by"); we keep only the first, because that is the stack
that identifies where the bug actually manifested.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

__all__ = ["StackFrame", "AsanReport", "parse"]


# A frame line looks like:  "    #0 0x4a1b2b in parse_header /src/parser.c:42:9"
# or:                       "    #5 0x7f.. in __libc_start_main (/lib/libc.so.6+0x24083)"
# or (no symbol):           "    #4 0x1234 (/lib/libfoo.so+0xdead)"
_FRAME_RE = re.compile(
    r"^\s*#(?P<idx>\d+)\s+0x[0-9a-fA-F]+\s+(?P<rest>.*\S)\s*$"
)

# "READ of size 4 at 0x60200000eff4 thread T0"
_ACCESS_RE = re.compile(
    r"\b(?P<kind>READ|WRITE) of size (?P<size>\d+) at (?P<addr>0x[0-9a-fA-F]+)"
)

# "on address 0x..." / "on unknown address 0x..."
_ADDR_RE = re.compile(r"on (?:unknown )?address (0x[0-9a-fA-F]+)")

# "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:42 in parse_header"
_SUMMARY_RE = re.compile(
    r"SUMMARY:\s*(?P<san>AddressSanitizer|UndefinedBehaviorSanitizer|\S+):\s*"
    r"(?P<kind>[^\s]+)"
)

# "==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x..."
_ERROR_RE = re.compile(
    r"(?:ERROR|WARNING):\s*(?P<san>AddressSanitizer|UndefinedBehaviorSanitizer)"
    r":\s*(?P<rest>.+)"
)

# "file.c:12:9: runtime error: signed integer overflow: ..."
_UBSAN_RUNTIME_RE = re.compile(r"runtime error:\s*(?P<desc>.+)")

# module+offset tail of a frame, e.g. "(/lib/libc.so.6+0x24083)"
_MODULE_OFFSET_RE = re.compile(r"\((?P<mod>[^()]*)\+0x(?P<off>[0-9a-fA-F]+)\)\s*$")

# source location tail of a frame, e.g. " /src/parser.c:42:9"
_FILE_LINE_RE = re.compile(r"\s(?P<file>\S+?):(?P<line>\d+)(?::\d+)?\s*$")

# Known ASan bug-class keywords, in the order we prefer to recognise them.
_KNOWN_ASAN_KINDS = (
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "stack-buffer-underflow",
    "heap-use-after-free",
    "use-after-free",
    "double-free",
    "stack-use-after-return",
    "stack-use-after-scope",
    "container-overflow",
    "stack-overflow",
    "negative-size-param",
    "memcpy-param-overlap",
    "dynamic-stack-buffer-overflow",
    "alloc-dealloc-mismatch",
    "SEGV",
    "FPE",
    "ILL",
    "ABRT",
)

# Addresses below this are treated as "near NULL" (page-zero-ish) dereferences.
_NULL_DEREF_THRESHOLD = 0x1000


@dataclass
class StackFrame:
    """A single parsed stack frame from a sanitizer backtrace."""

    index: int
    function: str
    file: Optional[str] = None
    line: Optional[int] = None
    module: Optional[str] = None
    offset: Optional[str] = None


@dataclass
class AsanReport:
    """Structured representation of a sanitizer crash report."""

    bug_class: str
    sanitizer: Optional[str] = None
    access_type: Optional[str] = None  # "READ" | "WRITE"
    access_size: Optional[int] = None
    fault_address: Optional[int] = None
    is_null_deref: bool = False
    frames: list[StackFrame] = field(default_factory=list)
    summary: Optional[str] = None
    raw: str = ""

    @property
    def top_frame(self) -> Optional[StackFrame]:
        """The first parsed frame of the primary crash stack, if any."""
        return self.frames[0] if self.frames else None


def _parse_frame(index: int, rest: str) -> StackFrame:
    """Parse the text after ``#N 0x...`` into a :class:`StackFrame`."""
    function = ""
    file: Optional[str] = None
    line: Optional[int] = None
    module: Optional[str] = None
    offset: Optional[str] = None

    if rest.startswith("in "):
        body = rest[3:].strip()
        mod_match = _MODULE_OFFSET_RE.search(body)
        if mod_match:
            module = mod_match.group("mod")
            offset = "0x" + mod_match.group("off")
            function = body[: mod_match.start()].strip()
        else:
            loc_match = _FILE_LINE_RE.search(body)
            if loc_match:
                file = loc_match.group("file")
                line = int(loc_match.group("line"))
                function = body[: loc_match.start()].strip()
            else:
                function = body.strip()
    else:
        mod_match = _MODULE_OFFSET_RE.search(rest)
        if mod_match:
            module = mod_match.group("mod")
            offset = "0x" + mod_match.group("off")

    return StackFrame(
        index=index,
        function=function,
        file=file,
        line=line,
        module=module,
        offset=offset,
    )


def _parse_frames(text: str) -> list[StackFrame]:
    """Extract only the first (primary) crash stack from ``text``.

    Sanitizer reports may contain several stacks (crash, freed-by,
    allocated-by).  Each starts again at ``#0``; we stop at the second ``#0``.
    """
    frames: list[StackFrame] = []
    started = False
    for raw_line in text.splitlines():
        match = _FRAME_RE.match(raw_line)
        if not match:
            continue
        idx = int(match.group("idx"))
        if started and idx == 0:
            break  # a new stack section has begun
        frames.append(_parse_frame(idx, match.group("rest")))
        started = True
    return frames


def _ub_kind_from_desc(desc: str) -> str:
    """Turn a UBSan "runtime error" description into a kebab-case kind."""
    head = desc.split(":", 1)[0].strip()
    head = head.split(" (", 1)[0].strip()
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", head).strip("-").lower()
    return slug or "undefined-behavior"


def _detect_sanitizer(text: str) -> Optional[str]:
    if "UndefinedBehaviorSanitizer" in text or "runtime error:" in text:
        return "UndefinedBehaviorSanitizer"
    if "AddressSanitizer" in text:
        return "AddressSanitizer"
    return None


def _normalize_asan_kind(kind: str) -> str:
    if kind == "stack-overflow":
        return "stack-overflow (recursion)"
    return kind


def _classify_bug_class(text: str, sanitizer: Optional[str]) -> str:
    """Determine the bug class string from the report body."""
    summary = _SUMMARY_RE.search(text)

    if sanitizer == "UndefinedBehaviorSanitizer":
        kind: Optional[str] = None
        if summary and summary.group("kind") not in ("undefined-behavior",):
            kind = summary.group("kind")
        if kind is None:
            runtime = _UBSAN_RUNTIME_RE.search(text)
            if runtime:
                kind = _ub_kind_from_desc(runtime.group("desc"))
        if kind is None:
            kind = "undefined-behavior"
        return f"UBSan-{kind}"

    # AddressSanitizer (or unknown, treated as ASan-style).
    if "attempting double-free" in text:
        return "double-free"
    if summary is not None:
        return _normalize_asan_kind(summary.group("kind"))

    error = _ERROR_RE.search(text)
    if error is not None:
        rest = error.group("rest")
        for known in _KNOWN_ASAN_KINDS:
            if rest.startswith(known) or f" {known}" in f" {rest}":
                return _normalize_asan_kind(known)
        # First token as a last resort.
        token = rest.split()[0].strip(":")
        return _normalize_asan_kind(token)

    # Absolute fallback: scan the whole text for a known keyword.
    for known in _KNOWN_ASAN_KINDS:
        if known in text:
            return _normalize_asan_kind(known)
    return "unknown"


def parse(text: str) -> AsanReport:
    """Parse a sanitizer report ``text`` into an :class:`AsanReport`.

    The parser never raises on malformed input; missing fields are simply left
    at their defaults (``None`` / empty).
    """
    sanitizer = _detect_sanitizer(text)
    bug_class = _classify_bug_class(text, sanitizer)

    access_type: Optional[str] = None
    access_size: Optional[int] = None
    access_addr: Optional[int] = None
    access_match = _ACCESS_RE.search(text)
    if access_match:
        access_type = access_match.group("kind")
        access_size = int(access_match.group("size"))
        access_addr = int(access_match.group("addr"), 16)

    fault_address: Optional[int] = None
    addr_match = _ADDR_RE.search(text)
    if addr_match:
        fault_address = int(addr_match.group(1), 16)
    elif access_addr is not None:
        fault_address = access_addr

    is_null_deref = (
        fault_address is not None and fault_address < _NULL_DEREF_THRESHOLD
    )

    summary_line: Optional[str] = None
    for line in text.splitlines():
        if line.strip().startswith("SUMMARY:"):
            summary_line = line.strip()
            break

    return AsanReport(
        bug_class=bug_class,
        sanitizer=sanitizer,
        access_type=access_type,
        access_size=access_size,
        fault_address=fault_address,
        is_null_deref=is_null_deref,
        frames=_parse_frames(text),
        summary=summary_line,
        raw=text,
    )
