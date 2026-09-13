"""Structural invariants: the *why* an input is dangerous, not the *what*.

The central thesis of this package
----------------------------------
A detection rule that matches the literal proof-of-concept (PoC) bytes is an
"atomic-of-one" signature: it fires on exactly one input and nothing else.  It
is worthless the moment an attacker changes a single padding byte, because it
never captured *why* the input was dangerous -- only *which* bytes the fuzzer
happened to emit.

A **credible** rule matches the *vulnerability-triggering invariant*: the
structural property of the input that actually drives the bug class.  For an
oversized-length overflow that property is "an encoded length field exceeds the
buffer bound", regardless of which tag carries it or what padding surrounds it.

This module defines a small, composable vocabulary of such invariants.  Each
one:

* actually parses enough structure to *evaluate* its predicate
  (:meth:`Invariant.matches`),
* knows which byte spans carry the invariant, so held-out mutations can be
  generated that preserve it (:meth:`Invariant.protected_regions`), and
* carries a human description used when rendering rules and reports.

The concrete generators live in :mod:`detect.yara_gen` and
:mod:`detect.suricata_gen`; the honesty engine lives in :mod:`detect.validate`.

:class:`ByteSequencePresent` is included deliberately as the **anti-pattern
baseline** -- the overfit byte-sequence rule -- so the validation harness can
demonstrate, with numbers, why invariant rules generalize and byte rules do
not.  Do not model a real bug class with it.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "Invariant",
    "Span",
    "TLVRecord",
    "FieldLocator",
    "der_tlv_records",
    "der_tlv_locator",
    "FieldLengthExceeds",
    "NestingDepthExceeds",
    "HeadersCoexist",
    "MalformedChunkFraming",
    "ByteSequencePresent",
]

Span = Tuple[int, int]
"""A half-open byte interval ``[start, end)`` inside an input buffer."""


class Invariant(abc.ABC):
    """A structural predicate over bytes that captures *why* input is dangerous.

    Subclasses must implement :meth:`matches`.  They should override
    :meth:`protected_regions` to report the byte spans that carry the
    invariant, so :func:`detect.validate.mutate_triggers` can mutate *away*
    from those spans and produce held-out triggers that still fire.
    """

    #: Short kind tag used by the rule generators to dispatch.
    kind: str = "invariant"

    @abc.abstractmethod
    def matches(self, data: bytes) -> bool:
        """Return ``True`` iff *data* satisfies the invariant."""

    def protected_regions(self, data: bytes) -> List[Span]:
        """Byte spans of *data* that carry the invariant and must be preserved.

        The default is empty (no region is protected), which makes any
        mutation fair game.  Overriding this lets mutation preserve the
        invariant while still disturbing the rest of the payload.
        """
        return []

    def describe(self) -> str:
        """One-line, human-readable description of the invariant."""
        return self.__class__.__name__


# ---------------------------------------------------------------------------
# TLV / DER length parsing (shared by FieldLengthExceeds)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TLVRecord:
    """A decoded BER/DER Tag-Length-Value record.

    ``length`` is the value *claimed by the length octets*, which may be far
    larger than the bytes actually present -- that discrepancy is precisely the
    oversized-length overflow condition.
    """

    tag: int
    length: int
    tag_start: int  # offset of the first tag byte
    header_end: int  # offset just past the length octets (== value start)
    constructed: bool


def der_tlv_records(data: bytes, _max_depth: int = 32) -> List[TLVRecord]:
    """Parse *data* as a sequence of BER/DER TLVs, recursing into constructed types.

    The parser is deliberately lenient: it decodes the length from the length
    octets even when the declared length overruns the available bytes, because
    an over-declared length *is* the bug we want to detect.  Indefinite-length
    encodings (``0x80``) are skipped rather than decoded.
    """

    records: List[TLVRecord] = []

    def parse(start: int, end: int, depth: int) -> None:
        i = start
        while i < end and depth < _max_depth:
            tag_start = i
            tag = data[i]
            i += 1
            # High-tag-number form: subsequent octets while high bit set.
            if tag & 0x1F == 0x1F:
                while i < end and data[i] & 0x80:
                    i += 1
                if i < end:
                    i += 1
            if i >= end:
                break
            l0 = data[i]
            i += 1
            if l0 & 0x80 == 0:
                length = l0
            else:
                num = l0 & 0x7F
                if num == 0:
                    # Indefinite length; we do not model it, stop this run.
                    break
                octets = data[i : min(end, i + num)]
                length = int.from_bytes(octets, "big") if octets else 0
                i += num
            header_end = i
            constructed = bool(tag & 0x20)
            records.append(
                TLVRecord(
                    tag=tag,
                    length=length,
                    tag_start=tag_start,
                    header_end=header_end,
                    constructed=constructed,
                )
            )
            content_end = min(end, header_end + length)
            if constructed and content_end > header_end:
                parse(header_end, content_end, depth + 1)
            i = content_end

    parse(0, len(data), 0)
    return records


@dataclass(frozen=True)
class FieldLocator:
    """Names and extracts encoded length values from an input.

    ``extract`` returns ``(length_value, header_span)`` tuples; the header span
    is the byte range of the tag+length octets, protected during mutation.
    """

    name: str
    extract: Callable[[bytes], List[Tuple[int, Span]]]

    def values(self, data: bytes) -> List[int]:
        return [v for v, _ in self.extract(data)]

    def spans(self, data: bytes) -> List[Span]:
        return [s for _, s in self.extract(data)]


def der_tlv_locator() -> FieldLocator:
    """A :class:`FieldLocator` over BER/DER TLV length fields."""

    def extract(data: bytes) -> List[Tuple[int, Span]]:
        return [
            (r.length, (r.tag_start, r.header_end)) for r in der_tlv_records(data)
        ]

    return FieldLocator(name="der-tlv-length", extract=extract)


@dataclass
class FieldLengthExceeds(Invariant):
    """An encoded length field exceeds a bound.

    Models the oversized-DER-field / over-length-label / oversized-TLV overflow
    class (CWE-130 / CWE-120): a length prefix claims more bytes than the
    consuming buffer can hold.  The invariant is independent of *which* field
    carries the length or what surrounds it -- only the numeric relationship
    ``declared_length > threshold`` matters.
    """

    field_locator: FieldLocator
    threshold: int
    kind: str = field(default="field-length-exceeds", init=False)

    def matches(self, data: bytes) -> bool:
        return any(v > self.threshold for v in self.field_locator.values(data))

    def protected_regions(self, data: bytes) -> List[Span]:
        return [
            span
            for value, span in self.field_locator.extract(data)
            if value > self.threshold
        ]

    def describe(self) -> str:
        return (
            f"{self.field_locator.name} length field exceeds {self.threshold} bytes"
        )


@dataclass
class NestingDepthExceeds(Invariant):
    """Nesting depth of paired tokens exceeds a bound.

    Models the unbounded-recursion / stack-exhaustion class (CWE-674): a parser
    recurses once per nesting level, and a sufficiently deep input overflows
    the stack.  The invariant is the *depth*, not the specific bytes between the
    delimiters.
    """

    open_token: bytes
    close_token: bytes
    depth: int
    kind: str = field(default="nesting-depth-exceeds", init=False)

    def _scan(self, data: bytes) -> Tuple[int, List[Span]]:
        depth = 0
        max_depth = 0
        positions: List[Span] = []
        i = 0
        n = len(data)
        lo = len(self.open_token)
        lc = len(self.close_token)
        while i < n:
            if lo and data[i : i + lo] == self.open_token:
                depth += 1
                max_depth = max(max_depth, depth)
                positions.append((i, i + lo))
                i += lo
                continue
            if lc and data[i : i + lc] == self.close_token:
                if depth > 0:
                    positions.append((i, i + lc))
                    depth -= 1
                i += lc
                continue
            i += 1
        return max_depth, positions

    def matches(self, data: bytes) -> bool:
        max_depth, _ = self._scan(data)
        return max_depth > self.depth

    def protected_regions(self, data: bytes) -> List[Span]:
        # Preserve every delimiter token so the achieved depth is unchanged.
        _, positions = self._scan(data)
        return positions

    def describe(self) -> str:
        return (
            f"nesting of {self.open_token!r}/{self.close_token!r} deeper than "
            f"{self.depth} levels"
        )


# ---------------------------------------------------------------------------
# HTTP header parsing (shared by HeadersCoexist / MalformedChunkFraming)
# ---------------------------------------------------------------------------


def _header_region(data: bytes) -> Tuple[int, bytes]:
    """Return ``(header_end, newline)`` for an HTTP-ish message.

    ``header_end`` is the offset of the blank line separating headers from the
    body (or ``len(data)`` if there is none); ``newline`` is the detected line
    terminator (``\\r\\n`` preferred).
    """

    idx = data.find(b"\r\n\r\n")
    if idx != -1:
        return idx, b"\r\n"
    idx = data.find(b"\n\n")
    if idx != -1:
        return idx, b"\n"
    nl = b"\r\n" if b"\r\n" in data else b"\n"
    return len(data), nl


def _header_lines(data: bytes) -> List[Tuple[bytes, int, int]]:
    """Yield ``(name_lower, line_start, line_end)`` for each header line.

    The request/status line (the first line) is skipped, as are continuation
    and malformed lines without a colon.
    """

    header_end, nl = _header_region(data)
    lines: List[Tuple[bytes, int, int]] = []
    i = 0
    first = True
    while i <= header_end:
        j = data.find(nl, i)
        if j == -1 or j > header_end:
            j = header_end
        line = data[i:j]
        if not first and line:
            colon = line.find(b":")
            if colon != -1:
                name = line[:colon].strip().lower()
                lines.append((name, i, j))
        first = False
        if j == header_end:
            break
        i = j + len(nl)
    return lines


@dataclass
class HeadersCoexist(Invariant):
    """Two named headers are present in the same message.

    Models the HTTP request-smuggling / desync invariant (CWE-444): when both
    ``Content-Length`` and ``Transfer-Encoding`` are present, front-end and
    back-end servers can disagree on message framing.  The danger is the
    *coexistence*, not the specific values -- so this invariant ignores order,
    casing, and everything else on the lines.
    """

    name_a: str
    name_b: str
    kind: str = field(default="headers-coexist", init=False)

    def _targets(self) -> Tuple[bytes, bytes]:
        return self.name_a.encode().lower(), self.name_b.encode().lower()

    def matches(self, data: bytes) -> bool:
        a, b = self._targets()
        names = {name for name, _, _ in _header_lines(data)}
        return a in names and b in names

    def protected_regions(self, data: bytes) -> List[Span]:
        a, b = self._targets()
        return [
            (start, end)
            for name, start, end in _header_lines(data)
            if name in (a, b)
        ]

    def describe(self) -> str:
        return f"headers {self.name_a!r} and {self.name_b!r} coexist"


@dataclass
class MalformedChunkFraming(Invariant):
    """The first chunk-size line is not valid hex framing.

    Models the HTTP chunked-encoding parsing class (CWE-444 / CWE-20): a
    chunk-size token that is not valid hexadecimal, or that carries trailing
    junk (anything after the size that is not a well-formed ``;chunk-ext``),
    is parsed inconsistently by different servers.  The invariant is the
    malformation of the framing, independent of chunk contents.
    """

    kind: str = field(default="malformed-chunk-framing", init=False)

    def _body_offset(self, data: bytes) -> int:
        idx = data.find(b"\r\n\r\n")
        if idx != -1:
            return idx + 4
        idx = data.find(b"\n\n")
        if idx != -1:
            return idx + 2
        return 0

    def _first_size_line(self, data: bytes) -> Optional[Tuple[bytes, int, int]]:
        start = self._body_offset(data)
        body = data[start:]
        if not body:
            return None
        nl = b"\r\n" if b"\r\n" in body else b"\n"
        j = body.find(nl)
        if j == -1:
            j = len(body)
        return body[:j], start, start + j

    @staticmethod
    def _is_malformed(line: bytes) -> bool:
        size_field, _sep, _ext = line.partition(b";")
        size_field = size_field.strip()
        if size_field == b"":
            return True
        try:
            int(size_field, 16)
        except ValueError:
            return True
        return False

    def matches(self, data: bytes) -> bool:
        parsed = self._first_size_line(data)
        if parsed is None:
            return False
        line, _s, _e = parsed
        return self._is_malformed(line)

    def protected_regions(self, data: bytes) -> List[Span]:
        parsed = self._first_size_line(data)
        if parsed is None:
            return []
        line, start, end = parsed
        if self._is_malformed(line):
            return [(start, end)]
        return []

    def describe(self) -> str:
        return "chunk-size line is not valid hex framing"


@dataclass
class ByteSequencePresent(Invariant):
    """ANTI-PATTERN BASELINE: a literal byte sequence is present.

    This is the overfit "atomic-of-one" signature the rest of the package
    exists to argue against.  It captures nothing about *why* an input is
    dangerous -- only that a specific run of bytes appears verbatim.  Any
    padding, reordering, or single-byte change away from the recorded sequence
    defeats it.

    It is retained solely so :mod:`detect.validate` can score it against
    held-out mutated triggers and demonstrate, numerically, how poorly a
    byte-sequence rule generalizes compared with a real invariant.  **Never use
    it to model a bug class.**
    """

    seq: bytes
    kind: str = field(default="byte-sequence-present", init=False)

    def matches(self, data: bytes) -> bool:
        return self.seq in data

    def protected_regions(self, data: bytes) -> List[Span]:
        idx = data.find(self.seq)
        if idx == -1:
            return []
        return [(idx, idx + len(self.seq))]

    def describe(self) -> str:
        preview = self.seq[:24]
        return f"literal byte sequence {preview!r} present (OVERFIT baseline)"
