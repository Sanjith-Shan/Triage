"""Render an :class:`~detect.invariant.Invariant` into a YARA rule string.

YARA is a host/file detection language.  Some invariants map cleanly onto it
(header coexistence is just two string matches); others -- notably arbitrary
length arithmetic on a variable-width encoding -- cannot be expressed exactly.
Where the match is only an approximation, the emitted rule carries a
``meta: limitation = "..."`` line stating honestly what the rule actually
detects versus the true invariant.  This keeps the generator from silently
shipping a rule that claims more than it can deliver.
"""

from __future__ import annotations

import re
from typing import Dict, List

from .invariant import (
    ByteSequencePresent,
    FieldLengthExceeds,
    HeadersCoexist,
    Invariant,
    MalformedChunkFraming,
    NestingDepthExceeds,
)

__all__ = ["to_yara"]

Meta = Dict[str, object]


def _rule_name(bug_id: str) -> str:
    """Coerce *bug_id* into a valid YARA identifier."""
    name = re.sub(r"[^0-9A-Za-z_]", "_", bug_id)
    if not name or not re.match(r"[A-Za-z_]", name[0]):
        name = "detect_" + name
    return name


def _escape(value: object) -> str:
    """Escape a value for a YARA double-quoted meta string."""
    text = str(value)
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _meta_block(meta: Meta, extra: Dict[str, str]) -> List[str]:
    """Build the ``meta:`` section lines.

    ``extra`` (e.g. a limitation note) is merged after the caller-supplied meta.
    """
    lines = ["  meta:"]
    merged: Dict[str, object] = {
        "bug_id": meta.get("bug_id", "unknown"),
        "bug_class": meta.get("bug_class", "unknown"),
        "cwe": meta.get("cwe", "unknown"),
        "approach": "invariant-based",
    }
    if "note" in meta:
        merged["description"] = meta["note"]
    merged.update(extra)
    for key, value in merged.items():
        lines.append(f'    {key} = "{_escape(value)}"')
    return lines


def _bytes_to_yara_hex(seq: bytes) -> str:
    """Render bytes as a YARA hex string body, e.g. ``{ 41 42 43 }``."""
    return "{ " + " ".join(f"{b:02x}" for b in seq) + " }"


def _text_string(name: str, value: str, *, nocase: bool = True) -> str:
    flags = " nocase" if nocase else ""
    return f'    {name} = "{value}"{flags}'


def to_yara(invariant: Invariant, meta: Meta) -> str:
    """Render *invariant* into a syntactically valid YARA rule string.

    Args:
        invariant: the structural predicate to encode.
        meta: rule metadata; recognized keys are ``bug_id``, ``bug_class``,
            ``cwe`` and ``note``.

    Returns:
        A complete ``rule { meta: ... strings: ... condition: ... }`` string.
        For invariants YARA cannot express exactly, a ``limitation`` meta line
        documents the approximation.
    """

    rule = _rule_name(str(meta.get("bug_id", "unknown")))
    strings: List[str]
    condition: str
    extra: Dict[str, str] = {}

    if isinstance(invariant, HeadersCoexist):
        strings = [
            _text_string("$a", f"{invariant.name_a}:"),
            _text_string("$b", f"{invariant.name_b}:"),
        ]
        condition = "$a and $b"
        extra["limitation"] = (
            "Fires on any file containing both header names; does not verify "
            "they belong to the same HTTP request/framing. Prefer the Suricata "
            "rule for on-the-wire desync detection."
        )

    elif isinstance(invariant, MalformedChunkFraming):
        # Approximate: Transfer-Encoding: chunked present AND a chunk-size line
        # whose first token contains a non-hex, non-';' character.
        strings = [
            _text_string("$te", "Transfer-Encoding:"),
            "    $chunked = \"chunked\" nocase",
            r"    $badsize = /\r\n[0-9A-Fa-f]*[^0-9A-Fa-f;\r\n][^\r\n]*\r\n/",
        ]
        condition = "$te and $chunked and $badsize"
        extra["limitation"] = (
            "Regex approximates a malformed chunk-size line anywhere in the "
            "file; it does not track HTTP message boundaries or which chunk is "
            "first."
        )

    elif isinstance(invariant, NestingDepthExceeds):
        # YARA cannot count recursion depth; approximate by a run of >= depth
        # consecutive open tokens (deep nesting with no intervening content).
        run = invariant.open_token * invariant.depth
        strings = [f"    $deep = {_bytes_to_yara_hex(run)}"]
        condition = "$deep"
        extra["limitation"] = (
            f"Detects {invariant.depth} consecutive {invariant.open_token!r} "
            f"tokens only; genuine deep nesting with content between delimiters "
            f"(the true invariant: max depth > {invariant.depth}) is not "
            f"counted by YARA's non-recursive matcher."
        )

    elif isinstance(invariant, FieldLengthExceeds):
        # YARA cannot do BER length arithmetic. Approximate: a DER long-form
        # length introducer declaring 3+ length octets (0x83/0x84/0x85...),
        # which encodes lengths >= 2^16 -- almost always oversized.
        strings = [
            r"    $len3 = { 83 ?? ?? ?? }",
            r"    $len4 = { 84 ?? ?? ?? ?? }",
            r"    $len5 = { 85 ?? ?? ?? ?? ?? }",
        ]
        condition = "any of them"
        extra["limitation"] = (
            f"Approximates '{invariant.field_locator.name} > "
            f"{invariant.threshold}' by matching DER long-form length "
            f"introducers of 3+ octets (declared length >= 65536). YARA cannot "
            f"evaluate the exact numeric threshold; the Suricata/host parser is "
            f"authoritative."
        )

    elif isinstance(invariant, ByteSequencePresent):
        strings = [f"    $poc = {_bytes_to_yara_hex(invariant.seq)}"]
        condition = "$poc"
        extra["limitation"] = (
            "OVERFIT baseline: matches the literal PoC bytes only. Any padding, "
            "reordering or single-byte change defeats it. Not a credible rule."
        )

    else:  # pragma: no cover - defensive
        raise TypeError(f"no YARA renderer for {type(invariant).__name__}")

    lines: List[str] = [f"rule {rule}", "{"]
    lines += _meta_block(meta, extra)
    lines.append("  strings:")
    lines += strings
    lines.append("  condition:")
    lines.append(f"    {condition}")
    lines.append("}")
    return "\n".join(lines) + "\n"
