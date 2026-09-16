"""Render an :class:`~detect.invariant.Invariant` into a Suricata/Snort rule.

Suricata is a network IDS: it inspects live traffic, so it is the right home
for the desync and chunked-framing invariants (which are about how bytes cross
the wire), and it can approximate host-oriented invariants on the raw stream.
As in :mod:`detect.yara_gen`, any approximate match records a ``limitation``
entry in the rule ``metadata`` so operators know what the rule really covers.

Signature IDs (sids) are generated deterministically from the bug id, mapped
into the local/private sid range ``1_000_000``--``1_999_999`` so the same bug
always yields the same sid.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List

from .invariant import (
    ByteSequencePresent,
    FieldLengthExceeds,
    HeadersCoexist,
    Invariant,
    MalformedChunkFraming,
    NestingDepthExceeds,
)

__all__ = ["to_suricata", "sid_for"]

Meta = Dict[str, object]

_SID_BASE = 1_000_000
_SID_SPAN = 1_000_000


def sid_for(bug_id: str) -> int:
    """Deterministically map *bug_id* into the local sid range."""
    digest = hashlib.sha256(bug_id.encode("utf-8")).hexdigest()
    return _SID_BASE + (int(digest[:8], 16) % _SID_SPAN)


def _clean(value: object) -> str:
    """Make a value safe inside a Suricata option (no ``;`` or ``"``)."""
    return (
        str(value)
        .replace("\\", " ")
        .replace('"', "'")
        .replace(";", ",")
        .replace("\n", " ")
    )


def _clean_meta(value: object) -> str:
    """Make a value safe inside a comma-separated ``metadata:`` list."""
    return _clean(value).replace(",", " ")


def _metadata(meta: Meta, limitation: str = "") -> str:
    """Build the ``metadata:`` option value."""
    items = [
        f"bug_id {_clean_meta(meta.get('bug_id', 'unknown'))}",
        f"bug_class {_clean_meta(meta.get('bug_class', 'unknown'))}",
        f"cwe {_clean_meta(meta.get('cwe', 'unknown'))}",
        "approach invariant-based",
    ]
    if limitation:
        items.append(f"limitation {_clean_meta(limitation)}")
    return ", ".join(items)


def to_suricata(invariant: Invariant, meta: Meta) -> str:
    """Render *invariant* into a syntactically valid Suricata rule string.

    Args:
        invariant: the structural predicate to encode.
        meta: rule metadata; recognized keys are ``bug_id``, ``bug_class``,
            ``cwe`` and ``note``.

    Returns:
        A complete ``alert ... (...)`` rule terminated by a newline, with
        ``msg``, ``classtype``, ``sid``, ``rev`` and ``metadata`` set. Approximate
        matches carry a ``limitation`` entry in the metadata.
    """

    bug_id = str(meta.get("bug_id", "unknown"))
    sid = sid_for(bug_id)
    note = str(meta.get("note", invariant.describe()))
    options: List[str]
    header: str
    classtype: str
    limitation = ""

    if isinstance(invariant, HeadersCoexist):
        header = "alert http any any -> any any"
        classtype = "protocol-command-decode"
        options = [
            f'msg:"INVARIANT {bug_id} {_clean(note)}"',
            "flow:established,to_server",
            "http.header_names",
            f'content:"{_clean(invariant.name_a)}"; nocase',
            "http.header_names",
            f'content:"{_clean(invariant.name_b)}"; nocase',
        ]
        limitation = (
            "Matches coexistence of both header names in one request; does not "
            "adjudicate which framing the peers honor."
        )

    elif isinstance(invariant, MalformedChunkFraming):
        header = "alert http any any -> any any"
        classtype = "protocol-command-decode"
        options = [
            f'msg:"INVARIANT {bug_id} {_clean(note)}"',
            "flow:established,to_server",
            "http.header",
            'content:"chunked"; nocase',
            "http.request_body",
            r'pcre:"/^[0-9A-Fa-f]*[^0-9A-Fa-f;\r\n]/m"',
        ]
        limitation = (
            "pcre approximates a non-hex chunk-size token in the reassembled "
            "body; exact chunk boundary tracking is left to the host parser."
        )

    elif isinstance(invariant, FieldLengthExceeds):
        header = "alert tcp any any -> any any"
        classtype = "protocol-command-decode"
        options = [
            f'msg:"INVARIANT {bug_id} {_clean(note)}"',
            "flow:established",
            # DER long-form length introducer of 3+ octets => length >= 65536.
            r'pcre:"/[\x83-\x8f]/"',
        ]
        limitation = (
            f"Network approximation of '{invariant.field_locator.name} > "
            f"{invariant.threshold}': flags DER long-form length introducers of "
            f"3+ octets. Byte-exact length arithmetic is not expressible; the "
            f"host YARA/parser is authoritative."
        )

    elif isinstance(invariant, NestingDepthExceeds):
        header = "alert tcp any any -> any any"
        classtype = "protocol-command-decode"
        run = invariant.open_token * invariant.depth
        options = [
            f'msg:"INVARIANT {bug_id} {_clean(note)}"',
            "flow:established",
            f'content:"{_clean(run.decode("latin-1"))}"',
        ]
        limitation = (
            f"Approximates recursion depth > {invariant.depth} by matching "
            f"{invariant.depth} consecutive open tokens; nesting with content "
            f"between delimiters is not counted on the wire."
        )

    elif isinstance(invariant, ByteSequencePresent):
        header = "alert tcp any any -> any any"
        classtype = "misc-attack"
        options = [
            f'msg:"OVERFIT {bug_id} literal PoC bytes"',
            "flow:established",
            f'content:"{_clean(invariant.seq.decode("latin-1"))}"',
        ]
        limitation = (
            "OVERFIT baseline: literal PoC content match; defeated by any "
            "padding, reordering or single-byte change."
        )

    else:  # pragma: no cover - defensive
        raise TypeError(f"no Suricata renderer for {type(invariant).__name__}")

    options.append(f"classtype:{classtype}")
    options.append(f"sid:{sid}")
    options.append("rev:1")
    options.append(f"metadata:{_metadata(meta, limitation)}")

    body = "; ".join(options)
    return f"{header} ({body};)\n"
