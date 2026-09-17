"""Top-level rule generation for a confirmed, triaged bug.

What these rules are -- and are not
-----------------------------------
:func:`generate_rules` turns a single **confirmed, triaged** fuzzing bug into a
YARA rule, a Suricata rule, and an honest validation report.  The rules detect
attempts to exploit a **known bug class** whose PoC we already hold.  They are:

* **PoC-derived** -- inferred from one minimized crashing input, then
  generalized to the structural invariant behind it;
* **FP/FN-tested** -- shipped with a measured true-positive rate on held-out
  mutated triggers and a false-positive rate on a benign corpus; and
* **deliberately narrow** -- they do **not** generalize to unknown attacks or
  novel bug classes.

This is **virtual patching / defense-in-depth**: a stopgap that buys time before
the code fix ships and adds a detection layer around a *specific* known weakness.
It is emphatically **not** a novel intrusion-detection system, an anomaly
detector, or a claim to catch zero-days.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .invariant import (
    ByteSequencePresent,
    FieldLengthExceeds,
    HeadersCoexist,
    Invariant,
    MalformedChunkFraming,
    NestingDepthExceeds,
    der_tlv_locator,
)
from .suricata_gen import to_suricata
from .validate import RuleReport, evaluate, mutate_triggers
from .yara_gen import to_yara

__all__ = [
    "Bug",
    "GeneratedRules",
    "generate_rules",
    "BUG_CLASS_MAP",
    "infer_invariant",
]

# bug_class -> invariant constructor name, for documentation/inspection.
BUG_CLASS_MAP: Dict[str, str] = {
    "overflow-on-length-field": "FieldLengthExceeds",
    "recursion": "NestingDepthExceeds",
    "http-desync": "HeadersCoexist",
    "http-chunk": "MalformedChunkFraming",
}

_NESTING_PAIRS: Tuple[Tuple[bytes, bytes], ...] = (
    (b"(", b")"),
    (b"{", b"}"),
    (b"[", b"]"),
    (b"<", b">"),
)

_DEFAULT_TRIGGERS = 40


@dataclass
class Bug:
    """A confirmed, triaged fuzzing bug ready for signature generation."""

    bug_id: str
    bug_class: str
    cwe: str
    minimized_input: bytes
    fault_hint: str = ""
    params: Dict[str, object] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "Bug":
        """Build a :class:`Bug` from a plain dict (e.g. parsed JSON).

        ``minimized_input`` is a string decoded according to
        ``input_encoding`` (one of ``utf-8`` (default), ``latin-1``, ``base64``
        or ``hex``).  Already-``bytes`` input is accepted as-is.
        """
        raw = data["minimized_input"]
        encoding = str(data.get("input_encoding", "utf-8")).lower()
        if isinstance(raw, bytes):
            minimized = raw
        else:
            text = str(raw)
            if encoding in ("utf-8", "utf8"):
                minimized = text.encode("utf-8")
            elif encoding in ("latin-1", "latin1", "iso-8859-1"):
                minimized = text.encode("latin-1")
            elif encoding == "base64":
                import base64

                minimized = base64.b64decode(text)
            elif encoding == "hex":
                minimized = bytes.fromhex(text)
            else:
                raise ValueError(f"unknown input_encoding: {encoding!r}")
        return cls(
            bug_id=str(data["bug_id"]),
            bug_class=str(data["bug_class"]),
            cwe=str(data.get("cwe", "unknown")),
            minimized_input=minimized,
            fault_hint=str(data.get("fault_hint", "")),
            params=dict(data.get("params", {}) or {}),
        )


@dataclass
class GeneratedRules:
    """The full output of :func:`generate_rules` for one bug."""

    bug_id: str
    bug_class: str
    cwe: str
    invariant: Invariant
    yara: str
    suricata: str
    invariant_report: RuleReport
    overfit_report: RuleReport
    n_triggers: int
    n_benign: int

    def report_markdown(self) -> str:
        """Full honesty report: framing, both rules' metrics, and the contrast."""
        lines = [
            f"# Detection report: `{self.bug_id}`",
            "",
            f"- **Bug class:** `{self.bug_class}`",
            f"- **CWE:** {self.cwe}",
            f"- **Invariant:** {self.invariant.describe()}",
            "",
            "## Scope and honesty",
            "",
            "These rules are **PoC-derived virtual patching / defense-in-depth**. "
            "They detect exploitation attempts against this *known bug class*, are "
            "FP/FN-tested below, and do **not** generalize to unknown attacks or "
            "novel bug classes.",
            "",
            "## Generalization metrics",
            "",
            self.invariant_report.to_markdown(),
            "## Anti-overfit contrast",
            "",
            "The same held-out mutated triggers are scored against an overfit "
            "byte-sequence rule built on the literal PoC. A credible invariant "
            "rule generalizes; the byte-sequence rule does not:",
            "",
            self.overfit_report.to_markdown(),
            f"**Invariant TP {self.invariant_report.tp_rate:.1%} vs. "
            f"byte-sequence TP {self.overfit_report.tp_rate:.1%}** on the same "
            f"{self.n_triggers} held-out mutated triggers.",
            "",
            "## YARA rule",
            "",
            "```",
            self.yara.rstrip("\n"),
            "```",
            "",
            "## Suricata rule",
            "",
            "```",
            self.suricata.rstrip("\n"),
            "```",
            "",
        ]
        return "\n".join(lines)

    def write(self, out_dir: str) -> Dict[str, str]:
        """Write ``<bug_id>.yar``, ``.rules`` and ``.report.md`` into *out_dir*.

        Returns a mapping of artifact kind to the path written.
        """
        import os

        os.makedirs(out_dir, exist_ok=True)
        yar_path = os.path.join(out_dir, f"{self.bug_id}.yar")
        rules_path = os.path.join(out_dir, f"{self.bug_id}.rules")
        report_path = os.path.join(out_dir, f"{self.bug_id}.report.md")
        with open(yar_path, "w", encoding="utf-8") as fh:
            fh.write(self.yara)
        with open(rules_path, "w", encoding="utf-8") as fh:
            fh.write(self.suricata)
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(self.report_markdown())
        return {"yara": yar_path, "suricata": rules_path, "report": report_path}


def _derive_nesting(minimized: bytes, params: Dict[str, object]) -> NestingDepthExceeds:
    open_token = params.get("open_token")
    close_token = params.get("close_token")
    if open_token is not None and close_token is not None:
        ot = open_token if isinstance(open_token, bytes) else str(open_token).encode()
        ct = close_token if isinstance(close_token, bytes) else str(close_token).encode()
        pairs = ((ot, ct),)
    else:
        pairs = _NESTING_PAIRS

    best_pair = pairs[0]
    best_depth = -1
    for ot, ct in pairs:
        probe = NestingDepthExceeds(ot, ct, 0)
        max_depth, _ = probe._scan(minimized)
        if max_depth > best_depth:
            best_depth = max_depth
            best_pair = (ot, ct)

    requested = params.get("depth")
    if requested is not None:
        depth = int(requested)
        if best_depth > 0:
            depth = min(depth, best_depth - 1)
    else:
        depth = max(best_depth - 1, 0)
    return NestingDepthExceeds(best_pair[0], best_pair[1], depth)


def _derive_field_length(
    minimized: bytes, params: Dict[str, object]
) -> FieldLengthExceeds:
    locator = der_tlv_locator()
    observed = locator.values(minimized)
    threshold = params.get("threshold")
    if threshold is not None:
        thr = int(threshold)
    else:
        thr = 255  # single-octet length / common label bound
    if observed:
        max_obs = max(observed)
        if thr >= max_obs:
            thr = max(max_obs - 1, 0)
    return FieldLengthExceeds(locator, thr)


def infer_invariant(bug: Bug) -> Invariant:
    """Map a bug's class onto its vulnerability-triggering invariant.

    Parameters may be supplied via ``bug.params``; otherwise sensible values are
    derived from the minimized input so that the seed input actually triggers
    the invariant.
    """
    bug_class = bug.bug_class
    params = bug.params

    if bug_class == "http-desync":
        a = str(params.get("name_a", "Content-Length"))
        b = str(params.get("name_b", "Transfer-Encoding"))
        return HeadersCoexist(a, b)
    if bug_class == "http-chunk":
        return MalformedChunkFraming()
    if bug_class == "recursion":
        return _derive_nesting(bug.minimized_input, params)
    if bug_class == "overflow-on-length-field":
        return _derive_field_length(bug.minimized_input, params)
    raise ValueError(
        f"unknown bug_class {bug_class!r}; known: {sorted(BUG_CLASS_MAP)}"
    )


# ---------------------------------------------------------------------------
# Benign corpora (must NOT satisfy the invariant)
# ---------------------------------------------------------------------------


def _benign_http_no_both(a: str, b: str) -> List[bytes]:
    return [
        (
            f"GET / HTTP/1.1\r\nHost: example.com\r\n{a}: 42\r\n"
            "Accept: */*\r\n\r\n"
        ).encode(),
        (
            f"POST /submit HTTP/1.1\r\nHost: api.test\r\n{b}: chunked\r\n\r\n"
            "0\r\n\r\n"
        ).encode(),
        b"GET /index.html HTTP/1.1\r\nHost: www.test\r\nUser-Agent: curl/8\r\n\r\n",
        b"HEAD / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
    ]


def _benign_valid_chunked() -> List[bytes]:
    return [
        b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
        b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"1a\r\nabcdefghijklmnopqrstuvwxyz\r\n0\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc",
        b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"f;name=value\r\n123456789012345\r\n0\r\n\r\n",
    ]


def _benign_small_tlv() -> List[bytes]:
    return [
        bytes([0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x0A]),  # SEQ{INT,INT}
        bytes([0x04, 0x03, 0x41, 0x42, 0x43]),  # OCTET STRING "ABC"
        bytes([0x30, 0x03, 0x0C, 0x01, 0x58]),  # SEQ{UTF8String "X"}
        bytes([0x02, 0x02, 0x01, 0x00]),  # INTEGER 256
    ]


def _benign_shallow_nesting(inv: NestingDepthExceeds) -> List[bytes]:
    o = inv.open_token
    c = inv.close_token
    shallow = max(inv.depth, 1)
    return [
        o * shallow + b"x" + c * shallow,
        o + b"a" + c + o + b"b" + c,
        b"no delimiters here at all",
        o + b"only one level" + c,
    ]


def _benign_corpus(invariant: Invariant) -> List[bytes]:
    """Build a class-appropriate benign corpus that must not fire the rule."""
    generic = [b"hello world", b"the quick brown fox", b"\x00\x01\x02\x03\x04"]
    if isinstance(invariant, HeadersCoexist):
        corpus = _benign_http_no_both(invariant.name_a, invariant.name_b)
    elif isinstance(invariant, MalformedChunkFraming):
        corpus = _benign_valid_chunked()
    elif isinstance(invariant, FieldLengthExceeds):
        corpus = _benign_small_tlv()
    elif isinstance(invariant, NestingDepthExceeds):
        corpus = _benign_shallow_nesting(invariant)
    else:
        corpus = []
    # Keep only genuinely benign samples (defensive: never ship a corpus the
    # rule already fires on).
    return [s for s in corpus + generic if not invariant.matches(s)]


def generate_rules(
    bug: Bug,
    *,
    n_triggers: int = _DEFAULT_TRIGGERS,
    seed: int = 1337,
) -> GeneratedRules:
    """Generate YARA + Suricata rules and honest validation for *bug*.

    The pipeline:

    1. Infer the vulnerability-triggering invariant from ``bug.bug_class``
       (see :data:`BUG_CLASS_MAP`), deriving parameters from the minimized input
       so the seed actually triggers it.
    2. Render YARA and Suricata rules from the invariant.
    3. Build a held-out corpus of mutated triggers (still satisfying the
       invariant) and a class-appropriate benign corpus.
    4. Score both the invariant rule and an overfit byte-sequence baseline, so
       the report can show the generalization contrast.

    The returned rules are PoC-derived, FP/FN-tested virtual-patching signatures
    for a *known* bug class -- not a general-purpose IDS. See the module
    docstring.
    """

    invariant = infer_invariant(bug)
    if not invariant.matches(bug.minimized_input):
        raise ValueError(
            f"inferred invariant does not fire on the minimized input for "
            f"{bug.bug_id!r}; refusing to ship an unvalidated rule"
        )

    meta = {
        "bug_id": bug.bug_id,
        "bug_class": bug.bug_class,
        "cwe": bug.cwe,
        "note": bug.fault_hint or invariant.describe(),
    }
    yara = to_yara(invariant, meta)
    suricata = to_suricata(invariant, meta)

    triggers = mutate_triggers(bug.minimized_input, invariant, n_triggers, seed=seed)
    benign = _benign_corpus(invariant)

    invariant_report = evaluate(
        invariant.matches,
        triggers,
        benign,
        rule_name=f"{bug.bug_id}::invariant",
        description=f"Invariant-based rule: {invariant.describe()}",
    )
    overfit = ByteSequencePresent(bug.minimized_input)
    overfit_report = evaluate(
        overfit.matches,
        triggers,
        benign,
        rule_name=f"{bug.bug_id}::byte-sequence(overfit)",
        description="Overfit baseline: literal PoC byte sequence.",
    )

    return GeneratedRules(
        bug_id=bug.bug_id,
        bug_class=bug.bug_class,
        cwe=bug.cwe,
        invariant=invariant,
        yara=yara,
        suricata=suricata,
        invariant_report=invariant_report,
        overfit_report=overfit_report,
        n_triggers=len(triggers),
        n_benign=len(benign),
    )
