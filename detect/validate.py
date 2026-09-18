"""The honesty engine: measure how well a rule generalizes.

A rule is only credible if it ships with honest generalization metrics:

* **True-positive rate (TP)** over a *held-out* set of mutated triggers -- inputs
  that were *not* used to build the rule but that still satisfy the bug-class
  invariant.  A rule that captured the invariant scores ~100%; a rule that
  memorized the PoC bytes scores poorly.
* **False-positive rate (FP)** over a benign corpus -- inputs that must *not*
  fire the rule.

:func:`mutate_triggers` is what makes the TP number meaningful.  It takes a
seed trigger and an :class:`~detect.invariant.Invariant`, and produces variants
that *still satisfy the invariant* by mutating away from the invariant-bearing
byte spans (via :meth:`Invariant.protected_regions`).  Padding, reordering and
byte substitution disturb the payload without disturbing the structural
property.  This is precisely the input distribution on which an overfit
byte-sequence rule falls apart while an invariant rule holds.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .invariant import Invariant, Span

__all__ = ["RuleReport", "evaluate", "mutate_triggers"]

RuleMatcher = Callable[[bytes], bool]


@dataclass
class RuleReport:
    """Generalization metrics for a single rule matcher."""

    rule_name: str
    tp_count: int
    trigger_count: int
    fp_count: int
    benign_count: int
    description: str = ""

    @property
    def tp_rate(self) -> float:
        """Fraction of held-out mutated triggers the rule detects."""
        if self.trigger_count == 0:
            return 0.0
        return self.tp_count / self.trigger_count

    @property
    def fp_rate(self) -> float:
        """Fraction of the benign corpus the rule wrongly fires on."""
        if self.benign_count == 0:
            return 0.0
        return self.fp_count / self.benign_count

    def to_markdown(self) -> str:
        """Render the report as a Markdown fragment."""
        lines = [
            f"### Rule: `{self.rule_name}`",
            "",
        ]
        if self.description:
            lines += [f"_{self.description}_", ""]
        lines += [
            "| Metric | Value | Counts |",
            "| --- | --- | --- |",
            f"| True-positive rate (held-out mutated triggers) | "
            f"{self.tp_rate:.1%} | {self.tp_count}/{self.trigger_count} |",
            f"| False-positive rate (benign corpus) | "
            f"{self.fp_rate:.1%} | {self.fp_count}/{self.benign_count} |",
            "",
        ]
        return "\n".join(lines)


def evaluate(
    rule_matcher: RuleMatcher,
    triggers: List[bytes],
    benign: List[bytes],
    *,
    rule_name: str = "rule",
    description: str = "",
) -> RuleReport:
    """Score *rule_matcher* against held-out triggers and a benign corpus.

    Args:
        rule_matcher: the deployed detection predicate under test.
        triggers: held-out inputs that *should* fire (e.g. the output of
            :func:`mutate_triggers`).
        benign: inputs that *must not* fire.
        rule_name: label for the report.
        description: optional human note.

    Returns:
        A :class:`RuleReport` with TP/FP rates and raw counts.
    """

    tp = sum(1 for t in triggers if rule_matcher(t))
    fp = sum(1 for b in benign if rule_matcher(b))
    return RuleReport(
        rule_name=rule_name,
        tp_count=tp,
        trigger_count=len(triggers),
        fp_count=fp,
        benign_count=len(benign),
        description=description,
    )


def _protected_index(data: bytes, regions: List[Span]) -> List[bool]:
    """Boolean mask: ``True`` where a byte must not be mutated."""
    mask = [False] * len(data)
    for start, end in regions:
        for i in range(max(0, start), min(len(data), end)):
            mask[i] = True
    return mask


def _mutable_positions(data: bytes, mask: List[bool]) -> List[int]:
    """Offsets that are safe to overwrite.

    A byte is safe when it is outside every protected region and is not part of
    the line structure (``\\r`` / ``\\n``), so mutation cannot accidentally
    merge or split header/framing lines and thereby break the invariant.
    """
    structural = (0x0D, 0x0A)  # CR, LF
    return [
        i
        for i, protected in enumerate(mask)
        if not protected and data[i] not in structural
    ]


def _reorder_headers(
    data: bytes, invariant: Invariant, rng: random.Random
) -> bytes:
    """Swap two non-protected header lines of an HTTP-ish message.

    Preserves the protected (invariant-bearing) lines in place and only permutes
    other headers, so header-coexistence and framing invariants are unaffected
    while the raw byte order changes.
    """
    from .invariant import _header_lines  # local import: internal helper

    nl = b"\r\n" if b"\r\n" in data else b"\n"
    lines = _header_lines(data)
    if len(lines) < 3:
        return data
    protected = invariant.protected_regions(data)
    protected_spans = set((s, e) for s, e in protected)
    movable = [
        (start, end) for _n, start, end in lines if (start, end) not in protected_spans
    ]
    if len(movable) < 2:
        return data
    i, j = rng.sample(range(len(movable)), 2)
    (si, ei), (sj, ej) = movable[i], movable[j]
    if si > sj:
        (si, ei), (sj, ej) = (sj, ej), (si, ei)
    # Splice the two line contents, keeping everything else byte-identical.
    new = data[:si] + data[sj:ej] + data[ei:sj] + data[si:ei] + data[ej:]
    return new


def _random_bytes(rng: random.Random, n: int) -> bytes:
    # Printable-ish, avoiding CR/LF so we never introduce framing.
    return bytes(rng.randrange(0x20, 0x7F) for _ in range(n))


def mutate_triggers(
    seed_trigger: bytes,
    invariant: Invariant,
    n: int,
    *,
    seed: int = 1337,
    rng: Optional[random.Random] = None,
) -> List[bytes]:
    """Produce ``n`` held-out variants of *seed_trigger* that still fire.

    Each variant is built by applying, away from the invariant-bearing spans:

    * random padding prepended and/or appended,
    * random byte substitutions in the payload (outside protected regions and
      away from line structure), and
    * header reordering for HTTP-ish messages.

    Every candidate is re-checked with ``invariant.matches`` and only kept if
    the structural property survived, guaranteeing the returned set is a valid
    held-out trigger corpus.  Because each variant disturbs payload bytes that
    an overfit :class:`~detect.invariant.ByteSequencePresent` rule keyed on, the
    contrast in TP rate between an invariant rule and a byte-sequence rule is
    the whole demonstration.

    The result is deterministic for a given ``seed`` (useful for tests).
    """

    if rng is None:
        rng = random.Random(seed)

    results: List[bytes] = []
    seen = {seed_trigger}
    attempts = 0
    max_attempts = max(200, n * 100)

    while len(results) < n and attempts < max_attempts:
        attempts += 1
        variant = seed_trigger

        # Always disturb at least some payload bytes so padding-only variants
        # (which a literal-substring rule would still match) do not dominate.
        mask = _protected_index(variant, invariant.protected_regions(variant))
        positions = _mutable_positions(variant, mask)
        if positions:
            k = min(len(positions), rng.randint(2, 6))
            chosen = rng.sample(positions, k)
            buf = bytearray(variant)
            for pos in chosen:
                new_byte = rng.randrange(0x20, 0x7F)
                if new_byte == buf[pos]:
                    new_byte = (new_byte + 1) if new_byte < 0x7E else 0x20
                buf[pos] = new_byte
            variant = bytes(buf)

        # Optional header reordering (HTTP-ish inputs only).
        if rng.random() < 0.5:
            variant = _reorder_headers(variant, invariant, rng)

        # Optional padding, always outside the message proper.
        if rng.random() < 0.6:
            variant = _random_bytes(rng, rng.randint(1, 16)) + variant
        if rng.random() < 0.6:
            variant = variant + _random_bytes(rng, rng.randint(1, 16))

        if variant in seen:
            continue
        if invariant.matches(variant):
            results.append(variant)
            seen.add(variant)

    return results
