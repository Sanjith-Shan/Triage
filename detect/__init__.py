"""detect: fuzzing -> intrusion-detection bridge.

For each confirmed, triaged fuzzing bug, this package emits a detection rule
that fires on inputs which trigger the *bug class* -- not the literal PoC bytes.

Design principle
----------------
A rule that matches the literal PoC bytes is a worthless "atomic-of-one" overfit
signature. A credible rule matches the **vulnerability-triggering invariant**,
and ships with honest generalization metrics: a true-positive rate on held-out
mutated triggers and a false-positive rate on a benign corpus.

Modules
-------
* :mod:`detect.invariant`  -- composable structural invariants (the *why*).
* :mod:`detect.yara_gen`   -- render invariants to YARA (host/file).
* :mod:`detect.suricata_gen` -- render invariants to Suricata/Snort (network).
* :mod:`detect.validate`   -- the honesty engine: mutate + measure TP/FP.
* :mod:`detect.generate`   -- infer invariant from a bug and produce rules.
* :mod:`detect.cli`        -- ``python -m detect`` command line.
"""

from __future__ import annotations

from .generate import Bug, GeneratedRules, generate_rules, infer_invariant
from .invariant import (
    ByteSequencePresent,
    FieldLengthExceeds,
    HeadersCoexist,
    Invariant,
    MalformedChunkFraming,
    NestingDepthExceeds,
    der_tlv_locator,
    der_tlv_records,
)
from .suricata_gen import sid_for, to_suricata
from .validate import RuleReport, evaluate, mutate_triggers
from .yara_gen import to_yara

__all__ = [
    "Invariant",
    "FieldLengthExceeds",
    "NestingDepthExceeds",
    "HeadersCoexist",
    "MalformedChunkFraming",
    "ByteSequencePresent",
    "der_tlv_locator",
    "der_tlv_records",
    "to_yara",
    "to_suricata",
    "sid_for",
    "evaluate",
    "mutate_triggers",
    "RuleReport",
    "Bug",
    "GeneratedRules",
    "generate_rules",
    "infer_invariant",
]
