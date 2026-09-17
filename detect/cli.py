"""Command-line entry point for the detection-signature generator.

Usage::

    python -m detect --bug bug.json --out-dir rules/

Reads a triaged bug description from a JSON file, generates the YARA and
Suricata rules plus an honest validation report, and writes
``<bug_id>.yar``, ``<bug_id>.rules`` and ``<bug_id>.report.md`` into the
output directory.

The bug JSON schema::

    {
      "bug_id": "BUG-1234",
      "bug_class": "http-desync",          # see detect.generate.BUG_CLASS_MAP
      "cwe": "CWE-444",
      "minimized_input": "GET / HTTP/1.1\\r\\n...",
      "input_encoding": "utf-8",           # utf-8 | latin-1 | base64 | hex
      "fault_hint": "CL and TE both present",
      "params": {}                          # optional invariant overrides
    }
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from .generate import Bug, generate_rules


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m detect",
        description=(
            "Generate PoC-derived, FP/FN-tested detection signatures "
            "(YARA + Suricata) for a confirmed, triaged fuzzing bug."
        ),
    )
    parser.add_argument(
        "--bug",
        required=True,
        help="path to the bug description JSON file",
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        help="directory to write <bug_id>.yar/.rules/.report.md into",
    )
    parser.add_argument(
        "--triggers",
        type=int,
        default=40,
        help="number of held-out mutated triggers for validation (default 40)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Run the CLI. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    with open(args.bug, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    bug = Bug.from_dict(data)
    rules = generate_rules(bug, n_triggers=args.triggers)
    written = rules.write(args.out_dir)

    print(f"bug_id={rules.bug_id} class={rules.bug_class} cwe={rules.cwe}")
    print(f"invariant: {rules.invariant.describe()}")
    print(
        f"invariant TP={rules.invariant_report.tp_rate:.1%} "
        f"FP={rules.invariant_report.fp_rate:.1%} "
        f"(vs. overfit byte-sequence TP={rules.overfit_report.tp_rate:.1%})"
    )
    for kind, path in written.items():
        print(f"wrote {kind}: {path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
