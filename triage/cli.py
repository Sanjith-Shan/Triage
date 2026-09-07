"""Command-line interface for the crash-triage stage.

Usage::

    python -m triage <crashes_dir> [--binary PATH] [--minimize]
                     [--json out.json] [--markdown out.md]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

from .pipeline import triage_directory

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="triage",
        description="Classify, deduplicate and minimize fuzzing crashes.",
    )
    parser.add_argument(
        "crashes_dir",
        help="Directory of crash inputs (with optional .asan sidecar reports).",
    )
    parser.add_argument(
        "--binary",
        default=None,
        help="Sanitizer-built target used to (re)generate reports and minimize.",
    )
    parser.add_argument(
        "--minimize",
        action="store_true",
        help="Minimize one representative input per bucket (requires --binary).",
    )
    parser.add_argument(
        "--json",
        dest="json_out",
        default=None,
        help="Write the result as JSON to this path.",
    )
    parser.add_argument(
        "--markdown",
        dest="markdown_out",
        default=None,
        help="Write the triage table as Markdown to this path.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-run timeout in seconds when executing the binary.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    crashes_dir = Path(args.crashes_dir)
    if not crashes_dir.is_dir():
        parser.error(f"not a directory: {crashes_dir}")

    if args.minimize and args.binary is None:
        parser.error("--minimize requires --binary")

    result = triage_directory(
        crashes_dir,
        binary_path=args.binary,
        minimize_inputs=args.minimize,
        timeout=args.timeout,
    )

    markdown = result.to_markdown()
    if args.markdown_out:
        Path(args.markdown_out).write_text(markdown, encoding="utf-8")
    if args.json_out:
        Path(args.json_out).write_text(result.to_json(), encoding="utf-8")

    # Always print a human-readable summary to stdout.
    print(
        f"# {len(result.bugs)} unique bug(s) from "
        f"{result.total_crashes} crash(es)\n"
    )
    print(markdown, end="")
    if result.skipped:
        print(f"\nskipped {len(result.skipped)} input(s) without reports")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
