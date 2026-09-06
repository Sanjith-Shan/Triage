"""Tests for :mod:`triage.pipeline` and the CLI."""

from __future__ import annotations

import json

import fixtures
from triage.cli import main
from triage.pipeline import triage_directory


def _make_crash(directory, name: str, data: bytes, report: str) -> None:
    (directory / name).write_bytes(data)
    (directory / (name + ".asan")).write_text(report, encoding="utf-8")


def _populate(directory) -> None:
    # Two heap-overflow crashes that dedup to one bucket.
    _make_crash(directory, "crash-01", b"AAAAoverflowAAAA", fixtures.HEAP_BOF_WRITE)
    _make_crash(
        directory, "crash-02", b"BBBBoverflowBBBB", fixtures.HEAP_BOF_WRITE_OTHER_RUN
    )
    # One use-after-free.
    _make_crash(directory, "crash-03", b"free-then-use", fixtures.HEAP_UAF_READ)
    # One NULL-deref SEGV.
    _make_crash(directory, "crash-04", b"\x00\x00\x00\x00", fixtures.SEGV_NULL_DEREF)


def test_pipeline_dedups_into_unique_buckets(tmp_path):
    _populate(tmp_path)
    result = triage_directory(tmp_path)

    assert result.total_crashes == 4
    assert len(result.bugs) == 3  # heap-bof (x2) + uaf + segv

    by_class = {bug.bug_class: bug for bug in result.bugs}
    assert by_class["heap-buffer-overflow"].crash_count == 2
    assert by_class["heap-use-after-free"].crash_count == 1
    assert by_class["SEGV"].crash_count == 1

    # Without a binary, no minimization happened.
    assert all(bug.minimized_size is None for bug in result.bugs)


def test_pipeline_markdown_table(tmp_path):
    _populate(tmp_path)
    result = triage_directory(tmp_path)
    md = result.to_markdown()

    assert "| bug id | class | exploitability |" in md
    assert "controlled-offset" in md
    assert "minimized size" in md
    assert "BUG-0001" in md
    assert "heap-buffer-overflow" in md
    assert "likely-exploitable" in md
    # Nine columns per row.
    header = md.splitlines()[0]
    assert header.count("|") == 10  # 9 columns -> 10 pipes


def test_pipeline_json_roundtrips(tmp_path):
    _populate(tmp_path)
    result = triage_directory(tmp_path)
    payload = json.loads(result.to_json())

    assert payload["total_crashes"] == 4
    assert payload["unique_bugs"] == 3
    assert len(payload["bugs"]) == 3
    first = payload["bugs"][0]
    assert "bucket" in first and "major" in first["bucket"]
    assert "classification" in first


def test_pipeline_skips_inputs_without_reports(tmp_path):
    (tmp_path / "orphan").write_bytes(b"no report here")
    result = triage_directory(tmp_path)  # no binary, no sidecar
    assert result.total_crashes == 0
    assert result.bugs == []
    assert len(result.skipped) == 1


def test_cli_writes_outputs(tmp_path):
    _populate(tmp_path)
    json_out = tmp_path / "out.json"
    md_out = tmp_path / "out.md"

    rc = main(
        [str(tmp_path), "--json", str(json_out), "--markdown", str(md_out)]
    )
    assert rc == 0
    assert json_out.is_file()
    assert md_out.is_file()

    payload = json.loads(json_out.read_text())
    assert payload["unique_bugs"] == 3
    assert "| bug id |" in md_out.read_text()


def test_cli_minimize_requires_binary(tmp_path):
    _populate(tmp_path)
    try:
        main([str(tmp_path), "--minimize"])
    except SystemExit as exc:
        assert exc.code != 0
    else:  # pragma: no cover
        raise AssertionError("--minimize without --binary should error")
