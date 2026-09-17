"""End-to-end generation + CLI file-writing tests."""

import json

from detect.cli import main
from detect.generate import Bug, generate_rules, infer_invariant
from detect.invariant import (
    FieldLengthExceeds,
    HeadersCoexist,
    MalformedChunkFraming,
    NestingDepthExceeds,
)

SMUGGLE = (
    b"POST /login HTTP/1.1\r\nHost: v\r\n"
    b"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n"
    b"0\r\n\r\nGET /admin HTTP/1.1\r\n\r\n"
)


def _bug(**over):
    base = dict(
        bug_id="BUG-DESYNC-1",
        bug_class="http-desync",
        cwe="CWE-444",
        minimized_input=SMUGGLE,
        fault_hint="CL and TE coexist",
    )
    base.update(over)
    return Bug(**base)


def test_infer_invariant_per_class():
    assert isinstance(infer_invariant(_bug()), HeadersCoexist)
    chunk_seed = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\nx\r\n"
    assert isinstance(
        infer_invariant(_bug(bug_class="http-chunk", minimized_input=chunk_seed)),
        MalformedChunkFraming,
    )
    nest_seed = b'{"a":{"b":{"c":{"d":1}}}}'
    assert isinstance(
        infer_invariant(_bug(bug_class="recursion", minimized_input=nest_seed)),
        NestingDepthExceeds,
    )
    tlv_seed = bytes([0x04, 0x84, 0x00, 0x01, 0x00, 0x00]) + b"A" * 4
    assert isinstance(
        infer_invariant(
            _bug(bug_class="overflow-on-length-field", minimized_input=tlv_seed)
        ),
        FieldLengthExceeds,
    )


def test_generate_rules_end_to_end_desync():
    result = generate_rules(_bug(), n_triggers=40)
    assert result.n_triggers == 40
    # Invariant generalizes and is clean on the benign corpus.
    assert result.invariant_report.tp_rate >= 0.99
    assert result.invariant_report.fp_rate == 0.0
    # Overfit baseline does not generalize.
    assert result.overfit_report.tp_rate <= 0.10
    assert "rule" in result.yara and "alert " in result.suricata
    md = result.report_markdown()
    assert "Anti-overfit contrast" in md
    assert "virtual patching" in md.lower()


def test_generate_rules_recursion_auto_derives_depth():
    nest_seed = b'{"a":{"b":{"c":{"d":{"e":1}}}}}'  # depth 5
    result = generate_rules(
        _bug(bug_id="BUG-REC-1", bug_class="recursion", minimized_input=nest_seed),
        n_triggers=20,
    )
    assert result.invariant.matches(nest_seed)
    assert result.invariant_report.tp_rate >= 0.99
    assert result.invariant_report.fp_rate == 0.0


def test_generate_rules_field_length_end_to_end():
    tlv_seed = bytes([0x30, 0x84, 0x00, 0x01, 0x00, 0x00]) + b"B" * 8
    result = generate_rules(
        _bug(
            bug_id="BUG-TLV-1",
            bug_class="overflow-on-length-field",
            cwe="CWE-130",
            minimized_input=tlv_seed,
        ),
        n_triggers=20,
    )
    assert result.invariant_report.tp_rate >= 0.99
    assert result.invariant_report.fp_rate == 0.0


def test_cli_writes_three_files(tmp_path, capsys):
    bug_json = {
        "bug_id": "BUG-CLI-1",
        "bug_class": "http-desync",
        "cwe": "CWE-444",
        "minimized_input": SMUGGLE.decode("latin-1"),
        "input_encoding": "latin-1",
        "fault_hint": "CL and TE coexist",
    }
    bug_path = tmp_path / "bug.json"
    bug_path.write_text(json.dumps(bug_json))
    out_dir = tmp_path / "rules"

    rc = main(["--bug", str(bug_path), "--out-dir", str(out_dir), "--triggers", "20"])
    assert rc == 0

    yar = out_dir / "BUG-CLI-1.yar"
    rules = out_dir / "BUG-CLI-1.rules"
    report = out_dir / "BUG-CLI-1.report.md"
    assert yar.exists() and rules.exists() and report.exists()
    assert "rule" in yar.read_text()
    assert "alert " in rules.read_text()
    assert "Anti-overfit contrast" in report.read_text()

    out = capsys.readouterr().out
    assert "invariant TP=" in out
