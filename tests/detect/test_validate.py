"""The honesty engine: mutation, TP/FP metrics, and the anti-overfit thesis."""

from detect.invariant import ByteSequencePresent, HeadersCoexist
from detect.validate import RuleReport, evaluate, mutate_triggers

SEED_SMUGGLE = (
    b"POST /login HTTP/1.1\r\nHost: victim.example\r\n"
    b"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n"
    b"User-Agent: fuzzer/1.0\r\nAccept: */*\r\n\r\n"
    b"0\r\n\r\nGET /admin HTTP/1.1\r\nHost: victim.example\r\n\r\n"
)


def test_mutate_triggers_all_satisfy_invariant():
    inv = HeadersCoexist("Content-Length", "Transfer-Encoding")
    triggers = mutate_triggers(SEED_SMUGGLE, inv, 40)
    assert len(triggers) == 40
    # All held-out mutants preserve the invariant...
    assert all(inv.matches(t) for t in triggers)
    # ...but they are genuinely different from the seed.
    assert all(t != SEED_SMUGGLE for t in triggers)
    assert len(set(triggers)) == len(triggers)


def test_mutate_is_deterministic():
    inv = HeadersCoexist("Content-Length", "Transfer-Encoding")
    a = mutate_triggers(SEED_SMUGGLE, inv, 15, seed=7)
    b = mutate_triggers(SEED_SMUGGLE, inv, 15, seed=7)
    assert a == b


def test_anti_overfit_invariant_beats_byte_sequence():
    """THE KEY TEST: invariant rule generalizes; byte-sequence rule does not.

    Both rules are scored on the *same* held-out mutated triggers. The invariant
    rule (CL+TE coexistence) should catch essentially all of them; the overfit
    rule built on the literal PoC bytes should catch almost none, because every
    mutant disturbs payload bytes outside the invariant-bearing header lines.
    """
    inv = HeadersCoexist("Content-Length", "Transfer-Encoding")
    triggers = mutate_triggers(SEED_SMUGGLE, inv, 50)

    invariant_report = evaluate(inv.matches, triggers, [], rule_name="invariant")
    overfit = ByteSequencePresent(SEED_SMUGGLE)
    overfit_report = evaluate(overfit.matches, triggers, [], rule_name="overfit")

    assert invariant_report.tp_rate >= 0.99
    assert overfit_report.tp_rate <= 0.10
    # The whole point: a large, honest generalization gap.
    assert invariant_report.tp_rate - overfit_report.tp_rate >= 0.80


def test_invariant_rule_zero_false_positives_on_benign():
    inv = HeadersCoexist("Content-Length", "Transfer-Encoding")
    triggers = mutate_triggers(SEED_SMUGGLE, inv, 20)
    benign = [
        b"GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc",
        b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"GET /x HTTP/1.1\r\nHost: h\r\nUser-Agent: curl\r\n\r\n",
        b"hello world, not even http",
    ]
    report = evaluate(inv.matches, triggers, benign)
    assert report.tp_rate >= 0.99
    assert report.fp_rate == 0.0


def test_rule_report_markdown_contains_metrics():
    report = RuleReport(
        rule_name="r", tp_count=49, trigger_count=50, fp_count=0, benign_count=10
    )
    md = report.to_markdown()
    assert "True-positive" in md
    assert "False-positive" in md
    assert "98.0%" in md
