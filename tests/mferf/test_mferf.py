"""Regression tests for the MFERF demonstration target and its fixes.

The discipline (borrowed from DriveEval): every planted bug has a reproducer, and
the test proves both that the bug is real on the unpatched build and that the fix
holds — the regression assertions run against the *unpatched* code, where they
must fire, and against the *patched* code, where they must not.

Plain-build checks run everywhere. ASan-build checks (the four silent-corruption
bugs) run wherever an ASan binary can execute — locally when possible, always on
Linux CI. See tests/_ci_support.py.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _ci_support import (  # noqa: E402
    ASAN_SKIP_REASON, REPO, asan_runnable, clang, compile_c, run,
)

MFERF_DIR = REPO / "targets" / "mferf"
RUNNER = REPO / "targets" / "standalone_main.c"
REPRO = Path(__file__).resolve().parent / "reproducers"
SEEDS = REPO / "corpus" / "mferf"

# Map each reproducer to the ASan bug class its report should contain.
EXPECTED = {
    "crash-MFERF-001": "stack-buffer-overflow",
    "crash-MFERF-002": "heap-buffer-overflow",
    "crash-MFERF-003": "heap-buffer-overflow",   # OOB read is a heap-buffer-overflow READ
    "crash-MFERF-004": "heap-use-after-free",
    "crash-MFERF-005": None,                      # stack-overflow (recursion): plain SIGSEGV
}

pytestmark = pytest.mark.skipif(clang() is None, reason="clang not available")


@pytest.fixture(scope="module")
def builds(tmp_path_factory):
    """Build the four variants we need, once."""
    d = tmp_path_factory.mktemp("mferf")
    src = [MFERF_DIR / "mferf.c", MFERF_DIR / "driver.c", RUNNER]
    out = {}
    # plain builds (always runnable)
    ok, err = compile_c(src, d / "vuln_plain", includes=[MFERF_DIR])
    assert ok, err
    out["vuln_plain"] = d / "vuln_plain"
    ok, err = compile_c(src, d / "patched_plain", defines=["MFERF_PATCHED"], includes=[MFERF_DIR])
    assert ok, err
    out["patched_plain"] = d / "patched_plain"
    # ASan builds (compile always — proves it builds clean; run only if runnable)
    ok, err = compile_c(src, d / "vuln_asan", sanitize="address,undefined", includes=[MFERF_DIR])
    assert ok, err
    out["vuln_asan"] = d / "vuln_asan"
    ok, err = compile_c(src, d / "patched_asan", defines=["MFERF_PATCHED"],
                        sanitize="address,undefined", includes=[MFERF_DIR])
    assert ok, err
    out["patched_asan"] = d / "patched_asan"
    return out


def test_reproducers_exist():
    missing = [n for n in EXPECTED if not (REPRO / n).exists()]
    assert not missing, f"run scripts/mferf_pack.py --repro {REPRO}; missing {missing}"


def test_benign_seeds_parse_clean(builds):
    for seed in ("seed_valid_1", "seed_valid_2"):
        p = run(builds["vuln_plain"], SEEDS / seed, timeout=10)
        assert p.returncode == 0, f"{seed} should parse cleanly, got {p.returncode}"


def _run_small_stack(binary, arg, kb=2048, timeout=30):
    """Run under a reduced stack so the recursion overflows regardless of the
    platform's default (Linux's 8 MB would otherwise need a much deeper input)."""
    import subprocess
    return subprocess.run(
        ["bash", "-c", f'ulimit -s {kb}; exec "$0" "$1"', str(binary), str(arg)],
        capture_output=True, timeout=timeout)


def test_recursion_bug_is_real_and_fixed_plainly(builds):
    # MFERF-005 faults on its own (no sanitizer needed): unbounded recursion.
    vuln = _run_small_stack(builds["vuln_plain"], REPRO / "crash-MFERF-005")
    assert vuln.returncode != 0, "unbounded recursion must crash the unpatched build"
    patched = _run_small_stack(builds["patched_plain"], REPRO / "crash-MFERF-005")
    assert patched.returncode == 0, "depth limit must fix MFERF-005"


@pytest.mark.skipif(not asan_runnable(), reason=ASAN_SKIP_REASON)
@pytest.mark.parametrize("name", [n for n, c in EXPECTED.items() if c is not None])
def test_planted_bug_detected_by_asan(builds, name):
    env = {"ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0"}
    p = run(builds["vuln_asan"], REPRO / name, timeout=30, env=env)
    assert p.returncode != 0, f"{name} should crash the unpatched ASan build"
    report = p.stderr.decode("utf-8", "replace")
    assert EXPECTED[name] in report, f"{name}: expected {EXPECTED[name]} in report:\n{report[:800]}"


@pytest.mark.skipif(not asan_runnable(), reason=ASAN_SKIP_REASON)
@pytest.mark.parametrize("name", list(EXPECTED))
def test_patched_build_is_clean(builds, name):
    env = {"ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0"}
    p = run(builds["patched_asan"], REPRO / name, timeout=30, env=env)
    assert p.returncode == 0, (
        f"patched build must parse {name} cleanly; got {p.returncode}\n"
        + p.stderr.decode('utf-8', 'replace')[:800])
