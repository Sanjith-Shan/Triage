"""
test_http_diff.py -- compile-and-run test for the HTTP/1.1 differential target.

What it does (mirrors what the parent project's runner does, but self-contained
so it works with Apple clang, which has ASan/UBSan but no libFuzzer runtime):

  1. Compile the two parsers + diff_driver + a tiny standalone `main`
     (_test_main.c, in this dir) with `-fsanitize=address,undefined`.
  2. Assert benign corpus files exit 0 (no divergence, no sanitizer error).
  3. Assert smuggle_cl_te.http aborts with a `DIVERGENCE:` line on stderr that
     identifies the CL/TE disagreement.
  4. Assert no ASan/UBSan errors on ANY input (the parsers/driver are
     memory-safe; a divergence is signalled by abort(), not a memory bug).

Toolchain reality handled here:
  * If no clang/cc is on PATH, the whole module is skipped with a clear reason.
  * AddressSanitizer's *runtime* infinite-loops during shadow-memory setup on
    some macOS builds (observed on macOS 26 / Darwin 25: an unterminating loop
    in __sanitizer::MemoryMappingLayout::Next inside InitializeShadowMemory).
    That is a runtime regression, not a bug in this target. We PROBE whether an
    ASan-instrumented binary can actually run; if it hangs, we transparently
    fall back to `-fsanitize=undefined` only, emit a warning, and still run all
    functional checks plus UBSan. On a healthy toolchain (Linux, or any macOS
    where the ASan runtime is fine) the full address+undefined build is used.

Every child process is run under a hard timeout so a broken sanitizer runtime
can never stall the test session.
"""

import os
import shutil
import signal
import subprocess
import warnings

import pytest

# ---- paths -----------------------------------------------------------------

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
TARGET_DIR = os.path.join(REPO, "targets", "http_diff")
CORPUS_DIR = os.path.join(REPO, "corpus", "http_diff")

SOURCES = [
    os.path.join(TARGET_DIR, "parser_a.c"),
    os.path.join(TARGET_DIR, "parser_b.c"),
    os.path.join(TARGET_DIR, "diff_driver.c"),
    os.path.join(HERE, "_test_main.c"),
]

BENIGN = [
    "benign_get.http",
    "benign_post_cl.http",
    "benign_chunked.http",
    "benign_get_headers.http",
]
SMUGGLE = "smuggle_cl_te.http"

CLANG = shutil.which("clang") or shutil.which("cc")

RUN_TIMEOUT = 20      # seconds; the target itself runs in milliseconds
PROBE_TIMEOUT = 10    # seconds; enough to catch an infinite shadow-setup loop

pytestmark = pytest.mark.skipif(
    CLANG is None,
    reason="no clang/cc compiler found on PATH; cannot build the C target",
)


def _sanitizer_env():
    env = dict(os.environ)
    # abort_on_error makes ASan raise SIGABRT (consistent with abort()); leak
    # detection is off (not relevant and unsupported on some platforms).
    env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0"
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    return env


def _asan_runtime_works(tmpdir):
    """Compile a trivial ASan+UBSan program and check it actually RUNS.

    Returns True only if it builds and exits 0 within PROBE_TIMEOUT. A build
    failure or a hang/crash => ASan runtime is unusable here.
    """
    src = os.path.join(tmpdir, "probe.c")
    exe = os.path.join(tmpdir, "probe")
    with open(src, "w") as fh:
        fh.write("int main(void){ return 0; }\n")
    build = subprocess.run(
        [CLANG, "-fsanitize=address,undefined", src, "-o", exe],
        capture_output=True, text=True,
    )
    if build.returncode != 0:
        return False
    try:
        run = subprocess.run(
            [exe], capture_output=True, text=True,
            env=_sanitizer_env(), timeout=PROBE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return False
    return run.returncode == 0


# ---- build fixture ---------------------------------------------------------

@pytest.fixture(scope="module")
def target(tmp_path_factory):
    """Compile the target once. Returns (binary_path, asan_enabled)."""
    workdir = str(tmp_path_factory.mktemp("http_diff_build"))
    asan_ok = _asan_runtime_works(workdir)

    if asan_ok:
        san = "address,undefined"
    else:
        san = "undefined"
        warnings.warn(
            "AddressSanitizer runtime is unusable on this host (an "
            "instrumented binary hangs during shadow-memory setup -- a known "
            "macOS 26 / Darwin 25 regression). Falling back to "
            "'-fsanitize=undefined' only. Functional differential checks and "
            "UBSan still run; ASan heap red-zone coverage is skipped here but "
            "applies on Linux / healthy toolchains.",
            RuntimeWarning,
        )

    out = os.path.join(workdir, "http_diff")
    cmd = [
        CLANG, "-std=c11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror",
        "-fsanitize=" + san,
        "-fno-omit-frame-pointer",
        "-I", TARGET_DIR,
        *SOURCES,
        "-o", out,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.fail(
            "compilation failed:\n" + " ".join(cmd)
            + "\n--- stdout ---\n" + proc.stdout
            + "\n--- stderr ---\n" + proc.stderr
        )
    return out, asan_ok


def _run(binary, corpus_name):
    path = os.path.join(CORPUS_DIR, corpus_name)
    assert os.path.exists(path), f"missing corpus file: {path}"
    try:
        return subprocess.run(
            [binary, path], capture_output=True, text=True,
            env=_sanitizer_env(), timeout=RUN_TIMEOUT,
        )
    except subprocess.TimeoutExpired as e:
        pytest.fail(
            f"{corpus_name} did not finish within {RUN_TIMEOUT}s "
            f"(unexpected hang in the target).\nstderr:\n{e.stderr!r}"
        )


def _has_sanitizer_error(stderr):
    markers = (
        "ERROR: AddressSanitizer",
        "AddressSanitizer: heap-",
        "AddressSanitizer: stack-",
        "AddressSanitizer: global-",
        "SUMMARY: AddressSanitizer",
        "runtime error:",                       # UBSan
        "SUMMARY: UndefinedBehaviorSanitizer",
    )
    return any(m in stderr for m in markers)


# ---- tests -----------------------------------------------------------------

@pytest.mark.parametrize("name", BENIGN)
def test_benign_inputs_do_not_diverge(target, name):
    """Benign, well-formed requests: both parsers agree -> exit 0, no crash."""
    binary, _ = target
    proc = _run(binary, name)
    assert proc.returncode == 0, (
        f"{name} expected clean exit 0 but got rc={proc.returncode}\n"
        f"stderr:\n{proc.stderr}"
    )
    assert "DIVERGENCE:" not in proc.stderr, (
        f"{name} unexpectedly reported a divergence:\n{proc.stderr}"
    )
    assert not _has_sanitizer_error(proc.stderr), (
        f"{name} triggered a sanitizer error:\n{proc.stderr}"
    )


def test_smuggle_input_diverges_with_cl_te(target):
    """The CL.TE seed must abort with a greppable DIVERGENCE line."""
    binary, _ = target
    proc = _run(binary, SMUGGLE)

    assert proc.returncode == -signal.SIGABRT, (
        f"expected SIGABRT from the divergence oracle, got "
        f"rc={proc.returncode}\nstderr:\n{proc.stderr}"
    )

    assert "DIVERGENCE:" in proc.stderr, f"missing report:\n{proc.stderr}"
    assert "class=CL.TE" in proc.stderr, (
        f"expected CL.TE classification:\n{proc.stderr}"
    )
    # Strict parser A frames by chunked TE; lenient parser B frames by CL.
    assert "A=CHUNKED" in proc.stderr, proc.stderr
    assert "B=CL" in proc.stderr, proc.stderr

    # The abort is the ORACLE, not a memory bug: nothing sanitizer-flagged may
    # appear before the DIVERGENCE line.
    pre = proc.stderr.split("DIVERGENCE:", 1)[0]
    assert not _has_sanitizer_error(pre), (
        f"sanitizer error before divergence report:\n{proc.stderr}"
    )


@pytest.mark.parametrize("name", BENIGN + [SMUGGLE])
def test_no_memory_errors_on_any_input(target, name):
    """No input may produce an ASan/UBSan memory error; the parsers are safe.

    The smuggle seed aborts via the divergence oracle, but that is a plain
    abort() -- not a sanitizer-reported memory error.
    """
    binary, _ = target
    proc = _run(binary, name)
    assert not _has_sanitizer_error(proc.stderr), (
        f"{name} produced a sanitizer error:\n{proc.stderr}"
    )
