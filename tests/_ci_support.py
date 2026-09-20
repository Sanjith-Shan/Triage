"""Shared helpers for the C-target tests.

The parsers are exercised two ways:

  * plain builds (no sanitizer) — always runnable, catch crashing bugs that fault
    on their own (e.g. unbounded recursion -> SIGSEGV) and confirm benign inputs
    parse cleanly;
  * ASan/UBSan builds — catch the silent-corruption bugs (heap/stack overflow,
    OOB read, use-after-free) that a plain build would miss.

Some hosts cannot execute an ASan binary at all: notably this project's dev Mac,
where the ASan runtime hangs at init (Apple clang, sandboxed). `asan_runnable()`
detects that and lets those assertions skip locally while still running for real
on Linux CI, where ASan works. Nothing is silently dropped — a skip prints why.
"""
from __future__ import annotations

import functools
import shutil
import subprocess
import tempfile
import os
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INCLUDE = REPO / "include"


@functools.lru_cache(maxsize=1)
def clang() -> str | None:
    return shutil.which("clang")


def compile_c(sources, out, *, defines=(), sanitize=None, includes=(), std="c11",
              extra=()):
    """Compile C sources to `out`. Returns (ok, stderr)."""
    cc = clang()
    if not cc:
        return False, "clang not found"
    cmd = [cc, f"-std={std}", "-g", "-O1", f"-I{INCLUDE}"]
    for inc in includes:
        cmd.append(f"-I{inc}")
    if sanitize:
        cmd.append(f"-fsanitize={sanitize}")
    for d in defines:
        cmd.append(f"-D{d}")
    cmd += list(extra)
    cmd += [str(s) for s in sources]
    cmd += ["-o", str(out)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode == 0, p.stderr


def run(binary, *args, timeout=20, env=None):
    """Run a binary, returning a completed process. Raises on timeout."""
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run([str(binary), *[str(a) for a in args]],
                          capture_output=True, timeout=timeout, env=full_env)


@functools.lru_cache(maxsize=1)
def asan_runnable() -> bool:
    """True iff an ASan-instrumented binary actually runs on this host."""
    if not clang():
        return False
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "probe.c"
        src.write_text('#include <stdio.h>\nint main(){puts("ok_asan");return 0;}\n')
        exe = Path(td) / "probe"
        ok, _ = compile_c([src], exe, sanitize="address")
        if not ok:
            return False
        try:
            p = subprocess.run([str(exe)], capture_output=True, text=True,
                               timeout=8, env={**os.environ,
                                               "ASAN_OPTIONS": "detect_leaks=0"})
        except subprocess.TimeoutExpired:
            return False
        return "ok_asan" in p.stdout


ASAN_SKIP_REASON = ("ASan binaries do not run on this host (runtime hangs at "
                    "init); these assertions run on Linux CI. See tests/_ci_support.py")
