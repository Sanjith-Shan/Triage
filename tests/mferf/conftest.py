"""Ensure MFERF reproducers exist before the regression tests run.

They are generated (not committed) so the repo carries no large crash blobs;
scripts/mferf_pack.py is the source of truth and CI regenerates them too.
"""
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
REPRO = Path(__file__).resolve().parent / "reproducers"


def pytest_configure(config):
    needed = [f"crash-MFERF-00{i}" for i in range(1, 6)]
    if all((REPRO / n).exists() for n in needed):
        return
    subprocess.run(
        [sys.executable, str(REPO / "scripts" / "mferf_pack.py"),
         "--seeds", str(REPO / "corpus" / "mferf"), "--repro", str(REPRO)],
        check=True, cwd=REPO)
