"""Ensure the repo root (containing the ``detect`` package) is importable.

Running ``python -m pytest`` from the repo root already puts the cwd on
``sys.path``; this is belt-and-suspenders for other invocation styles.
"""

import os
import sys

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
