#!/usr/bin/env python3
"""Run gpconnect straight from a checkout, without installing it.

Handy for a symlink:  ln -sf "$PWD/gpconnect.py" ~/.local/bin/gpconnect
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "src"))

from gpconnect.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
