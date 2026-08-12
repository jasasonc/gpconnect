"""Shared constants and small helpers."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import requests

# Version string we present to the portal. Some portals reject unknown
# clients, so we identify ourselves as the official Linux GlobalProtect app.
CLIENT_VERSION = "6.3.3-619"
USER_AGENT = f"PAN GlobalProtect/{CLIENT_VERSION} (linux-64)"

CALLBACK_SCHEME = "globalprotectcallback"
DESKTOP_ID = "gpconnect-callback.desktop"

CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "gpconnect"
PORT_FILE = CACHE_DIR / "callback.port"

SESSION = requests.Session()
SESSION.headers["User-Agent"] = USER_AGENT


def log(msg: str) -> None:
    print(f"[gpconnect] {msg}", file=sys.stderr)


def die(msg: str, code: int = 1) -> None:
    print(f"[gpconnect] error: {msg}", file=sys.stderr)
    sys.exit(code)
