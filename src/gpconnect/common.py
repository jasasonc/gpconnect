"""Shared constants and small helpers."""

from __future__ import annotations

import json
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

CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "gpconnect"
CONFIG_FILE = CONFIG_DIR / "config.json"
#: Persistent WebKit storage; only used with --remember-session.
DATA_DIR = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "gpconnect"


def load_config() -> dict:
    try:
        return json.loads(CONFIG_FILE.read_text())
    except (OSError, ValueError):
        return {}


def save_config(config: dict) -> None:
    """Store per-portal preferences. Only non-secret data belongs here."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n")
    CONFIG_FILE.chmod(0o600)

SESSION = requests.Session()
SESSION.headers["User-Agent"] = USER_AGENT


def log(msg: str) -> None:
    print(f"[gpconnect] {msg}", file=sys.stderr)


def die(msg: str, code: int = 1) -> None:
    print(f"[gpconnect] error: {msg}", file=sys.stderr)
    sys.exit(code)
