"""Storage for the reusable portal cookie.

That cookie is a bearer credential: whoever holds it can bring up the VPN until
the portal expires it. So it goes into the system keyring when one is available,
and into a 0600 file only as a fallback -- and only when the user asked for it
with ``--remember``.
"""

from __future__ import annotations

import json

from .common import CONFIG_DIR, log

SERVICE = "gpconnect"
CREDENTIALS_FILE = CONFIG_DIR / "credentials.json"


def _keyring():
    """Return a working keyring backend, or None."""
    try:
        import keyring
        from keyring.backends.fail import Keyring as FailKeyring
    except ImportError:
        return None
    try:
        backend = keyring.get_keyring()
    except Exception:
        return None
    return None if isinstance(backend, FailKeyring) else keyring


def _read_file() -> dict:
    try:
        return json.loads(CREDENTIALS_FILE.read_text())
    except (OSError, ValueError):
        return {}


def _write_file(data: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CREDENTIALS_FILE.touch(mode=0o600, exist_ok=True)
    CREDENTIALS_FILE.chmod(0o600)
    CREDENTIALS_FILE.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def save_cookie(portal: str, username: str, cookie: str) -> None:
    if not cookie:
        return
    payload = json.dumps({"username": username, "cookie": cookie})
    backend = _keyring()
    if backend is not None:
        try:
            backend.set_password(SERVICE, portal, payload)
            log(f"saved the portal login to the keyring ({portal})")
            return
        except Exception as exc:
            log(f"keyring unavailable ({exc}); falling back to a 0600 file")
    data = _read_file()
    data[portal] = {"username": username, "cookie": cookie}
    _write_file(data)
    log(f"saved the portal login to {CREDENTIALS_FILE} (mode 0600)")


def load_cookie(portal: str) -> dict | None:
    backend = _keyring()
    if backend is not None:
        try:
            raw = backend.get_password(SERVICE, portal)
            if raw:
                return json.loads(raw)
        except Exception:
            pass
    entry = _read_file().get(portal)
    return entry if entry and entry.get("cookie") else None


def clear_cookie(portal: str | None = None) -> None:
    backend = _keyring()
    data = _read_file()
    portals = [portal] if portal else list(data)
    if backend is not None:
        for name in ({portal} if portal else set(data)) or set():
            try:
                backend.delete_password(SERVICE, name)
            except Exception:
                pass
    for name in portals:
        data.pop(name, None)
    if data:
        _write_file(data)
    else:
        CREDENTIALS_FILE.unlink(missing_ok=True)
