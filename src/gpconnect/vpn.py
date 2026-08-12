"""Handing the session over to openconnect, which carries the actual tunnel."""

from __future__ import annotations

import os
import shutil
import subprocess

from .common import die, log
from .tls import Tls


def find_openconnect() -> str:
    binary = shutil.which("openconnect")
    if binary:
        return binary
    for candidate in ("/usr/sbin/openconnect", "/sbin/openconnect", "/usr/local/sbin/openconnect"):
        if os.access(candidate, os.X_OK):
            return candidate
    die("openconnect is not installed. Install it with:  sudo apt install openconnect")
    raise AssertionError("unreachable")


def elevation_prefix(mode: str) -> list[str]:
    """How to become root: sudo (needs a TTY) or pkexec (graphical prompt)."""
    if os.geteuid() == 0 or mode == "none":
        return []
    if mode == "sudo":
        return ["sudo", "--"]
    if mode == "pkexec":
        return ["pkexec"]
    # auto: passwordless sudo > pkexec (graphical session) > sudo
    if shutil.which("sudo") and subprocess.run(
            ["sudo", "-n", "true"], capture_output=True).returncode == 0:
        return ["sudo", "--"]
    if shutil.which("pkexec") and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        log("using pkexec for root -- confirm the graphical password prompt")
        return ["pkexec"]
    return ["sudo", "--"]


def run_openconnect(portal: str, auth: dict, tls: Tls, gateway: str | None,
                    extra: list[str], elevate: str = "auto") -> int:
    binary = find_openconnect()

    if auth.get("prelogin_cookie"):
        cookie, kind = auth["prelogin_cookie"], "prelogin-cookie"
    else:
        cookie, kind = auth["portal_userauthcookie"], "portal-userauthcookie"

    host = gateway or portal
    scope = "gateway" if gateway else "portal"

    argv = [
        binary,
        "--protocol=gp",
        f"--user={auth['username']}",
        f"--usergroup={scope}:{kind}",
        "--os=linux-64",
        "--passwd-on-stdin",
        f"--servercert=sha256:{tls.fingerprint}",
    ]
    if tls.cafile:
        argv.append(f"--cafile={tls.cafile}")
    argv += extra + [host]
    argv = elevation_prefix(elevate) + argv

    log(f"starting openconnect against {host}")
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE)
        proc.communicate(input=(cookie + "\n").encode())
        return proc.returncode or 0
    except KeyboardInterrupt:
        return 0
