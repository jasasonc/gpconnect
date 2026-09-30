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


def openconnect_argv(portal: str, auth: dict, tls: Tls, gateway: str | None,
                     extra: list[str]) -> tuple[list[str], str]:
    """The openconnect command line (without root) and the cookie for its stdin."""
    host = gateway or portal
    if auth.get("prelogin_cookie"):
        cookie, kind = auth["prelogin_cookie"], "prelogin-cookie"
        scope = "gateway" if gateway else "portal"
    else:
        cookie, kind = auth["portal_userauthcookie"], "portal-userauthcookie"
        # The portal refuses this cookie (HTTP 512) -- it is meant for the
        # gateway login, so always enter at the gateway with it.
        scope = "gateway"

    argv = [
        find_openconnect(),
        "--protocol=gp",
        f"--user={auth['username']}",
        f"--usergroup={scope}:{kind}",
        "--os=linux-64",
        "--passwd-on-stdin",
        # We supply everything openconnect needs, and stdin is a pipe. Without
        # this a rejected cookie turns into a prompt and the opaque
        # "fgets (stdin): Inappropriate ioctl for device"; with it, it fails
        # cleanly and the caller can fall back to a fresh login.
        "--non-inter",
        f"--servercert=sha256:{tls.fingerprint}",
    ]
    if tls.cafile:
        argv.append(f"--cafile={tls.cafile}")
    return argv + extra + [host], cookie


#: What openconnect prints when the server wants credentials we did not give,
#: i.e. when it did not accept the cookie.
REFUSED_MARKERS = ("User input required in non-interactive mode", "auth-failed")


def check_cookie(portal: str, auth: dict, tls: Tls, gateway: str | None) -> bool | None:
    """Ask the gateway whether it still accepts the cookie, without a tunnel.

    ``openconnect --authenticate`` stops after the login and needs no root, so
    this settles the question before any password prompt. Returns True when
    accepted, False when refused, and None when it could not tell (no network,
    server down) -- that is no reason to throw the cookie away.
    """
    argv, cookie = openconnect_argv(portal, auth, tls, gateway, [])
    argv.insert(1, "--authenticate")
    try:
        proc = subprocess.run(argv, input=cookie + "\n", capture_output=True,
                              text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode == 0:
        return True
    output = proc.stdout + proc.stderr
    return False if any(m in output for m in REFUSED_MARKERS) else None


def run_openconnect(portal: str, auth: dict, tls: Tls, gateway: str | None,
                    extra: list[str], elevate: str = "auto") -> int:
    argv, cookie = openconnect_argv(portal, auth, tls, gateway, extra)
    argv = elevation_prefix(elevate) + argv

    log(f"starting openconnect against {gateway or portal}")
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE)
        proc.communicate(input=(cookie + "\n").encode())
        return proc.returncode or 0
    except KeyboardInterrupt:
        return 0
