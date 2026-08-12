"""Tests for argument parsing and the openconnect command construction."""

from __future__ import annotations

import pytest

from gpconnect.cli import parse_args
from gpconnect.tls import Tls
from gpconnect.vpn import elevation_prefix, run_openconnect

AUTH = {"username": "u@example.org", "prelogin_cookie": "COOKIE", "portal_userauthcookie": ""}
TLS = Tls("deadbeef", "/tmp/ca.pem")


def test_shared_flags_work_after_the_subcommand():
    args = parse_args(["connect", "vpn.example.org", "--webview"])
    assert args.portal == "vpn.example.org"
    assert args.webview is True


def test_shared_flags_work_before_the_subcommand():
    args = parse_args(["--webview", "connect", "vpn.example.org"])
    assert args.webview is True


def test_extra_openconnect_args_are_passed_through():
    args = parse_args(["connect", "vpn.example.org", "--", "-v"])
    assert args.openconnect_args == ["-v"]


def test_defaults_are_applied_when_flags_are_absent():
    args = parse_args(["connect", "vpn.example.org"])
    assert (args.webview, args.timeout, args.elevate) == (False, 300.0, "auto")
    assert args.insecure is False and args.servercert is None


def test_unknown_subcommand_is_rejected():
    with pytest.raises(SystemExit):
        parse_args(["nope"])


def test_elevation_none_is_empty():
    assert elevation_prefix("none") == []


def test_elevation_explicit_pkexec():
    assert elevation_prefix("pkexec") == ["pkexec"]


@pytest.fixture
def spawn(monkeypatch):
    """Run run_openconnect without spawning anything; capture argv and stdin."""
    recorded: dict = {}

    class FakeProc:
        returncode = 0

        def communicate(self, input=None):
            recorded["stdin"] = input
            return b"", b""

    def fake_popen(argv, **_kwargs):
        recorded["argv"] = argv
        return FakeProc()

    monkeypatch.setattr("gpconnect.vpn.find_openconnect", lambda: "/usr/sbin/openconnect")
    monkeypatch.setattr("gpconnect.vpn.subprocess.Popen", fake_popen)

    def run(auth=AUTH, gateway=None, extra=None):
        run_openconnect("vpn.example.org", auth, TLS, gateway, extra or [], elevate="none")
        return recorded

    return run


def test_portal_scope_and_pinned_certificate(spawn):
    rec = spawn()
    assert rec["argv"][-1] == "vpn.example.org"
    assert "--usergroup=portal:prelogin-cookie" in rec["argv"]
    assert "--servercert=sha256:deadbeef" in rec["argv"]
    assert "--cafile=/tmp/ca.pem" in rec["argv"]
    # the cookie is fed through stdin, never as an argument
    assert rec["stdin"] == b"COOKIE\n"
    assert not any("COOKIE" in arg for arg in rec["argv"])


def test_gateway_scope(spawn):
    rec = spawn(gateway="gw.example.org")
    assert rec["argv"][-1] == "gw.example.org"
    assert "--usergroup=gateway:prelogin-cookie" in rec["argv"]


def test_portal_userauthcookie_selects_the_other_usergroup(spawn):
    auth = {"username": "u", "prelogin_cookie": "", "portal_userauthcookie": "PORTAL"}
    rec = spawn(auth=auth)
    assert "--usergroup=portal:portal-userauthcookie" in rec["argv"]
    assert rec["stdin"] == b"PORTAL\n"


def test_extra_arguments_precede_the_host(spawn):
    rec = spawn(extra=["-v"])
    assert rec["argv"][-2:] == ["-v", "vpn.example.org"]
