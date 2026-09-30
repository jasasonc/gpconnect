"""Tests for the saved portal login (the file backend and its reuse)."""

from __future__ import annotations

import pytest

from gpconnect import common, store


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    """Keep the tests away from the real config and any real keyring."""
    monkeypatch.setattr(common, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(store, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(store, "CREDENTIALS_FILE", tmp_path / "credentials.json")
    monkeypatch.setattr(store, "_keyring", lambda: None)  # force the file backend
    return tmp_path / "credentials.json"


def test_round_trip():
    store.save_cookie("vpn.example.org", "u@example.org", "COOKIE")
    saved = store.load_cookie("vpn.example.org")
    assert saved == {"username": "u@example.org", "cookie": "COOKIE"}


def test_missing_portal_returns_none():
    assert store.load_cookie("vpn.unknown.org") is None


def test_credentials_file_is_owner_only(isolated_store):
    store.save_cookie("vpn.example.org", "u@example.org", "COOKIE")
    assert isolated_store.stat().st_mode & 0o077 == 0


def test_empty_cookie_is_not_stored(isolated_store):
    store.save_cookie("vpn.example.org", "u@example.org", "")
    assert not isolated_store.exists()


def test_clear_removes_only_the_named_portal():
    store.save_cookie("vpn.a.org", "a@example.org", "A")
    store.save_cookie("vpn.b.org", "b@example.org", "B")
    store.clear_cookie("vpn.a.org")
    assert store.load_cookie("vpn.a.org") is None
    assert store.load_cookie("vpn.b.org")["cookie"] == "B"


def test_clear_without_argument_removes_everything(isolated_store):
    store.save_cookie("vpn.a.org", "a@example.org", "A")
    store.save_cookie("vpn.b.org", "b@example.org", "B")
    store.clear_cookie()
    assert store.load_cookie("vpn.a.org") is None
    assert not isolated_store.exists()


def test_keyring_failure_falls_back_to_the_file(monkeypatch, isolated_store):
    class Broken:
        def set_password(self, *_args):
            raise RuntimeError("no keyring daemon")

    monkeypatch.setattr(store, "_keyring", lambda: Broken())
    store.save_cookie("vpn.example.org", "u@example.org", "COOKIE")
    assert isolated_store.exists()


class Args:
    """Stand-in for the parsed argparse namespace."""

    portal = "vpn.example.org"
    gateway = None
    openconnect_args: list = []
    elevate = "none"
    no_saved_login = False
    remember = False
    browser = None
    timeout = 5.0
    no_browser = False
    webview = False
    login_hint = None
    no_login_hint = False


def test_saved_login_skips_the_browser(monkeypatch):
    """With a saved cookie, connect must not open any login window."""
    from gpconnect import cli

    store.save_cookie("vpn.example.org", "u@example.org", "COOKIE")
    captured = {}

    def fake_run(portal, auth, tls, gateway, extra, elevate):
        captured["auth"] = auth
        return 0

    def boom(*_args, **_kwargs):
        raise AssertionError("authenticate() must not be called")

    monkeypatch.setattr(cli, "check_cookie", lambda *_a: True)
    monkeypatch.setattr(cli, "run_openconnect", fake_run)
    monkeypatch.setattr(cli, "authenticate", boom)

    assert cli.do_connect(Args(), tls=None) == 0
    assert captured["auth"]["portal_userauthcookie"] == "COOKIE"
    assert captured["auth"]["username"] == "u@example.org"


def test_a_refused_cookie_is_replaced_by_a_remembered_login(monkeypatch):
    """Without --remember, a refused cookie must still be replaced, not just dropped.

    Otherwise one expired cookie leaves every later run at the login window.
    """
    from gpconnect import cli

    store.save_cookie("vpn.example.org", "u@example.org", "STALE")
    calls, logins = [], []

    def fake_run(portal, auth, tls, gateway, extra, elevate):
        calls.append(auth)
        return 0

    def fake_authenticate(*args, **_kwargs):
        logins.append(args[-1])  # the remember flag
        return {"username": "u@example.org", "prelogin_cookie": "FRESH",
                "portal_userauthcookie": ""}

    monkeypatch.setattr(cli, "check_cookie", lambda *_a: False)
    monkeypatch.setattr(cli, "run_openconnect", fake_run)
    monkeypatch.setattr(cli, "authenticate", fake_authenticate)
    monkeypatch.setattr(cli, "portal_config",
                        lambda *_a: {"gateways": [], "userauthcookie": "NEW",
                                     "prelogonuserauthcookie": ""})

    assert cli.do_connect(Args(), tls=None) == 0
    assert logins == [True]                       # the login window keeps the IdP session
    assert len(calls) == 1                        # the refused cookie never reaches the tunnel
    assert calls[0]["portal_userauthcookie"] == "NEW"
    assert store.load_cookie("vpn.example.org")["cookie"] == "NEW"


def test_a_failing_tunnel_keeps_an_accepted_cookie(monkeypatch):
    """A cancelled password prompt or a dropped link says nothing about the cookie."""
    from gpconnect import cli

    store.save_cookie("vpn.example.org", "u@example.org", "COOKIE")

    def boom(*_args, **_kwargs):
        raise AssertionError("authenticate() must not be called")

    monkeypatch.setattr(cli, "check_cookie", lambda *_a: True)
    monkeypatch.setattr(cli, "run_openconnect", lambda *_a: 126)
    monkeypatch.setattr(cli, "authenticate", boom)

    assert cli.do_connect(Args(), tls=None) == 126
    assert store.load_cookie("vpn.example.org")["cookie"] == "COOKIE"


def test_an_unverifiable_cookie_is_tried_and_kept(monkeypatch):
    """No network during the check is no reason to throw the cookie away."""
    from gpconnect import cli

    store.save_cookie("vpn.example.org", "u@example.org", "COOKIE")
    used = {}

    def fake_run(portal, auth, tls, gateway, extra, elevate):
        used["auth"] = auth
        return 1

    monkeypatch.setattr(cli, "check_cookie", lambda *_a: None)
    monkeypatch.setattr(cli, "run_openconnect", fake_run)

    assert cli.do_connect(Args(), tls=None) == 1
    assert used["auth"]["portal_userauthcookie"] == "COOKIE"
    assert store.load_cookie("vpn.example.org")["cookie"] == "COOKIE"


def test_no_saved_login_ignores_the_stored_cookie(monkeypatch):
    from gpconnect import cli

    store.save_cookie("vpn.example.org", "u@example.org", "COOKIE")
    used = {}

    def fake_run(portal, auth, tls, gateway, extra, elevate):
        used["auth"] = auth
        return 0

    monkeypatch.setattr(cli, "run_openconnect", fake_run)
    monkeypatch.setattr(cli, "authenticate",
                        lambda *a, **k: {"username": "u@example.org",
                                         "prelogin_cookie": "FRESH",
                                         "portal_userauthcookie": ""})

    args = Args()
    args.no_saved_login = True
    assert cli.do_connect(args, tls=None) == 0
    assert used["auth"]["prelogin_cookie"] == "FRESH"
