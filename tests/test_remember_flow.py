"""Tests for --remember: a prelogin-cookie must never be spent twice.

The portal invalidates a prelogin-cookie as soon as it is presented to
getconfig.esp. Handing that spent cookie to openconnect made it fall back to
prompting, which died with "fgets (stdin): Inappropriate ioctl for device".
"""

from __future__ import annotations

import pytest

from gpconnect import cli, common, store

SAML_ONLY = {"username": "u@example.org", "prelogin_cookie": "PRELOGIN",
             "portal_userauthcookie": ""}
SAML_WITH_COOKIE = {"username": "u@example.org", "prelogin_cookie": "PRELOGIN",
                    "portal_userauthcookie": "PORTAL"}


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    monkeypatch.setattr(common, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(store, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(store, "CREDENTIALS_FILE", tmp_path / "credentials.json")
    monkeypatch.setattr(store, "_keyring", lambda: None)


class Args:
    portal = "vpn.example.org"
    gateway = None
    openconnect_args: list = []
    elevate = "none"
    no_saved_login = False
    remember = True
    browser = None
    timeout = 5.0
    no_browser = False
    webview = True
    login_hint = None
    no_login_hint = False


def test_cookie_from_the_idp_needs_no_portal_call(monkeypatch):
    """Nothing is spent, so the prelogin-cookie stays usable for openconnect."""
    def boom(*_a, **_k):
        raise AssertionError("portal_config() must not be called")

    monkeypatch.setattr(cli, "portal_config", boom)
    auth = cli.save_reusable_login(Args(), dict(SAML_WITH_COOKIE), tls=None)
    assert auth["prelogin_cookie"] == "PRELOGIN"       # untouched
    assert store.load_cookie("vpn.example.org")["cookie"] == "PORTAL"


def test_portal_call_hands_the_new_cookie_to_openconnect(monkeypatch):
    """After getconfig.esp the prelogin-cookie is spent and must not be reused."""
    monkeypatch.setattr(cli, "portal_config",
                        lambda *_a: {"gateways": [], "userauthcookie": "PORTAL",
                                     "prelogonuserauthcookie": ""})
    auth = cli.save_reusable_login(Args(), dict(SAML_ONLY), tls=None)
    assert auth["prelogin_cookie"] == ""               # the spent one is dropped
    assert auth["portal_userauthcookie"] == "PORTAL"
    assert store.load_cookie("vpn.example.org")["cookie"] == "PORTAL"


def test_prelogon_cookie_is_accepted_too(monkeypatch):
    monkeypatch.setattr(cli, "portal_config",
                        lambda *_a: {"gateways": [], "userauthcookie": "",
                                     "prelogonuserauthcookie": "PRELOGON"})
    auth = cli.save_reusable_login(Args(), dict(SAML_ONLY), tls=None)
    assert auth["portal_userauthcookie"] == "PRELOGON"


def test_portal_without_cookie_auth_logs_in_again(monkeypatch):
    """The spent cookie cannot be reused, so a fresh login is the only way on."""
    monkeypatch.setattr(cli, "portal_config",
                        lambda *_a: {"gateways": [], "userauthcookie": "",
                                     "prelogonuserauthcookie": ""})
    monkeypatch.setattr(cli, "authenticate",
                        lambda *a, **k: {"username": "u@example.org",
                                         "prelogin_cookie": "FRESH",
                                         "portal_userauthcookie": ""})
    auth = cli.save_reusable_login(Args(), dict(SAML_ONLY), tls=None)
    assert auth["prelogin_cookie"] == "FRESH"
    assert store.load_cookie("vpn.example.org") is None


def test_openconnect_never_waits_for_input():
    """--non-inter keeps a rejected cookie from turning into a stdin prompt."""
    from gpconnect.tls import Tls
    from gpconnect.vpn import run_openconnect

    recorded = {}

    class FakeProc:
        stdin = type("FakeStdin", (), {"write": lambda self, data: None,
                                       "close": lambda self: None})()
        stdout = iter([])

        def wait(self):
            return 0

    def fake_popen(argv, **_kwargs):
        recorded["argv"] = argv
        return FakeProc()

    import gpconnect.vpn as vpn
    original_find, original_popen = vpn.find_openconnect, vpn.subprocess.Popen
    vpn.find_openconnect = lambda: "/usr/sbin/openconnect"
    vpn.subprocess.Popen = fake_popen
    try:
        run_openconnect("vpn.example.org", SAML_ONLY, Tls("fp", None), None, [],
                        elevate="none")
    finally:
        vpn.find_openconnect, vpn.subprocess.Popen = original_find, original_popen

    assert "--non-inter" in recorded["argv"]
