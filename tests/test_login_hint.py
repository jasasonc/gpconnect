"""Tests for remembering the account and pre-filling it via login_hint."""

from __future__ import annotations

import pytest

from gpconnect import auth, common

SAML_URL = ("https://login.microsoftonline.com/tenant/saml2"
            "?SAMLRequest=jVHPT4M%2BwFP5XSO9A1zJWmkGC28El&RelayState=n%2FgAAPT84Gk")


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    """Never touch the real ~/.config/gpconnect during tests."""
    config = tmp_path / "config.json"
    monkeypatch.setattr(common, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(common, "CONFIG_FILE", config)
    monkeypatch.setattr(auth, "CONFIG_FILE", config)
    return config


def test_hint_is_appended_to_an_existing_query():
    out = auth.with_login_hint(SAML_URL, "user@example.org")
    assert out.startswith(SAML_URL + "&login_hint=")
    assert out.endswith("user%40example.org")


def test_saml_request_is_left_byte_for_byte_intact():
    """Re-encoding the query would corrupt the base64 SAML request."""
    out = auth.with_login_hint(SAML_URL, "user@example.org")
    assert out.split("&login_hint=")[0] == SAML_URL


def test_question_mark_is_used_when_there_is_no_query():
    out = auth.with_login_hint("https://idp.example.org/saml", "u@example.org")
    assert out == "https://idp.example.org/saml?login_hint=u%40example.org"


def test_existing_hint_is_not_duplicated():
    url = SAML_URL + "&login_hint=someone%40example.org"
    assert auth.with_login_hint(url, "other@example.org") == url


def test_empty_username_changes_nothing():
    assert auth.with_login_hint(SAML_URL, "") == SAML_URL


def test_non_http_payload_is_untouched():
    """A POST-method payload is HTML, not a URL."""
    html = "<html><form action='...'></form></html>"
    assert auth.with_login_hint(html, "u@example.org") == html


def test_username_round_trip(isolated_config):
    assert auth.remembered_username("vpn.example.org") == ""
    auth.remember_username("vpn.example.org", "u@example.org")
    assert auth.remembered_username("vpn.example.org") == "u@example.org"
    assert isolated_config.exists()


def test_usernames_are_kept_per_portal():
    auth.remember_username("vpn.a.org", "a@example.org")
    auth.remember_username("vpn.b.org", "b@example.org")
    assert auth.remembered_username("vpn.a.org") == "a@example.org"
    assert auth.remembered_username("vpn.b.org") == "b@example.org"


def test_config_file_is_not_world_readable(isolated_config):
    auth.remember_username("vpn.example.org", "u@example.org")
    assert isolated_config.stat().st_mode & 0o077 == 0


def test_no_secrets_are_written(isolated_config):
    """Only the account name is persisted -- never a cookie."""
    auth.finalize_auth(
        "<saml-auth-status>1</saml-auth-status>"
        "<prelogin-cookie>SECRET-COOKIE</prelogin-cookie>"
        "<saml-username>u@example.org</saml-username>",
        timeout=1, portal="vpn.example.org")
    assert "SECRET-COOKIE" not in isolated_config.read_text()
    assert "u@example.org" in isolated_config.read_text()
