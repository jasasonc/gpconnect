"""Tests for the callback payload parsing and the loopback callback path."""

from __future__ import annotations

import base64
import threading

import pytest

from gpconnect.auth import CallbackServer, parse_auth_data

XML = ("<saml-auth-status>1</saml-auth-status>"
       "<prelogin-cookie>COOKIE==</prelogin-cookie>"
       "<saml-username>user@example.org</saml-username>")


def callback_url(payload: str) -> str:
    return "globalprotectcallback:" + base64.b64encode(payload.encode()).decode()


def test_parses_base64_xml():
    auth = parse_auth_data(callback_url(XML))
    assert auth["username"] == "user@example.org"
    assert auth["prelogin_cookie"] == "COOKIE=="
    assert auth["status"] == "1"


def test_parses_plain_xml():
    """Some portals hand the payload over undecoded."""
    assert parse_auth_data("globalprotectcallback:" + XML)["prelogin_cookie"] == "COOKIE=="


def test_parses_url_encoded_payload():
    encoded = base64.b64encode(XML.encode()).decode().replace("=", "%3D")
    assert parse_auth_data("globalprotectcallback:" + encoded)["username"] == "user@example.org"


def test_parses_cas_json():
    blob = base64.b64encode(
        b'{"username":"u@example.org","preloginCookie":"XYZ"}').decode()
    auth = parse_auth_data("globalprotectcallback:cas-as=" + blob)
    assert (auth["username"], auth["prelogin_cookie"]) == ("u@example.org", "XYZ")


def test_portal_userauthcookie_variant():
    payload = ("<saml-auth-status>1</saml-auth-status>"
               "<portal-userauthcookie>PORTAL</portal-userauthcookie>"
               "<saml-username>u@example.org</saml-username>")
    auth = parse_auth_data(callback_url(payload))
    assert auth["portal_userauthcookie"] == "PORTAL"
    assert auth["prelogin_cookie"] == ""


def test_missing_fields_are_empty_not_fatal():
    auth = parse_auth_data(callback_url("<saml-auth-status>-1</saml-auth-status>"))
    assert auth["username"] == ""
    assert auth["status"] == "-1"


def test_callback_server_round_trip():
    """The browser -> handler -> waiting process path, without a browser."""
    from gpconnect.auth import forward_callback

    with CallbackServer() as server:
        threading.Thread(target=forward_callback, args=(callback_url(XML),),
                         daemon=True).start()
        raw = server.wait(10)

    assert raw is not None
    assert parse_auth_data(raw)["prelogin_cookie"] == "COOKIE=="


@pytest.mark.parametrize("junk", ["", "globalprotectcallback:", "not-a-callback"])
def test_junk_does_not_raise(junk):
    assert parse_auth_data(junk)["username"] == ""
