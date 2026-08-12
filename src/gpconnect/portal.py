"""The GlobalProtect portal HTTP API (prelogin / getconfig)."""

from __future__ import annotations

import base64
import binascii
import socket
import xml.etree.ElementTree as ET
from pathlib import Path

from .common import CLIENT_VERSION, SESSION, die


def portal_post(portal: str, path: str, data: dict) -> str:
    resp = SESSION.post(f"https://{portal}{path}", data=data, timeout=30)
    resp.raise_for_status()
    return resp.text


def prelogin(portal: str) -> dict:
    """Ask the portal which kind of login it wants."""
    xml = portal_post(
        portal,
        "/global-protect/prelogin.esp",
        {"tmp": "tmp", "clientVer": "4100", "clientos": "Linux", "os-version": "linux-64"},
    )
    root = ET.fromstring(xml)

    def text(tag: str) -> str:
        el = root.find(tag)
        return (el.text or "").strip() if el is not None and el.text else ""

    if text("status") != "Success":
        die(f"prelogin failed: {text('msg') or xml[:200]}")

    saml_request = text("saml-request")
    decoded = ""
    if saml_request:
        try:
            decoded = base64.b64decode(saml_request).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            die("saml-request is not valid base64")

    return {
        "region": text("region"),
        "auth_message": text("authentication-message"),
        "saml_method": text("saml-auth-method").upper(),  # REDIRECT or POST
        "saml_payload": decoded,                          # URL or HTML form
        "default_browser": text("saml-default-browser").lower() == "yes",
    }


def host_id() -> str:
    """A stable machine identifier; some portals require one."""
    for path in ("/sys/class/dmi/id/product_uuid", "/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            value = Path(path).read_text().strip()
            if value:
                return value
        except OSError:
            continue
    return socket.gethostname()


def portal_config(portal: str, auth: dict) -> dict:
    """Fetch the portal configuration: gateways plus any reusable auth cookie.

    When the portal has cookie authentication enabled it hands out a
    ``portal-userauthcookie``, which later logins can present instead of going
    through the identity provider again.
    """
    data = {
        "prot": "https:",
        "inputStr": "",
        "jnlpReady": "jnlpReady",
        "computer": socket.gethostname(),
        "clientos": "Linux",
        "os-version": "linux-64",
        "clientgpversion": CLIENT_VERSION,
        "client-version": CLIENT_VERSION,
        "host-id": host_id(),
        "ipv6-support": "yes",
        "default-browser": "1",
        "cas-support": "1",
        "user": auth["username"],
        "passwd": "",
    }
    if auth.get("prelogin_cookie"):
        data["prelogin-cookie"] = auth["prelogin_cookie"]
    if auth.get("portal_userauthcookie"):
        data["portal-userauthcookie"] = auth["portal_userauthcookie"]

    xml = portal_post(portal, "/global-protect/getconfig.esp", data)
    root = ET.fromstring(xml)

    gateways: list[dict] = []
    for entry in root.iterfind(".//gateways//list/entry"):
        desc = entry.find("description")
        gateways.append({
            "address": entry.get("name", ""),
            "name": (desc.text or "").strip() if desc is not None and desc.text else "",
        })

    def cookie(tag: str) -> str:
        el = root.find(f".//{tag}")
        value = (el.text or "").strip() if el is not None and el.text else ""
        # An empty cookie is spelled "empty" by some PAN-OS versions.
        return "" if value.lower() in ("", "empty") else value

    return {
        "gateways": gateways,
        "userauthcookie": cookie("portal-userauthcookie"),
        "prelogonuserauthcookie": cookie("portal-prelogonuserauthcookie"),
    }


def getconfig(portal: str, auth: dict) -> list[dict]:
    """The gateway list alone."""
    return portal_config(portal, auth)["gateways"]
