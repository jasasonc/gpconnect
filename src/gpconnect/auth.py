"""SAML login: obtaining ``prelogin-cookie`` from the identity provider.

Three ways to get the answer back, because portals differ:

1. the browser navigates to ``globalprotectcallback:<base64>``,
2. the portal returns the data in HTTP response headers, or
3. the data sits in the final page's HTML.

The external-browser route needs a registered ``x-scheme-handler``; note that
Chrome refuses to follow a redirect to a custom scheme without a user gesture,
which is why :func:`webview_auth` exists.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import http.server
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import urllib.parse
from pathlib import Path

import requests

from .common import CACHE_DIR, CALLBACK_SCHEME, DESKTOP_ID, PORT_FILE, die, log
from .portal import prelogin
from .tls import Tls

AUTH_TAGS = ("saml-auth-status", "saml-username", "prelogin-cookie", "portal-userauthcookie")


def parse_auth_data(raw: str) -> dict:
    """Decode the payload of a ``globalprotectcallback:`` URL."""
    raw = raw.strip().strip('"')
    if raw.startswith(f"{CALLBACK_SCHEME}:"):
        raw = raw[len(CALLBACK_SCHEME) + 1 :]
    raw = raw.lstrip("/")
    raw = urllib.parse.unquote(raw)

    # CAS variant: "cas-as=<base64 json>"
    if raw.startswith("cas-as="):
        raw = raw[len("cas-as=") :]

    decoded = raw
    if not raw.lstrip().startswith(("<", "{")):
        padded = raw + "=" * (-len(raw) % 4)
        for candidate in (padded, padded.replace("-", "+").replace("_", "/")):
            try:
                decoded = base64.b64decode(candidate, validate=True).decode("utf-8", "replace")
                break
            except (binascii.Error, ValueError):
                continue  # some portals send the payload undecoded

    if decoded.lstrip().startswith("{"):
        obj = json.loads(decoded)
        return {
            "username": obj.get("username", "") or obj.get("user", ""),
            "prelogin_cookie": obj.get("preloginCookie", "") or "",
            "portal_userauthcookie": obj.get("portalUserauthcookie", "") or "",
            "status": "1",
        }

    fields = {}
    for tag in AUTH_TAGS:
        match = re.search(rf"<{tag}>(.*?)</{tag}>", decoded, re.DOTALL)
        fields[tag] = match.group(1).strip() if match else ""

    return {
        "username": fields["saml-username"],
        "prelogin_cookie": fields["prelogin-cookie"],
        "portal_userauthcookie": fields["portal-userauthcookie"],
        "status": fields["saml-auth-status"] or "1",
    }


class CallbackServer:
    """Loopback HTTP server that receives the callback URL from the handler."""

    def __init__(self) -> None:
        self.result: str | None = None
        self.event = threading.Event()
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _ok(self, body: bytes = b"OK") -> None:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                outer.submit(self.rfile.read(length).decode("utf-8", "replace"))
                self._ok()

            def do_GET(self):  # noqa: N802
                query = urllib.parse.urlparse(self.path).query
                data = urllib.parse.parse_qs(query).get("data", [""])[0]
                if data:
                    outer.submit(data)
                    self._ok(b"<h3>Login complete. You can close this window.</h3>")
                else:
                    self._ok()

            def log_message(self, *args):  # keep quiet
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]

    def submit(self, data: str) -> None:
        if data.strip() and not self.event.is_set():
            self.result = data
            self.event.set()

    def __enter__(self) -> "CallbackServer":
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        PORT_FILE.write_text(str(self.port))
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc) -> None:
        self.httpd.shutdown()
        PORT_FILE.unlink(missing_ok=True)

    def wait(self, timeout: float) -> str | None:
        self.event.wait(timeout)
        return self.result


def open_in_browser(payload: str, method: str, browser: str | None) -> None:
    """Open the SAML request (REDIRECT = URL, POST = self-submitting HTML form)."""
    if method == "POST" or payload.lstrip().startswith("<"):
        tmp = Path(tempfile.mkdtemp(prefix="gpconnect-")) / "saml.html"
        tmp.write_text(payload)
        target = tmp.as_uri()
    else:
        target = payload.strip()

    opener = [browser] if browser else [shutil.which("xdg-open") or "xdg-open"]
    log(f"opening browser: {opener[0]}")
    subprocess.Popen(
        opener + [target],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def webview_auth(payload: str, method: str, timeout: float,
                 portal: str = "", tls: Tls | None = None) -> str | None:
    """Log in inside an embedded WebKit window.

    Chrome will not follow a redirect to a custom scheme without a user gesture,
    so here we own the window and read the answer directly -- from the
    ``globalprotectcallback:`` navigation, from the HTTP headers, or from HTML.
    """
    # Same workaround the official client applies; without it WebKit on Wayland
    # tends to render a black window.
    if os.environ.get("WAYLAND_DISPLAY"):
        os.environ.setdefault("WEBKIT_DISABLE_DMABUF_RENDERER", "1")
        os.environ.setdefault("LIBGL_ALWAYS_SOFTWARE", "1")

    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_version("WebKit2", "4.1")
    from gi.repository import Gio, GLib, Gtk, WebKit2  # noqa: E402

    captured: dict[str, str] = {}

    def finish(raw: str) -> None:
        # The capture can happen before the main loop starts, so check the level.
        if raw and "result" not in captured:
            captured["result"] = raw
            if Gtk.main_level() > 0:
                Gtk.main_quit()

    def from_headers(headers) -> None:
        try:
            status = headers.get_one("saml-auth-status")
            cookie = headers.get_one("prelogin-cookie") or headers.get_one("portal-userauthcookie")
            user = headers.get_one("saml-username")
        except Exception:
            return
        if user and cookie:
            finish(f"<saml-auth-status>{status or 1}</saml-auth-status>"
                   f"<prelogin-cookie>{cookie}</prelogin-cookie>"
                   f"<saml-username>{user}</saml-username>")

    window = Gtk.Window(title="GlobalProtect login")
    window.set_default_size(620, 780)
    view = WebKit2.WebView()
    # Entra ID rejects unknown clients, so present a mainstream browser UA.
    view.get_settings().set_user_agent(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.0 Safari/605.1.15"
    )
    window.add(view)
    window.connect("destroy", lambda *_: Gtk.main_quit())

    def on_decide_policy(_view, decision, decision_type):
        if decision_type == WebKit2.PolicyDecisionType.NAVIGATION_ACTION:
            uri = decision.get_navigation_action().get_request().get_uri() or ""
            if uri.startswith(f"{CALLBACK_SCHEME}:"):
                decision.ignore()
                finish(uri)
                return True
        return False

    def on_resource_load(_view, resource, _request):
        def on_finished(res):
            response = res.get_response()
            if response is not None:
                from_headers(response.get_http_headers())
        resource.connect("finished", on_finished)

    def on_load_changed(_view, event):
        if event != WebKit2.LoadEvent.FINISHED or "result" in captured:
            return

        def got_html(source, result, *_unused):
            try:
                if hasattr(source, "evaluate_javascript_finish"):
                    value = source.evaluate_javascript_finish(result).to_string()
                else:
                    value = source.run_javascript_finish(result).get_js_value().to_string()
            except Exception:
                return
            match = re.search(rf"{CALLBACK_SCHEME}:[^\"'<\s]+", value or "")
            if match:
                finish(match.group(0))

        script = "document.documentElement.outerHTML"
        if hasattr(view, "evaluate_javascript"):
            view.evaluate_javascript(script, -1, None, None, None, got_html, None)
        else:
            view.run_javascript(script, None, got_html, None)

    def cert_der(certificate) -> bytes:
        try:
            data = certificate.get_property("certificate")
        except Exception:
            return b""
        return bytes(data.get_data()) if hasattr(data, "get_data") else bytes(data or b"")

    def on_tls_errors(_view, failing_uri, certificate, errors):
        """Accept exactly the certificate we verified ourselves -- not every error."""
        host = urllib.parse.urlparse(failing_uri).hostname or ""
        der = cert_der(certificate)
        if tls and der and hashlib.sha256(der).hexdigest() == tls.fingerprint:
            view.get_context().allow_tls_certificate_for_host(certificate, host)
            log(f"webview: accepted the verified certificate for {host}")
            GLib.idle_add(lambda: (view.load_uri(failing_uri), False)[1])
            return True
        log(f"webview: TLS error for {failing_uri} ({errors})")
        return False

    # Pre-authorise the certificate we validated with the completed chain.
    if tls and tls.leaf_der and portal:
        try:
            pem = ssl.DER_cert_to_PEM_cert(tls.leaf_der)
            view.get_context().allow_tls_certificate_for_host(
                Gio.TlsCertificate.new_from_pem(pem, -1), portal)
            log(f"webview: pinned the verified certificate for {portal}")
        except Exception as exc:
            log(f"webview: could not pin the certificate ({exc})")

    view.connect("decide-policy", on_decide_policy)
    view.connect("resource-load-started", on_resource_load)
    view.connect("load-changed", on_load_changed)
    view.connect("load-failed-with-tls-errors", on_tls_errors)

    if method == "POST" or payload.lstrip().startswith("<"):
        view.load_html(payload, "https://localhost/")
    else:
        view.load_uri(payload.strip())

    GLib.timeout_add_seconds(int(timeout), lambda: (Gtk.main_quit(), False)[1])
    window.show_all()
    log("opened the login window (WebKit)")
    if "result" not in captured:
        Gtk.main()
    window.destroy()
    while Gtk.events_pending():
        Gtk.main_iteration()
    return captured.get("result")


def read_stdin_fallback(server: CallbackServer) -> None:
    """Manual fallback: the user pastes the globalprotectcallback: URL."""
    try:
        for line in sys.stdin:
            if line.strip():
                server.submit(line)
                return
    except (OSError, ValueError):
        pass


def authenticate(portal: str, browser: str | None, timeout: float,
                 no_browser: bool = False, webview: bool = False,
                 tls: Tls | None = None) -> dict:
    info = prelogin(portal)
    if not info["saml_payload"]:
        die("this portal does not use SAML; only SAML login is supported so far")
    if not info["default_browser"]:
        log("warning: portal does not advertise saml-default-browser; "
            "the manual fallback may be needed")

    if webview:
        raw = webview_auth(info["saml_payload"], info["saml_method"], timeout, portal, tls)
        return finalize_auth(raw, timeout)

    with CallbackServer() as server:
        if not handler_installed():
            log("scheme handler not registered -> running 'install-handler'")
            install_handler()

        if no_browser:
            print("SAML-URL: " + info["saml_payload"].strip(), flush=True)
        else:
            open_in_browser(info["saml_payload"], info["saml_method"], browser)
        print(
            "\nComplete the login in the browser.\n"
            "If it does not finish by itself, paste the 'globalprotectcallback:...' URL "
            "here and press Enter:\n",
            file=sys.stderr,
        )
        threading.Thread(target=read_stdin_fallback, args=(server,), daemon=True).start()

        raw = server.wait(timeout)

    return finalize_auth(raw, timeout)


def finalize_auth(raw: str | None, timeout: float) -> dict:
    if raw is None:
        die(f"login did not complete within {int(timeout)} s")

    auth = parse_auth_data(raw)
    if auth["status"] not in ("1", ""):
        die(f"SAML login rejected (saml-auth-status={auth['status']})")
    if not auth["username"] or not (auth["prelogin_cookie"] or auth["portal_userauthcookie"]):
        die("the response carried no username or cookie")

    log(f"logged in as {auth['username']}")
    return auth


# --------------------------------------------------------------------------
# globalprotectcallback: scheme handler
# --------------------------------------------------------------------------

def launcher_command() -> list[str]:
    """How the desktop entry should invoke us."""
    installed = shutil.which("gpconnect")
    if installed:
        return [installed]
    return [sys.executable, str(Path(sys.argv[0]).resolve())]


def desktop_path() -> Path:
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "applications"
    return base / DESKTOP_ID


def handler_installed() -> bool:
    path = desktop_path()
    return path.exists() and " ".join(launcher_command()) in path.read_text()


def install_handler() -> None:
    path = desktop_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=gpconnect callback\n"
        f"Exec={' '.join(launcher_command())} callback %u\n"
        "Terminal=false\n"
        "NoDisplay=true\n"
        f"MimeType=x-scheme-handler/{CALLBACK_SCHEME};\n"
    )
    for cmd in (
        ["update-desktop-database", str(path.parent)],
        ["xdg-mime", "default", DESKTOP_ID, f"x-scheme-handler/{CALLBACK_SCHEME}"],
    ):
        if shutil.which(cmd[0]):
            subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log(f"registered handler: {path}")


def uninstall_handler() -> None:
    path = desktop_path()
    path.unlink(missing_ok=True)
    if shutil.which("update-desktop-database"):
        subprocess.run(["update-desktop-database", str(path.parent)], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log("handler removed")


def forward_callback(url: str) -> None:
    """Invoked by the browser: hand the callback URL to the waiting process."""
    try:
        port = int(PORT_FILE.read_text().strip())
    except (OSError, ValueError):
        die("no gpconnect is waiting for a login (callback.port is missing)")
    requests.post(f"http://127.0.0.1:{port}/", data=url.encode(), timeout=10)
