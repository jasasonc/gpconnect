"""Command line interface."""

from __future__ import annotations

import argparse
import functools
import json
import sys

from . import __doc__ as package_doc
from . import store
from .auth import authenticate, forget, forward_callback, install_handler, uninstall_handler
from .common import log
from .portal import getconfig, portal_config, prelogin
from .tls import setup_tls
from .vpn import check_cookie, run_openconnect

#: Defaults for the shared flags. They are *not* declared as argparse defaults:
#: the parent parser is reused by every subparser, and a subparser would then
#: reset whatever was given before the subcommand ("gpconnect --webview connect
#: host" would silently lose --webview). Declaring them SUPPRESS keeps unset
#: options out of the namespace, and we fill the gaps once, afterwards.
SHARED_DEFAULTS = {
    "insecure": False,
    "servercert": None,
    "browser": None,
    "no_browser": False,
    "webview": False,
    "timeout": 300.0,
    "elevate": "auto",
    "login_hint": None,
    "no_login_hint": False,
    "remember": False,
    "no_saved_login": False,
}


def build_parser() -> argparse.ArgumentParser:
    # Shared flags live in a parent parser so they work before *and* after the
    # subcommand -- `gpconnect connect host --webview` is what people type.
    common = argparse.ArgumentParser(add_help=False)
    add = functools.partial(common.add_argument, default=argparse.SUPPRESS)
    add("--insecure", action="store_true", help="do not verify the TLS certificate")
    add("--servercert", help="expected fingerprint, e.g. sha256:abc...")
    add("--browser", help="browser command (default: xdg-open)")
    add("--no-browser", action="store_true",
        help="do not open a browser; just print the SAML URL")
    add("--webview", action="store_true",
        help="log in inside an embedded WebKit window (bypasses Chrome)")
    add("--timeout", type=float, help="seconds to wait for the login (default: 300)")
    add("--elevate", choices=("auto", "sudo", "pkexec", "none"),
        help="how to gain root for openconnect (default: auto)")
    add("--login-hint", metavar="EMAIL",
        help="pre-fill this account (default: whoever logged in last)")
    add("--no-login-hint", action="store_true",
        help="do not pre-fill the account")
    add("--remember", action="store_true",
        help="save the login so later runs skip the browser entirely "
             "(stores a bearer credential; keyring when available)")
    add("--no-saved-login", action="store_true",
        help="ignore a saved login for this run")

    parser = argparse.ArgumentParser(
        prog="gpconnect", description=package_doc, parents=[common],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_connect = sub.add_parser("connect", parents=[common], help="log in and bring up the tunnel")
    p_connect.add_argument("portal")
    p_connect.add_argument("--gateway", help="connect straight to this gateway")
    p_connect.add_argument("openconnect_args", nargs="*",
                           help="extra arguments for openconnect (after --)")

    p_auth = sub.add_parser("auth", parents=[common], help="log in only; print the credentials")
    p_auth.add_argument("portal")
    p_auth.add_argument("--json", action="store_true")

    p_gw = sub.add_parser("gateways", parents=[common], help="list the available gateways")
    p_gw.add_argument("portal")

    p_check = sub.add_parser("check", parents=[common],
                             help="inspect the portal and its certificate (no login)")
    p_check.add_argument("portal")

    sub.add_parser("install-handler", help="register the globalprotectcallback: scheme")
    sub.add_parser("uninstall-handler", help="remove that registration")
    sub.add_parser("forget", help="delete the remembered account and session cookies")

    p_cb = sub.add_parser("callback", help="internal: receive a callback URL")
    p_cb.add_argument("url")

    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse arguments and apply the shared defaults left out by SUPPRESS."""
    args = build_parser().parse_args(argv)
    for key, value in SHARED_DEFAULTS.items():
        if not hasattr(args, key):
            setattr(args, key, value)
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.cmd == "install-handler":
        install_handler()
        return 0
    if args.cmd == "uninstall-handler":
        uninstall_handler()
        return 0
    if args.cmd == "callback":
        forward_callback(args.url)
        return 0
    if args.cmd == "forget":
        forget()
        return 0

    tls = setup_tls(args.portal, args.insecure, args.servercert)

    if args.cmd == "check":
        info = prelogin(args.portal)
        print(f"portal:          {args.portal}")
        print(f"sha256:          {tls.fingerprint}")
        print(f"ca bundle:       {tls.cafile or '(system)'}")
        print(f"login:           {info['saml_method'] or 'username/password'}")
        print(f"default browser: {'yes' if info['default_browser'] else 'no'}")
        print(f"region:          {info['region']}")
        return 0

    if args.cmd == "connect":
        return do_connect(args, tls)

    hint = "" if args.no_login_hint else args.login_hint
    auth = authenticate(args.portal, args.browser, args.timeout, args.no_browser,
                        args.webview, tls, hint, args.remember)

    if args.cmd == "gateways":
        for gw in getconfig(args.portal, auth):
            print(f"{gw['address']:<24} {gw['name']}")
        return 0

    if args.cmd == "auth":
        if args.json:
            print(json.dumps(auth, indent=2))
        else:
            cookie = auth["prelogin_cookie"] or auth["portal_userauthcookie"]
            print(f"user:   {auth['username']}")
            print(f"cookie: {cookie}")
        return 0

    return 0


def save_reusable_login(args, auth: dict, tls) -> dict:
    """Store a cookie that later runs can reuse, and return the auth to connect with.

    A prelogin-cookie is single use: the portal invalidates it the moment it is
    presented to getconfig.esp. So when we have to ask the portal ourselves, the
    connection must continue with the portal-userauthcookie we just received --
    handing openconnect the spent prelogin-cookie makes it fall back to
    prompting, which fails with "fgets (stdin)" as there is no terminal.
    """
    cookie = auth.get("portal_userauthcookie", "")
    if cookie:  # the identity provider already handed one over; nothing is spent
        store.save_cookie(args.portal, auth["username"], cookie)
        return auth

    config = portal_config(args.portal, auth)  # this spends the prelogin-cookie
    cookie = config["userauthcookie"] or config["prelogonuserauthcookie"]
    if cookie:
        store.save_cookie(args.portal, auth["username"], cookie)
        return {**auth, "prelogin_cookie": "", "portal_userauthcookie": cookie}

    log("the portal issued no reusable cookie -- cookie authentication is "
        "disabled on it, so every run needs a login")
    log("the one-time login cookie was spent asking; logging in once more")
    hint = "" if args.no_login_hint else args.login_hint
    return authenticate(args.portal, args.browser, args.timeout, args.no_browser,
                        args.webview, tls, hint, remember=True)


def do_connect(args, tls) -> int:
    """Bring up the tunnel, reusing a saved portal login when there is one."""
    saved = None if args.no_saved_login else store.load_cookie(args.portal)
    if saved:
        auth = {"username": saved["username"], "prelogin_cookie": "",
                "portal_userauthcookie": saved["cookie"]}
        accepted = check_cookie(args.portal, auth, tls, args.gateway)
        if accepted is not False:
            if accepted is None:
                log("could not check the saved login (network?) -- trying it anyway")
            log("using the saved portal login -- no browser needed")
            return run_openconnect(args.portal, auth, tls, args.gateway,
                                   args.openconnect_args, args.elevate)
        log("the saved login was refused (expired?) -- logging in again")
        store.clear_cookie(args.portal)

    # Having a saved login means --remember was chosen before; keep honouring it,
    # or one expired cookie would leave every later run at the login window.
    remember = args.remember or bool(saved)
    hint = "" if args.no_login_hint else args.login_hint
    auth = authenticate(args.portal, args.browser, args.timeout, args.no_browser,
                        args.webview, tls, hint, remember)

    if remember:
        auth = save_reusable_login(args, auth, tls)

    return run_openconnect(args.portal, auth, tls, args.gateway, args.openconnect_args,
                           args.elevate)


def run() -> None:
    """Console-script entry point."""
    sys.exit(main())
