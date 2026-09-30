# gpconnect

[![CI](https://github.com/ladisk/gpconnect/actions/workflows/ci.yml/badge.svg)](https://github.com/ladisk/gpconnect/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A small, free **GlobalProtect VPN client for Linux**.

Palo Alto's GlobalProtect has no usable free Linux client, and the popular
[GlobalProtect-openconnect](https://github.com/yuezk/GlobalProtect-openconnect)
GUI is paid. But the paid part is only the **login**: the tunnel itself is
carried perfectly well by [openconnect](https://www.infradead.org/openconnect/)
(GPL, in every distribution) via `--protocol=gp`.

So `gpconnect` does the SAML login, extracts `prelogin-cookie`, and hands the
tunnel to openconnect. About 700 lines of Python, no daemon, no tray icon.

## How it works

```
prelogin.esp ──► SAML request (e.g. Entra ID, Okta, Shibboleth)
                     │
             login window / browser ──► globalprotectcallback:<base64>
                     │                             │
                     │        x-scheme-handler ────┘
                     ▼
        saml-username + prelogin-cookie
                     │
                     ▼
   openconnect --protocol=gp --usergroup=portal:prelogin-cookie
```

The answer is picked up whichever way the portal returns it: as a navigation to
`globalprotectcallback:`, in the HTTP response headers (`saml-username`,
`prelogin-cookie`), or embedded in the final page's HTML.

### Certificate chains are repaired, not ignored

Many GlobalProtect portals serve only the leaf certificate and omit the
intermediate. Browsers hide this by fetching the missing link through the
certificate's AIA extension; Python, WebKit and openconnect do not, and refuse
the connection.

`gpconnect` downloads the missing intermediates itself, verifies the completed
chain against the ordinary system trust store, then pins that verified
certificate for the login window and passes it to openconnect as
`--servercert sha256:…` plus `--cafile`.

This is deliberately stricter than the official client, whose log reads
`TLS errors will be ignored` and `Accepting the server certificate though signer
not found`.

## Requirements

```bash
sudo apt install openconnect                             # the tunnel
sudo apt install python3-requests python3-cryptography   # usually present
sudo apt install python3-gi gir1.2-webkit2-4.1           # for --webview login
sudo apt install python3-keyring                          # optional, for --remember
```

## Install

```bash
pip install git+https://github.com/ladisk/gpconnect
```

Or run it straight from a checkout — no install needed:

```bash
git clone https://github.com/ladisk/gpconnect
ln -sf "$PWD/gpconnect/bin/gpconnect" ~/.local/bin/gpconnect
```

## Usage

```bash
gpconnect check    vpn.example.org             # portal + certificate, no login
gpconnect connect  vpn.example.org --webview   # log in and bring up the tunnel
gpconnect auth     vpn.example.org --webview   # log in only, print the cookie
gpconnect gateways vpn.example.org --webview   # list gateways
gpconnect connect  vpn.example.org --gateway gw.example.org
```

Extra arguments go to openconnect after `--`:

```bash
gpconnect connect vpn.example.org --webview -- --script /usr/share/vpnc-scripts/vpnc-script -v
```

Root is needed for the tunnel device: `gpconnect` uses passwordless `sudo` when
available, otherwise `pkexec` (graphical prompt). Override with
`--elevate sudo|pkexec|none`.

### `--webview`, and why you probably want it

By default the login opens in your **default browser**, and the answer comes
back through a registered `globalprotectcallback:` scheme handler (installed
automatically on first use).

**This does not work with Chrome**: Chrome will not follow a redirect to a
custom scheme without a user gesture, so the answer never returns. The desktop
plumbing itself is fine — `xdg-open 'globalprotectcallback:…'` triggers the
handler correctly — Chrome simply refuses the redirect.

With `--webview`, `gpconnect` opens its own WebKit window and reads the answer
directly. That path is portal- and browser-independent, and is the recommended
mode.

If the browser route stalls anyway, you can paste the `globalprotectcallback:…`
URL into the terminal and press Enter; `gpconnect` also listens on stdin.

### Not typing your address every time

After a successful login the account name is stored in
`~/.config/gpconnect/config.json` (per portal, mode 0600) and passed to the
identity provider as `login_hint` on the next run, so the account is pre-filled.
Nothing secret is written there — just the address.

```bash
gpconnect connect vpn.example.org --webview --login-hint me@example.org  # override
gpconnect connect vpn.example.org --webview --no-login-hint              # disable
gpconnect forget                                                         # clear
```

### Persistent login: skipping password and MFA

With `--remember`, a successful login is saved and later runs reuse it — no
browser window, no password, no second factor:

```bash
gpconnect connect vpn.example.org --webview --remember   # once
gpconnect connect vpn.example.org --webview              # afterwards: silent
```

Two things get stored:

- the portal's `portal-userauthcookie`, which replaces the whole SAML round trip.
  It is presented at the **gateway** — the portal itself answers HTTP 512 to it —
  and goes into the **system keyring** when one is available (install
  `python3-keyring`), otherwise into `~/.config/gpconnect/credentials.json` with
  mode 0600;
- the login window's own cookies in `~/.local/share/gpconnect/`, so the identity
  provider session survives too.

How long it lasts is decided by the portal and your identity provider, not by
gpconnect: the portal cookie lives as long as its *authentication override*
lifetime, and the IdP session as long as your conditional-access policy allows.
Before each connect, gpconnect checks the saved cookie with
`openconnect --authenticate` (no root, no tunnel). When it is refused, gpconnect
drops it and falls back to a normal login. A failure after the check, such as a
cancelled password prompt, leaves the cookie alone.

Both are bearer credentials — anyone who can read them can bring up your VPN —
which is why this is opt-in. `gpconnect forget` removes everything, and
`--no-saved-login` ignores it for one run.

If the portal has cookie authentication disabled, `--remember` says so and only
the pre-filled account remains.

## Commands

| command | description |
|---|---|
| `check` | certificate fingerprint, login method, region |
| `auth` | SAML login; prints user and cookie (`--json`) |
| `gateways` | gateway list from `getconfig.esp` |
| `connect` | login plus openconnect |
| `install-handler` / `uninstall-handler` | scheme registration |
| `forget` | drop the remembered account and the saved login |
| `callback <url>` | internal; invoked by the browser |

Shared flags: `--webview`, `--insecure`, `--servercert sha256:…`, `--browser`,
`--no-browser`, `--timeout`, `--elevate`, `--login-hint`, `--no-login-hint`,
`--remember`, `--no-saved-login`. They work before or after the subcommand.

## Shortcuts

`contrib/vpn-fs` is a one-line wrapper for a single portal:

```bash
install -m755 contrib/vpn-fs ~/.local/bin/vpn-fs   # then just: vpn-fs
```

`contrib/gpconnect.desktop` adds a desktop launcher.

## Limitations

- Only SAML login is implemented. For plain username/password portals,
  openconnect already works on its own.
- HIP (Host Information Profile) reporting is not implemented. If your portal
  requires it, the session drops after a while; openconnect's
  `--csd-wrapper=hipreport.sh` is the workaround.
- The data plane is openconnect's. This is not a reimplementation of the
  GlobalProtect tunnel protocol, and there is no reason for it to be one.
- Tested against a PAN-OS portal with Microsoft Entra ID SAML on Ubuntu.

## Development

```bash
pip install -e ".[dev]"
pytest -q
ruff check .
```

## Credits

Built on [openconnect](https://www.infradead.org/openconnect/). The
`globalprotectcallback:` mechanism and the header-based fallback follow the
approaches used by
[GlobalProtect-openconnect](https://github.com/yuezk/GlobalProtect-openconnect)
and [gp-saml-gui](https://github.com/dlenski/gp-saml-gui).

Not affiliated with or endorsed by Palo Alto Networks. "GlobalProtect" is their
trademark.

## License

MIT — see [LICENSE](LICENSE).
