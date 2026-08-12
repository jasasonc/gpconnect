"""Certificate handling.

Many GlobalProtect portals serve only the leaf certificate and omit the
intermediate. Browsers paper over this by fetching the missing link through the
Authority Information Access (AIA) extension; Python and openconnect do not, and
simply refuse to connect.

Rather than disabling verification (which is what the official client does), we
fetch the missing intermediates ourselves and verify the completed chain against
the ordinary system trust store. The verified leaf is then pinned for the login
webview and handed to openconnect as ``--servercert``.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
import warnings
from pathlib import Path

import requests

from .common import CACHE_DIR, SESSION, USER_AGENT, die, log

try:  # optional: without it the chain cannot be repaired
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs7
    from cryptography.x509.oid import AuthorityInformationAccessOID
except ImportError:  # pragma: no cover
    x509 = None


class Tls:
    """Outcome of trust negotiation with the portal."""

    def __init__(self, fingerprint: str, cafile: str | None, leaf_der: bytes = b"") -> None:
        self.fingerprint = fingerprint      # sha256 hex digest of the leaf
        self.cafile = cafile                # completed CA bundle, or None
        self.leaf_der = leaf_der            # server certificate (for the webview)


def fetch_leaf_der(host: str, port: int = 443, timeout: float = 15.0) -> bytes:
    """Grab the server certificate without validating it (validation follows)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
            der = tls_sock.getpeercert(binary_form=True)
    if not der:
        die(f"server {host} sent no certificate")
    return der


def _load_certs(data: bytes) -> list:
    """Accept a certificate in DER, PEM or PKCS#7 form."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # CA-issued PKCS#7 is often BER, not DER
        for loader in (
            lambda d: [x509.load_der_x509_certificate(d)],
            lambda d: [x509.load_pem_x509_certificate(d)],
            pkcs7.load_der_pkcs7_certificates,
            pkcs7.load_pem_pkcs7_certificates,
        ):
            try:
                certs = loader(data)
                if certs:
                    return list(certs)
            except Exception:
                continue
    return []


def _ca_issuer_url(cert) -> str | None:
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return None
    for desc in aia:
        if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
            url = desc.access_location.value
            if url.startswith(("http://", "https://")):
                return url
    return None


def aia_chain(leaf_der: bytes, max_depth: int = 4) -> list:
    """Follow AIA pointers and download the missing intermediates."""
    chain = []
    current = x509.load_der_x509_certificate(leaf_der)
    for _ in range(max_depth):
        if current.issuer == current.subject:
            break
        url = _ca_issuer_url(current)
        if not url:
            break
        try:
            data = requests.get(url, timeout=20).content
        except requests.RequestException as exc:
            log(f"could not download the issuer certificate ({exc})")
            break
        certs = _load_certs(data)
        if not certs:
            break
        chain.append(certs[0])
        current = certs[0]
    return chain


def system_ca_file() -> str | None:
    paths = ssl.get_default_verify_paths()
    for candidate in (paths.cafile, paths.openssl_cafile, "/etc/ssl/certs/ca-certificates.crt"):
        if candidate and Path(candidate).is_file():
            return candidate
    return None


def build_bundle(portal: str, leaf_der: bytes) -> str | None:
    """Write system roots plus the downloaded intermediates to a bundle file."""
    if x509 is None:
        log("the 'cryptography' module is missing -- cannot repair the chain")
        return None
    chain = aia_chain(leaf_der)
    if not chain:
        return None
    base = system_ca_file()
    if not base:
        return None
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    bundle = CACHE_DIR / f"ca-{portal}.pem"
    parts = [Path(base).read_bytes()]
    parts += [c.public_bytes(serialization.Encoding.PEM) for c in chain]
    bundle.write_bytes(b"\n".join(parts))
    names = ", ".join(c.subject.rfc4514_string() for c in chain)
    log(f"completed the certificate chain via AIA: {names}")
    return str(bundle)


def _verify_works(portal: str, verify) -> bool:
    try:
        requests.get(f"https://{portal}/", verify=verify, timeout=20,
                     headers={"User-Agent": USER_AGENT})
        return True
    except requests.exceptions.SSLError:
        return False
    except requests.RequestException:
        return True  # reachable; the failure was not about TLS


def setup_tls(portal: str, insecure: bool = False, expect: str | None = None) -> Tls:
    """Establish how we trust this portal and configure the shared session."""
    leaf_der = fetch_leaf_der(portal)
    fingerprint = hashlib.sha256(leaf_der).hexdigest()

    if expect:
        wanted = expect.split(":", 1)[-1].replace(":", "").lower()
        if wanted != fingerprint:
            die(f"certificate fingerprint mismatch!\n  expected: {wanted}\n  got:      {fingerprint}")
        log("certificate fingerprint matches --servercert")

    if insecure:
        SESSION.verify = False
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        log(f"TLS verification disabled; certificate sha256: {fingerprint}")
        return Tls(fingerprint, None, leaf_der)

    if _verify_works(portal, True):
        SESSION.verify = True
        return Tls(fingerprint, None, leaf_der)

    log("server sent an incomplete certificate chain -- trying the AIA repair")
    bundle = build_bundle(portal, leaf_der)
    if bundle and _verify_works(portal, bundle):
        SESSION.verify = bundle
        return Tls(fingerprint, bundle, leaf_der)

    die("cannot verify the portal certificate.\n"
        f"  If you trust it, retry with:  --servercert sha256:{fingerprint} --insecure")
    raise AssertionError("unreachable")
