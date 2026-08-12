"""gpconnect - a small, free GlobalProtect VPN client for Linux.

It performs the SAML login, extracts ``prelogin-cookie`` and hands the tunnel to
``openconnect --protocol=gp``. Along the way it repairs incomplete certificate
chains instead of disabling verification.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__", "main"]


def main(argv=None) -> int:
    from .cli import main as _main
    return _main(argv)
