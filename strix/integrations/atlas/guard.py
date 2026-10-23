"""Loopback target guard (structural, mirrors asset_atlas.adapters._assert_loopback)."""

from __future__ import annotations

import socket
import urllib.request
from urllib.parse import urlparse


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: ARG002 - stdlib signature
        raise ValueError("atlas bridge guard: redirects refused (re-validation would be required)")


_OPENER = urllib.request.build_opener(_NoRedirect)


def assert_loopback(host: str) -> str:
    """Resolve host; require EVERY IPv4 address to be loopback; return pinned IP.

    Callers must connect to the returned literal IP so a DNS change between
    check and connect cannot redirect the scan.
    """
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
    except socket.gaierror as exc:
        raise ValueError(f"atlas bridge guard: cannot resolve {host!r}") from exc
    if not infos:
        raise ValueError(f"atlas bridge guard: {host!r} resolved to nothing")
    for info in infos:
        addr = info[4][0]
        if not addr.startswith("127."):
            raise ValueError(
                f"atlas bridge guard: {host!r} resolves to {addr}, not loopback - refused"
            )
    return infos[0][4][0]


def assert_loopback_url(url: str) -> tuple[str, str, int]:
    """Validate an http(s) URL targets loopback only.

    Returns (pinned_url, host, port) where pinned_url rewrites the host to the
    resolved loopback literal so the scan cannot be redirected by re-resolution.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"atlas bridge guard: scheme {parsed.scheme!r} not supported")
    host = parsed.hostname
    if not host:
        raise ValueError(f"atlas bridge guard: no host in {url!r}")
    pinned = assert_loopback(host)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    netloc = f"{pinned}:{port}"
    if parsed.username or parsed.password:
        raise ValueError("atlas bridge guard: credentials in target URL refused")
    pinned_url = parsed._replace(netloc=netloc).geturl()
    return pinned_url, host, port


def preflight_target(pinned_url: str, timeout: float = 3.0) -> None:
    """Verify the pinned loopback target answers before a scan is launched.

    Raises ValueError when unreachable, so fan-out tasks against dead fixtures
    are rejected cleanly instead of burning scan budget. Any HTTP status
    (including 4xx) counts as answering; transport errors do not.
    """
    req = urllib.request.Request(pinned_url, method="HEAD")  # noqa: S310 - pinned loopback URL
    try:
        with _OPENER.open(req, timeout=timeout):
            return
    except ValueError:
        raise
    except Exception as exc:
        # an HTTP error response still proves the service is alive
        if exc.__class__.__name__ == "HTTPError":
            return
        raise ValueError(f"atlas bridge guard: target {pinned_url!r} unreachable ({exc})") from exc
