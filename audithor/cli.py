"""Command-line interface for Audithor."""

import argparse
import ipaddress
import os
import socket
import sys

from . import __version__


def resolve_bind(args, env):
    host = args.host if args.host is not None else env.get("AUDITHOR_HOST", "127.0.0.1")
    raw_port = args.port if args.port is not None else env.get("AUDITHOR_PORT", "5001")
    try:
        port = int(raw_port)
        if not 1 <= port <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError(f"Invalid port {raw_port!r}; choose an integer between 1 and 65535.")
    return host, port


def _is_loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower() == "localhost"


def _port_available(host, port):
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        for family, socktype, proto, _, address in addresses:
            with socket.socket(family, socktype, proto) as sock:
                sock.bind(address)
        return True
    except OSError:
        return False


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="audithor",
        description="Audithor's API has no authentication and must not be exposed beyond loopback.",
    )
    parser.add_argument("--host", help="Interface to bind (default: AUDITHOR_HOST or 127.0.0.1).")
    parser.add_argument("--port", help="Port to bind (default: AUDITHOR_PORT or 5001).")
    parser.add_argument("--no-browser", action="store_true", help="Do not open a browser at startup.")
    parser.add_argument("--version", action="version", version=f"audithor {__version__}")
    args = parser.parse_args(argv)
    try:
        host, port = resolve_bind(args, os.environ)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if not _port_available(host, port):
        print(f"Port {port} is already in use. Choose another one with --port.", file=sys.stderr)
        return 1

    os.environ["AUDITHOR_HOST"] = host
    os.environ["AUDITHOR_PORT"] = str(port)
    if not _is_loopback(host):
        print("Warning: The API has no authentication and is bound to a non-loopback host.", file=sys.stderr)
    print(f"Serving Audithor at http://{host}:{port}/")
    print("Press Ctrl+C to stop.")
    from .audithor_app import run

    try:
        run(host, port, open_browser=not args.no_browser)
    except KeyboardInterrupt:
        return 0
    return 0
