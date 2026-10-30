import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

from audithor import __version__
from audithor.cli import resolve_bind


def run_module(*args, env=None):
    process_env = os.environ.copy()
    process_env.pop("AUDITHOR_PORT", None)
    process_env.pop("AUDITHOR_HOST", None)
    if env:
        process_env.update(env)
    return subprocess.run(
        [sys.executable, "-m", "audithor", *args],
        capture_output=True,
        text=True,
        env=process_env,
        timeout=20,
    )


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_server(port, process):
    url = f"http://127.0.0.1:{port}/"
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and process.poll() is None:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                return response.status, response.headers
        except (urllib.error.URLError, TimeoutError):
            time.sleep(0.1)
    raise AssertionError(f"server did not respond; output={process.stdout.read()} {process.stderr.read()}")


def start_and_check(port, args=(), env=None):
    process_env = os.environ.copy()
    process_env.pop("AUDITHOR_PORT", None)
    process_env.pop("AUDITHOR_HOST", None)
    if env:
        process_env.update(env)
    process = subprocess.Popen(
        [sys.executable, "-m", "audithor", "--no-browser", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=process_env,
    )
    try:
        status, headers = wait_for_server(port, process)
        assert status == 200
        assert f"http://127.0.0.1:{port}" in headers["Content-Security-Policy"]
    finally:
        process.terminate()
        process.wait(timeout=10)


def test_resolve_bind_precedence_and_defaults():
    class Args:
        host = None
        port = None

    assert resolve_bind(Args(), {}) == ("127.0.0.1", 5001)
    assert resolve_bind(Args(), {"AUDITHOR_HOST": "localhost", "AUDITHOR_PORT": "8123"}) == ("localhost", 8123)
    Args.host = "127.0.0.2"
    Args.port = "8124"
    assert resolve_bind(Args(), {"AUDITHOR_HOST": "localhost", "AUDITHOR_PORT": "8123"}) == ("127.0.0.2", 8124)


def test_version():
    result = run_module("--version")
    assert result.returncode == 0
    assert result.stdout.strip() == f"audithor {__version__}"


def test_help_mentions_bind_options():
    result = run_module("--help")
    assert result.returncode == 0
    assert all(option in result.stdout for option in ("--port", "--host", "--no-browser"))
    assert "no authentication" in result.stdout


def test_invalid_ports_are_rejected():
    for port in ("abc", "0", "70000"):
        result = run_module("--port", port)
        assert result.returncode == 2
        assert "port" in result.stderr.lower()


def test_bound_port_is_rejected():
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        result = run_module("--port", str(sock.getsockname()[1]))
    assert result.returncode == 1
    assert "already in use" in result.stderr


def test_server_starts_with_selected_port():
    port = free_port()
    start_and_check(port, ("--port", str(port)))


def test_environment_port_is_used_without_cli_option():
    port = free_port()
    start_and_check(port, env={"AUDITHOR_PORT": str(port)})


def test_cli_port_overrides_environment_port():
    port = free_port()
    start_and_check(port, ("--port", str(port)), env={"AUDITHOR_PORT": str(free_port())})
