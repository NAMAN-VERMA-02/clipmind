"""clipmind must contain no network code at all."""

import ast
import importlib.metadata as md
import re
import socket
from pathlib import Path

import pytest
from conftest import NetworkBlocked

PKG = Path(__file__).resolve().parents[1] / "src" / "clipmind"

BANNED_MODULES = {
    "socket", "_socket", "ssl", "http", "urllib", "urllib3", "ftplib", "smtplib", "poplib", "imaplib",
    "telnetlib", "xmlrpc", "socketserver", "requests", "httpx", "aiohttp", "websocket", "websockets",
    "grpc", "paramiko", "huggingface_hub", "webbrowser",
}
# ctypes could reach the network through these DLLs without importing anything Python-side.
BANNED_DLLS = re.compile(r"ws2_32|wsock32|winhttp|wininet|urlmon|dnsapi|iphlpapi", re.IGNORECASE)
BANNED_DISTS = {"requests", "urllib3", "httpx", "aiohttp", "huggingface-hub", "websockets", "grpcio"}


def _sources():
    files = sorted(PKG.rglob("*.py"))
    assert files, "package sources not found"
    return files


def test_sockets_are_blocked_in_tests():
    with pytest.raises(NetworkBlocked):
        socket.socket()
    with pytest.raises(NetworkBlocked):
        socket.create_connection(("example.com", 80))
    with pytest.raises(NetworkBlocked):
        socket.getaddrinfo("example.com", 443)


@pytest.mark.parametrize("path", _sources(), ids=lambda p: p.name)
def test_package_imports_no_network_module(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names = [node.module]
        elif isinstance(node, ast.Call) and getattr(node.func, "id", None) == "__import__":
            names = [a.value for a in node.args if isinstance(a, ast.Constant)]
        else:
            continue
        for name in names:
            assert name.split(".")[0] not in BANNED_MODULES, f"{path.name} imports {name}"


@pytest.mark.parametrize("path", _sources(), ids=lambda p: p.name)
def test_package_loads_no_network_dll(path):
    assert not BANNED_DLLS.search(path.read_text(encoding="utf-8")), f"{path.name} names a network DLL"


def _closure(dist: str, seen: set[str]) -> set[str]:
    key = dist.lower().replace("_", "-")
    if key in seen:
        return seen
    seen.add(key)
    for req in md.requires(dist) or []:
        if "extra ==" in req:
            continue
        name = re.split(r"[\s;<>=!~\[(]", req, maxsplit=1)[0]
        try:
            _closure(name, seen)
        except md.PackageNotFoundError:  # optional platform-specific dep not installed here
            pass
    return seen


def test_runtime_dependency_closure_has_no_http_client():
    closure = _closure("clipmind", set())
    assert not closure & BANNED_DISTS, f"runtime deps pull in {closure & BANNED_DISTS}"
