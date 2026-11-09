"""Every test runs with networking disabled.

The block is installed at import time, before test collection imports clipmind,
so a module that grabs `socket.socket` at import still gets the blocked one.
"""

import _socket
import socket


class NetworkBlocked(RuntimeError):
    pass


def _blocked(*_args, **_kwargs):
    raise NetworkBlocked("clipmind tests run with networking disabled")


class _BlockedSocket:
    def __init__(self, *_args, **_kwargs):
        _blocked()


for _mod in (socket, _socket):
    _mod.socket = _BlockedSocket
socket.create_connection = _blocked
socket.getaddrinfo = _blocked
_socket.getaddrinfo = _blocked
socket.socketpair = _blocked
