#!/usr/bin/env python3
"""OpenSSH ProxyCommand: encrypted SSH bytes through Guard; no credential logs."""
import os
import selectors
import socket
import sys

host, port = sys.argv[1:]
if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:" for c in host):
    raise SystemExit(1)
with socket.create_connection(("127.0.0.1", int(os.environ["CLAUDE_GUARD_PROXY_PORT"])), 5) as sock:
    sock.sendall(f"CONNECT {host}:{int(port)} HTTP/1.1\r\nHost: {host}:{int(port)}\r\n\r\n".encode())
    header = bytearray()
    while not header.endswith(b"\r\n\r\n"):
        part = sock.recv(1)
        if not part or len(header) > 65536:
            raise SystemExit(1)
        header.extend(part)
    if bytes(header).split(b" ")[1:2] != [b"200"]:
        raise SystemExit(1)
    sock.settimeout(None)
    # SelectSelector supports pipe-backed stdin on macOS.
    with selectors.SelectSelector() as sel:
        sel.register(sock, selectors.EVENT_READ)
        sel.register(sys.stdin.buffer, selectors.EVENT_READ)
        while True:
            for key, _ in sel.select():
                if key.fileobj is sock:
                    data = sock.recv(65536)
                    if not data:
                        raise SystemExit(0)
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                else:
                    data = os.read(sys.stdin.fileno(), 65536)
                    if not data:
                        sock.shutdown(socket.SHUT_WR)
                        sel.unregister(sys.stdin.buffer)
                    else:
                        sock.sendall(data)
