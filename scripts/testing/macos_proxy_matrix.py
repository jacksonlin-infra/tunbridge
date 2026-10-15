#!/usr/bin/env python3
"""Small HTTP/SOCKS5 proxy fixture for the isolated macOS acceptance VM.

It deliberately supports only CONNECT and bounded username/password checks.
The fixture is not a production proxy; it exists to exercise the shared
TunBridge upstream contract without introducing a third-party dependency.
"""

import asyncio
import base64
import ipaddress
import os
import struct
import sys
from typing import Optional
from urllib.parse import urlsplit

TEST_DOMAIN = os.environ.get("TUNBRIDGE_TEST_DOMAIN", "").lower()
TEST_TARGET_HOST = os.environ.get("TUNBRIDGE_TEST_TARGET_HOST", "")
EXPECTED_USERNAME = os.environ.get("TUNBRIDGE_PROXY_USERNAME")
EXPECTED_PASSWORD = os.environ.get("TUNBRIDGE_PROXY_PASSWORD")


def target_for(host: str) -> str:
    if TEST_DOMAIN and host.lower() == TEST_DOMAIN:
        return TEST_TARGET_HOST
    return host


def credentials_valid(value: Optional[str]) -> bool:
    if EXPECTED_USERNAME is None and EXPECTED_PASSWORD is None:
        return value is None
    if not value or not value.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(value[6:], validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return False
    return decoded == f"{EXPECTED_USERNAME}:{EXPECTED_PASSWORD}"


async def copy_stream(
    source: asyncio.StreamReader,
    destination: asyncio.StreamWriter,
    label: str,
) -> None:
    transferred = 0
    try:
        while data := await source.read(65536):
            transferred += len(data)
            destination.write(data)
            await destination.drain()
    finally:
        print(f"proxy=relay_closed side={label} bytes={transferred}", flush=True)
        destination.close()


async def tunnel(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    port: int,
) -> None:
    connect_host = target_for(host)
    print(f"proxy=connect host={host} target={connect_host}:{port}", flush=True)
    try:
        remote_reader, remote_writer = await asyncio.open_connection(connect_host, port)
    except (OSError, asyncio.TimeoutError) as error:
        print(f"proxy=connect_error type={type(error).__name__} detail={error}", flush=True)
        writer.close()
        return
    await asyncio.gather(
        copy_stream(reader, remote_writer, "upstream"),
        copy_stream(remote_reader, writer, "downstream"),
        return_exceptions=True,
    )


async def socks5(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    try:
        version, count = await reader.readexactly(2)
        methods = await reader.readexactly(count)
        if version != 5:
            return
        method = 2 if EXPECTED_USERNAME is not None else 0
        if method not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            return
        writer.write(bytes((5, method)))
        await writer.drain()
        if method == 2:
            auth_version, username_length = await reader.readexactly(2)
            username = await reader.readexactly(username_length)
            password_length = (await reader.readexactly(1))[0]
            password = await reader.readexactly(password_length)
            valid = (
                auth_version == 1
                and EXPECTED_USERNAME is not None
                and EXPECTED_PASSWORD is not None
                and username.decode("utf-8", "replace") == EXPECTED_USERNAME
                and password.decode("utf-8", "replace") == EXPECTED_PASSWORD
            )
            writer.write(b"\x01\x00" if valid else b"\x01\x01")
            await writer.drain()
            if not valid:
                return
        version, command, reserved, address_type = await reader.readexactly(4)
        if version != 5 or command != 1 or reserved != 0:
            return
        if address_type == 1:
            host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
        elif address_type == 3:
            length = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(length)).decode("ascii")
        elif address_type == 4:
            host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
        else:
            return
        port = struct.unpack("!H", await reader.readexactly(2))[0]
        connect_host = target_for(host)
        print(f"proxy=socks5_connect host={host} target={connect_host}:{port}", flush=True)
        try:
            remote_reader, remote_writer = await asyncio.open_connection(connect_host, port)
        except (OSError, asyncio.TimeoutError) as error:
            print(f"proxy=connect_error type={type(error).__name__} detail={error}", flush=True)
            writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return
        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        await asyncio.gather(
            copy_stream(reader, remote_writer, "upstream"),
            copy_stream(remote_reader, writer, "downstream"),
            return_exceptions=True,
        )
    except (asyncio.IncompleteReadError, ConnectionError, OSError, UnicodeError):
        pass
    finally:
        writer.close()


async def http_connect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    try:
        request = await reader.readuntil(b"\r\n\r\n")
        if len(request) > 32 * 1024:
            return
        lines = request.decode("iso-8859-1").split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            if not line:
                continue
            key, value = line.split(":", 1)
            headers[key.lower()] = value.strip()
        if not credentials_valid(headers.get("proxy-authorization")):
            writer.write(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b"Proxy-Authenticate: Basic realm=TunBridge\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
            await writer.drain()
            return
        if method.upper() != "CONNECT":
            parsed = urlsplit(target)
            host = parsed.hostname or headers.get("host", "")
            port = parsed.port or 80
        else:
            host, port_text = target.rsplit(":", 1)
            port = int(port_text)
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await tunnel(reader, writer, host, port)
    except (asyncio.IncompleteReadError, ConnectionError, OSError, ValueError):
        pass
    finally:
        writer.close()


async def main() -> None:
    if len(sys.argv) != 3 or sys.argv[1] not in {"http", "socks5"}:
        raise SystemExit("usage: macos_proxy_matrix.py <http|socks5> <port>")
    kind, port_text = sys.argv[1:]
    port = int(port_text)
    if not 1024 <= port <= 65535:
        raise SystemExit("port must be between 1024 and 65535")
    handler = http_connect if kind == "http" else socks5
    server = await asyncio.start_server(handler, "127.0.0.1", port)
    auth = "auth" if EXPECTED_USERNAME is not None else "no-auth"
    print(f"proxy=ready kind={kind} auth={auth} pid={os.getpid()} port={port}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
