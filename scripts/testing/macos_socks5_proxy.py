#!/usr/bin/env python3
"""Minimal no-auth SOCKS5 relay for an isolated macOS acceptance VM."""

import asyncio
import ipaddress
import os
import struct
import sys

TEST_DOMAIN = os.environ.get("TUNBRIDGE_TEST_DOMAIN", "").lower()
TEST_TARGET_HOST = os.environ.get("TUNBRIDGE_TEST_TARGET_HOST", "")


async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        version, method_count = await reader.readexactly(2)
        methods = await reader.readexactly(method_count)
        if version != 5 or 0 not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            return
        writer.write(b"\x05\x00")
        await writer.drain()
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
        connect_host = TEST_TARGET_HOST if TEST_DOMAIN and host.lower() == TEST_DOMAIN else host
        print(f"socks5=connect host={host} target={connect_host}:{port}", flush=True)
        try:
            remote_reader, remote_writer = await asyncio.open_connection(connect_host, port)
        except (OSError, asyncio.TimeoutError) as error:
            print(f"socks5=connect_error type={type(error).__name__} detail={error}", flush=True)
            writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return
        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()

        async def copy(source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
            transferred = 0
            try:
                while data := await source.read(65536):
                    transferred += len(data)
                    destination.write(data)
                    await destination.drain()
            finally:
                print(f"socks5=relay_closed bytes={transferred}", flush=True)
                destination.close()

        await asyncio.gather(
            copy(reader, remote_writer),
            copy(remote_reader, writer),
            return_exceptions=True,
        )
    except (asyncio.IncompleteReadError, ConnectionError, OSError, UnicodeError):
        pass
    finally:
        writer.close()


async def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: macos_socks5_proxy.py <port>")
    port = int(sys.argv[1])
    if not 1024 <= port <= 65535:
        raise SystemExit("port must be between 1024 and 65535")
    server = await asyncio.start_server(relay, "127.0.0.1", port)
    mapping = f" mapping={TEST_DOMAIN}->{TEST_TARGET_HOST}" if TEST_DOMAIN else ""
    print(f"socks5=ready pid={os.getpid()} port={port}{mapping}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
