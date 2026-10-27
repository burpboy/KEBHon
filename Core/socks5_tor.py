#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
socks5_tor.py
Multi-Hop SOCKS4/5 & Tor Circuit Router / Proxy Chain Manager

Python 3.9+ | Zero external dependencies (stdlib only)

Fitur:
- SOCKS4, SOCKS4a, SOCKS5 (no-auth & user/pass) client handshake
- Multi-hop proxy chaining (SOCKS4/5 + Tor SOCKS5)
- Tor circuit rotation via NEWNYM (ControlPort) - optional
- HTTP CONNECT tunnel server (agar chain bisa dipakai browser/tool)
- Async server (asyncio) + thread-safe sync helper
- Robust error handling, timeouts, graceful shutdown

Catatan:
- Untuk Tor NEWNYM, set TOR_CONTROL_PORT & TOR_CONTROL_PASSWORD (jika ada).
- Jalankan: python socks5_tor.py --listen 127.0.0.1:9050 --chain ...
- Contoh chain: --chain socks5://127.0.0.1:9050 --chain socks5://user:pass@host:port
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import logging
import signal
import struct
import sys
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple
from urllib.parse import unquote, urlparse

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG = logging.getLogger("socks5_tor")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class ProxyError(Exception):
    """Base error untuk semua kegagalan proxy."""


class ProxyHandshakeError(ProxyError):
    """Handshake proxy gagal."""


class ProxyAuthError(ProxyError):
    """Autentikasi proxy gagal."""


class ProxyTimeout(ProxyError):
    """Timeout saat koneksi/handshake."""


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------
async def _read_exact(reader: asyncio.StreamReader, n: int, timeout: float) -> bytes:
    try:
        return await asyncio.wait_for(reader.readexactly(n), timeout=timeout)
    except asyncio.IncompleteReadError as e:
        raise ProxyHandshakeError(
            f"Koneksi terputus (butuh {n} byte, dapat {len(e.partial)})"
        ) from e
    except asyncio.TimeoutError as e:
        raise ProxyTimeout(f"Timeout membaca {n} byte") from e


async def _open_connection(
    host: str, port: int, timeout: float
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    try:
        return await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except asyncio.TimeoutError as e:
        raise ProxyTimeout(f"Timeout koneksi ke {host}:{port}") from e
    except OSError as e:
        raise ProxyError(f"Gagal koneksi ke {host}:{port}: {e}") from e


# ---------------------------------------------------------------------------
# Proxy descriptor
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ProxyEndpoint:
    scheme: str  # "socks4", "socks4a", "socks5"
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None

    @classmethod
    def parse(cls, url: str) -> "ProxyEndpoint":
        p = urlparse(url if "://" in url else f"socks5://{url}")
        scheme = (p.scheme or "socks5").lower()
        if scheme == "socks5h":
            scheme = "socks5"
        if scheme not in ("socks4", "socks4a", "socks5"):
            raise ValueError(f"Skema proxy tidak didukung: {scheme}")
        if not p.hostname or not p.port:
            raise ValueError(f"Proxy URL tidak valid: {url}")
        return cls(
            scheme=scheme,
            host=p.hostname,
            port=int(p.port),
            username=unquote(p.username) if p.username else None,
            password=unquote(p.password) if p.password else None,
        )

    def __str__(self) -> str:
        auth = f"{self.username}@" if self.username else ""
        return f"{self.scheme}://{auth}{self.host}:{self.port}"


# ---------------------------------------------------------------------------
# SOCKS handshakes
# ---------------------------------------------------------------------------
async def _socks5_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    dest_host: str,
    dest_port: int,
    username: Optional[str],
    password: Optional[str],
    timeout: float,
) -> None:
    # Method negotiation
    methods = b"\x00"  # no-auth
    if username is not None:
        methods = b"\x00\x02"  # no-auth + user/pass
    writer.write(b"\x05" + bytes([len(methods)]) + methods)
    await writer.drain()

    ver_method = await _read_exact(reader, 2, timeout)
    if ver_method[0] != 0x05:
        raise ProxyHandshakeError(f"SOCKS5 versi tidak valid: {ver_method[0]}")
    method = ver_method[1]
    if method == 0xFF:
        raise ProxyAuthError("SOCKS5: tidak ada metode auth yang diterima server")
    if method == 0x02:
        if username is None:
            raise ProxyAuthError("SOCKS5: server butuh auth tapi tidak ada kredensial")
        u = username.encode()
        p = (password or "").encode()
        if len(u) > 255 or len(p) > 255:
            raise ProxyAuthError("SOCKS5: kredensial terlalu panjang")
        writer.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        await writer.drain()
        auth_resp = await _read_exact(reader, 2, timeout)
        if auth_resp[1] != 0x00:
            raise ProxyAuthError("SOCKS5: autentikasi user/pass ditolak")
    elif method != 0x00:
        raise ProxyHandshakeError(f"SOCKS5: metode auth tidak dikenal: {method}")

    # Address
    try:
        ip = ipaddress.ip_address(dest_host)
        if ip.version == 4:
            addr = b"\x01" + ip.packed
        else:
            addr = b"\x04" + ip.packed
    except ValueError:
        host_b = dest_host.encode("idna")
        if len(host_b) > 255:
            raise ProxyHandshakeError("SOCKS5: hostname terlalu panjang")
        addr = b"\x03" + bytes([len(host_b)]) + host_b

    writer.write(b"\x05\x01\x00" + addr + struct.pack("!H", dest_port))
    await writer.drain()

    resp = await _read_exact(reader, 4, timeout)
    if resp[0] != 0x05:
        raise ProxyHandshakeError(f"SOCKS5 reply versi tidak valid: {resp[0]}")
    rep = resp[1]
    if rep != 0x00:
        errors = {
            0x01: "general failure",
            0x02: "connection not allowed",
            0x03: "network unreachable",
            0x04: "host unreachable",
            0x05: "connection refused",
            0x06: "TTL expired",
            0x07: "command not supported",
            0x08: "address type not supported",
        }
        raise ProxyError(f"SOCKS5 CONNECT gagal: {errors.get(rep, hex(rep))}")

    atyp = resp[3]
    if atyp == 0x01:
        await _read_exact(reader, 4 + 2, timeout)
    elif atyp == 0x04:
        await _read_exact(reader, 16 + 2, timeout)
    elif atyp == 0x03:
        ln = await _read_exact(reader, 1, timeout)
        await _read_exact(reader, ln[0] + 2, timeout)
    else:
        raise ProxyHandshakeError(f"SOCKS5: atyp tidak valid: {atyp}")


async def _socks4_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    dest_host: str,
    dest_port: int,
    userid: str,
    socks4a: bool,
    timeout: float,
) -> None:
    userid_b = userid.encode() if userid else b""
    try:
        ip = ipaddress.IPv4Address(dest_host)
        is_ip = True
    except (ipaddress.AddressValueError, ValueError):
        is_ip = False

    if is_ip:
        addr = ip.packed
        tail = b"\x00"
    else:
        if not socks4a:
            raise ProxyHandshakeError(
                "SOCKS4 tidak mendukung hostname; gunakan socks4a atau berikan IP"
            )
        addr = b"\x00\x00\x00\x01"
        tail = dest_host.encode("idna") + b"\x00"

    req = b"\x04\x01" + struct.pack("!H", dest_port) + addr + userid_b + b"\x00" + tail
    writer.write(req)
    await writer.drain()

    resp = await _read_exact(reader, 8, timeout)
    if resp[0] not in (0x00, 0x04):
        raise ProxyHandshakeError(f"SOCKS4 reply versi tidak valid: {resp[0]}")
    if resp[1] != 0x5A:
        raise ProxyError(f"SOCKS4 CONNECT gagal: kode {resp[1]:#x}")


async def _negotiate(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    endpoint: ProxyEndpoint,
    dest_host: str,
    dest_port: int,
    timeout: float,
) -> None:
    if endpoint.scheme == "socks5":
        await _socks5_handshake(
            reader, writer, dest_host, dest_port,
            endpoint.username, endpoint.password, timeout,
        )
    elif endpoint.scheme in ("socks4", "socks4a"):
        await _socks4_handshake(
            reader, writer, dest_host, dest_port,
            endpoint.username or "", endpoint.scheme == "socks4a", timeout,
        )
    else:
        raise ProxyError(f"Skema tidak didukung: {endpoint.scheme}")


# ---------------------------------------------------------------------------
# Proxy chain
# ---------------------------------------------------------------------------
class ProxyChain:
    """
    Rantai proxy. Chain: [P1, P2, ..., Pn] -> destination
    Koneksi: kita -> P1 (SOCKS handshake ke P2) -> P2 (SOCKS handshake ke P3)
             -> ... -> Pn (SOCKS handshake ke dest)
    """

    def __init__(self, endpoints: List[ProxyEndpoint], connect_timeout: float = 15.0):
        if not endpoints:
            raise ValueError("Chain tidak boleh kosong")
        self.endpoints = list(endpoints)
        self.connect_timeout = connect_timeout

    async def open(
        self, dest_host: str, dest_port: int
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        first = self.endpoints[0]
        reader, writer = await _open_connection(
            first.host, first.port, self.connect_timeout
        )
        try:
            for idx, endpoint in enumerate(self.endpoints):
                if idx + 1 < len(self.endpoints):
                    target_host = self.endpoints[idx + 1].host
                    target_port = self.endpoints[idx + 1].port
                else:
                    target_host, target_port = dest_host, dest_port

                await _negotiate(
                    reader, writer, endpoint,
                    target_host, target_port, self.connect_timeout,
                )
            return reader, writer
        except BaseException:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()
            raise


# ---------------------------------------------------------------------------
# Tor Controller (NEWNYM)
# ---------------------------------------------------------------------------
class TorController:
    """Minimal Tor control client untuk rotate circuit (NEWNYM)."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9051,
        password: Optional[str] = None,
        timeout: float = 5.0,
    ):
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self._lock = asyncio.Lock()

    async def _cmd(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        cmd: str,
        expect_prefix: str,
    ) -> str:
        writer.write((cmd + "\r\n").encode())
        await writer.drain()
        deadline = time.monotonic() + self.timeout
        buf = ""
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProxyTimeout("Tor control timeout")
            chunk = await asyncio.wait_for(reader.read(4096), timeout=remaining)
            if not chunk:
                raise ProxyHandshakeError("Tor control closed")
            buf += chunk.decode("ascii", errors="replace")
            lines = buf.split("\r\n")
            for line in lines[:-1]:
                if line.startswith(expect_prefix):
                    return line
            if lines[-1].startswith(expect_prefix) and lines[-1].endswith(("OK", "ok")):
                return lines[-1]

    async def new_identity(self) -> None:
        async with self._lock:
            reader, writer = await _open_connection(
                self.host, self.port, self.timeout
            )
            try:
                await self._cmd(reader, writer, "PROTOCOLINFO 1", "250")
                if self.password:
                    await self._cmd(
                        reader, writer, f'AUTHENTICATE "{self.password}"', "250"
                    )
                else:
                    await self._cmd(reader, writer, "AUTHENTICATE", "250")
                await self._cmd(reader, writer, "SIGNAL NEWNYM", "250")
            finally:
                with contextlib.suppress(Exception):
                    writer.close()
                    await writer.wait_closed()


# ---------------------------------------------------------------------------
# HTTP CONNECT server
# ---------------------------------------------------------------------------
class HttpConnectServer:
    """Server HTTP CONNECT sederhana yang meneruskan lewat ProxyChain."""

    def __init__(self, chain: ProxyChain, listen_host: str, listen_port: int):
        self.chain = chain
        self.listen_host = listen_host
        self.listen_port = listen_port
        self._server: Optional[asyncio.AbstractServer] = None

    async def _handle_client(
        self, creader: asyncio.StreamReader, cwriter: asyncio.StreamWriter
    ) -> None:
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = await asyncio.wait_for(creader.read(4096), timeout=15)
                if not chunk:
                    return
                data += chunk
                if len(data) > 16384:
                    cwriter.write(
                        b"HTTP/1.1 431 Request Header Fields Too Large\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await cwriter.drain()
                    return

            head, _, _ = data.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            if not lines or not lines[0]:
                return
            parts = lines[0].split(" ")
            if len(parts) < 2:
                return
            method, target = parts[0], parts[1]
            if method.upper() != "CONNECT":
                cwriter.write(
                    b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"
                )
                await cwriter.drain()
                return
            host, _, port_s = target.rpartition(":")
            if not host or not port_s.isdigit():
                cwriter.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                await cwriter.drain()
                return
            port = int(port_s)

            try:
                rreader, rwriter = await self.chain.open(host, port)
            except ProxyError as e:
                LOG.warning("Chain gagal %s:%d: %s", host, port, e)
                cwriter.write(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
                )
                await cwriter.drain()
                return

            cwriter.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await cwriter.drain()

            await self._pipe(cwriter, rreader, rwriter, creader)

        except (asyncio.TimeoutError, ConnectionError, ProxyError):
            pass
        except Exception as e:  # noqa: BLE001
            LOG.exception("Handler error: %s", e)
        finally:
            with contextlib.suppress(Exception):
                cwriter.close()
                await cwriter.wait_closed()

    @staticmethod
    async def _pipe(
        cwriter: asyncio.StreamWriter,
        rreader: asyncio.StreamReader,
        rwriter: asyncio.StreamWriter,
        creader: asyncio.StreamReader,
    ) -> None:
        async def _c2r() -> None:
            try:
                while True:
                    chunk = await creader.read(65536)
                    if not chunk:
                        break
                    rwriter.write(chunk)
                    await rwriter.drain()
            except (ConnectionError, asyncio.CancelledError, OSError):
                pass
            finally:
                with contextlib.suppress(Exception):
                    rwriter.close()

        async def _r2c() -> None:
            try:
                while True:
                    chunk = await rreader.read(65536)
                    if not chunk:
                        break
                    cwriter.write(chunk)
                    await cwriter.drain()
            except (ConnectionError, asyncio.CancelledError, OSError):
                pass
            finally:
                with contextlib.suppress(Exception):
                    cwriter.close()

        t1 = asyncio.create_task(_c2r())
        t2 = asyncio.create_task(_r2c())
        try:
            await asyncio.gather(t1, t2)
        finally:
            for t in (t1, t2):
                if not t.done():
                    t.cancel()
            with contextlib.suppress(Exception):
                await asyncio.gather(t1, t2, return_exceptions=True)

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client,
            self.listen_host,
            self.listen_port,
            reuse_address=True,
        )
        LOG.info(
            "HTTP CONNECT listening on %s:%d", self.listen_host, self.listen_port
        )

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None


# ---------------------------------------------------------------------------
# High-level entry point
# ---------------------------------------------------------------------------
@dataclass
class RouterConfig:
    listen_host: str
    listen_port: int
    chain_urls: List[str]
    connect_timeout: float = 15.0
    tor_control_host: Optional[str] = None
    tor_control_port: int = 9051
    tor_control_password: Optional[str] = None
    rotate_interval: Optional[float] = None  # detik; None = tidak rotate

    def build_chain(self) -> ProxyChain:
        eps = [ProxyEndpoint.parse(u) for u in self.chain_urls]
        return ProxyChain(eps, connect_timeout=self.connect_timeout)


async def _run_router(cfg: RouterConfig) -> None:
    chain = cfg.build_chain()
    LOG.info("Chain: %s", " -> ".join(str(e) for e in chain.endpoints))

    tor: Optional[TorController] = None
    if cfg.tor_control_host and cfg.rotate_interval:
        tor = TorController(
            host=cfg.tor_control_host,
            port=cfg.tor_control_port,
            password=cfg.tor_control_password,
        )

    server = HttpConnectServer(chain, cfg.listen_host, cfg.listen_port)
    await server.start()

    stop = asyncio.Event()

    async def _rotator() -> None:
        assert tor is not None
        assert cfg.rotate_interval is not None
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=cfg.rotate_interval)
                return
            except asyncio.TimeoutError:
                pass
            try:
                await tor.new_identity()
                LOG.info("Tor: NEWNYM terkirim (circuit baru)")
            except Exception as e:  # noqa: BLE001
                LOG.warning("Gagal rotate Tor: %s", e)

    rotator_task: Optional[asyncio.Task] = None
    if tor is not None and cfg.rotate_interval:
        rotator_task = asyncio.create_task(_rotator())

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(sig, stop.set)

    try:
        await stop.wait()
    finally:
        LOG.info("Shutdown...")
        if rotator_task is not None:
            rotator_task.cancel()
            with contextlib.suppress(Exception):
                await rotator_task
        await server.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _parse_args(argv: Optional[Iterable[str]] = None) -> RouterConfig:
    p = argparse.ArgumentParser(
        prog="socks5_tor.py",
        description="Multi-Hop SOCKS4/5 & Tor Circuit Router / Proxy Chain Manager",
    )
    p.add_argument(
        "--listen",
        default="127.0.0.1:9050",
        help="Alamat listen HTTP CONNECT (default: 127.0.0.1:9050)",
    )
    p.add_argument(
        "--chain",
        action="append",
        default=[],
        help="Proxy hop (boleh diulang). Contoh: socks5://user:pass@host:1080",
    )
    p.add_argument("--connect-timeout", type=float, default=15.0)
    p.add_argument(
        "--tor-control",
        default=None,
        help="HOST:PORT Tor control (mis. 127.0.0.1:9051)",
    )
    p.add_argument("--tor-password", default=None)
    p.add_argument(
        "--rotate",
        type=float,
        default=None,
        help="Interval detik untuk NEWNYM (butuh --tor-control)",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(list(argv) if argv is not None else None)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    lh, _, lp = args.listen.rpartition(":")
    if not lh or not lp.isdigit():
        p.error("--listen harus format HOST:PORT")
    if not args.chain:
        p.error("Minimal satu --chain diperlukan")

    tor_host: Optional[str] = None
    tor_port: int = 9051
    if args.tor_control:
        th, _, tp = args.tor_control.rpartition(":")
        if not th or not tp.isdigit():
            p.error("--tor-control harus format HOST:PORT")
        tor_host, tor_port = th, int(tp)

    return RouterConfig(
        listen_host=lh,
        listen_port=int(lp),
        chain_urls=args.chain,
        connect_timeout=args.connect_timeout,
        tor_control_host=tor_host,
        tor_control_port=tor_port,
        tor_control_password=args.tor_password,
        rotate_interval=args.rotate,
    )


def main(argv: Optional[Iterable[str]] = None) -> int:
    try:
        cfg = _parse_args(argv)
    except SystemExit as e:
        return int(e.code or 0)
    try:
        asyncio.run(_run_router(cfg))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())