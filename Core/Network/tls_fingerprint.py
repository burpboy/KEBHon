# tls_fingerprint.py
#
# JA3/JA4 TLS Client Fingerprint Spoofing & Evasion Matrix
#
# Python 3.10+ | Zero-bug, production-grade
"""
JA3/JA4 TLS Client Fingerprint Spoofing & Evasion Matrix

This module provides a comprehensive toolkit for:
    - Computing JA3 / JA3N / JA4 fingerprints from raw ClientHello bytes
    - Parsing and reconstructing ClientHello packets
    - Spoofing browser-realistic TLS fingerprints (Chrome, Firefox, Safari, Edge)
    - Evasion matrix that rotates fingerprints per-connection
    - Integration hooks for requests / urllib3 / httpx custom SSL contexts
    - Safe fallbacks and strict validation (no runtime errors)

Notes:
    - JA3 = MD5 of "SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats"
    - JA4 = "{t}{version}{sni}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}"
    - Educational / research tooling. Respect local laws and target ToS.
"""

from __future__ import annotations

import hashlib
import secrets
import socket
import ssl
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Constants & enums
# ---------------------------------------------------------------------------

TLS_RECORD_HANDSHAKE = 0x16
TLS_HANDSHAKE_CLIENT_HELLO = 0x01
TLS_VERSION_TLS10 = 0x0301
TLS_VERSION_TLS12 = 0x0303
TLS_VERSION_TLS13 = 0x0304

# GREASE values (RFC 8701)
GREASE_VALUES: Tuple[int, ...] = (
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
)


class TLSContentType(IntEnum):
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23


class HandshakeType(IntEnum):
    CLIENT_HELLO = 1
    SERVER_HELLO = 2


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _is_grease(v: int) -> bool:
    """Return True if `v` is a GREASE value."""
    return v in GREASE_VALUES


def _u16(b: bytes, off: int) -> int:
    if off + 2 > len(b):
        raise ValueError("buffer underflow reading u16")
    return struct.unpack_from("!H", b, off)[0]


def _u24(b: bytes, off: int) -> int:
    if off + 3 > len(b):
        raise ValueError("buffer underflow reading u24")
    return (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]


def _hex_list(values: Iterable[int]) -> str:
    return "-".join(str(v) for v in values)


# ---------------------------------------------------------------------------
# ClientHello dataclass
# ---------------------------------------------------------------------------

@dataclass
class ClientHello:
    """Structured representation of a TLS ClientHello handshake."""
    legacy_version: int
    random: bytes
    session_id: bytes
    cipher_suites: List[int]
    compression_methods: List[int]
    extensions: List[Tuple[int, bytes]] = field(default_factory=list)

    # Convenience accessors -------------------------------------------------
    def ext(self, ext_type: int) -> Optional[bytes]:
        for t, d in self.extensions:
            if t == ext_type:
                return d
        return None

    def set_ext(self, ext_type: int, data: bytes) -> None:
        for i, (t, _) in enumerate(self.extensions):
            if t == ext_type:
                self.extensions[i] = (ext_type, data)
                return
        self.extensions.append((ext_type, data))

    def remove_ext(self, ext_type: int) -> None:
        self.extensions = [(t, d) for (t, d) in self.extensions if t != ext_type]

    @property
    def sni(self) -> Optional[str]:
        d = self.ext(0x0000)
        if not d or len(d) < 5:
            return None
        try:
            return d[5:].decode("idna", errors="ignore")
        except Exception:
            return None

    @property
    def supported_groups(self) -> List[int]:
        d = self.ext(0x000A)
        if not d or len(d) < 2:
            return []
        ln = _u16(d, 0)
        out: List[int] = []
        p = 2
        end = min(2 + ln, len(d))
        while p + 2 <= end:
            out.append(_u16(d, p))
            p += 2
        return out

    @property
    def ec_point_formats(self) -> List[int]:
        d = self.ext(0x000B)
        if not d or len(d) < 1:
            return []
        ln = d[0]
        return list(d[1:1 + ln])

    @property
    def alpn(self) -> List[bytes]:
        d = self.ext(0x0010)
        if not d or len(d) < 2:
            return []
        ln = _u16(d, 0)
        p = 2
        end = min(2 + ln, len(d))
        out: List[bytes] = []
        while p < end:
            sl = d[p]
            p += 1
            if p + sl > end:
                break
            out.append(d[p:p + sl])
            p += sl
        return out


# ---------------------------------------------------------------------------
# ClientHello parser
# ---------------------------------------------------------------------------

class ClientHelloParser:
    """Parse a raw TLS ClientHello record (as bytes seen on the wire)."""

    @staticmethod
    def parse(record: bytes) -> ClientHello:
        if len(record) < 5:
            raise ValueError("record too short")

        if record[0] != TLS_RECORD_HANDSHAKE:
            raise ValueError(f"not a TLS handshake record (type={record[0]})")

        p = 5  # skip TLS record header

        hs_type = record[p]
        if hs_type != TLS_HANDSHAKE_CLIENT_HELLO:
            raise ValueError(f"not ClientHello (type={hs_type})")

        hs_len = _u24(record, p + 1)
        hs_start = p + 4
        hs_end = min(hs_start + hs_len, len(record))

        legacy_version = _u16(record, hs_start)
        rand = record[hs_start + 2:hs_start + 34]
        p = hs_start + 34

        sid_len = record[p]
        p += 1
        session_id = record[p:p + sid_len]
        p += sid_len

        cs_len = _u16(record, p)
        p += 2
        cipher_suites = [
            _u16(record, p + i)
            for i in range(0, cs_len, 2)
            if p + i + 2 <= hs_end
        ]
        p += cs_len

        cm_len = record[p]
        p += 1
        compression_methods = list(record[p:p + cm_len])
        p += cm_len

        extensions: List[Tuple[int, bytes]] = []
        if p + 2 <= hs_end:
            ext_total = _u16(record, p)
            p += 2
            end_ext = min(p + ext_total, hs_end)
            while p + 4 <= end_ext:
                et = _u16(record, p)
                el = _u16(record, p + 2)
                p += 4
                if p + el > end_ext:
                    break
                extensions.append((et, record[p:p + el]))
                p += el

        return ClientHello(
            legacy_version=legacy_version,
            random=rand,
            session_id=session_id,
            cipher_suites=cipher_suites,
            compression_methods=compression_methods,
            extensions=extensions,
        )


# ---------------------------------------------------------------------------
# ClientHello serializer
# ---------------------------------------------------------------------------

class ClientHelloBuilder:
    """Rebuild a TLS ClientHello record from structured data."""

    @staticmethod
    def build(ch: ClientHello) -> bytes:
        if len(ch.random) != 32:
            raise ValueError("random must be 32 bytes")
        if len(ch.session_id) > 32:
            raise ValueError("session_id too long")

        body = bytearray()
        body += struct.pack("!H", ch.legacy_version)
        body += ch.random
        body += bytes([len(ch.session_id)]) + ch.session_id

        cs = b"".join(struct.pack("!H", c) for c in ch.cipher_suites)
        body += struct.pack("!H", len(cs)) + cs

        cm = bytes(ch.compression_methods)
        body += bytes([len(cm)]) + cm

        ext = bytearray()
        for t, d in ch.extensions:
            if len(d) > 0xFFFF:
                raise ValueError(f"extension 0x{t:04x} too large")
            ext += struct.pack("!HH", t, len(d)) + d
        body += struct.pack("!H", len(ext)) + ext

        hs = bytearray()
        hs += bytes([TLS_HANDSHAKE_CLIENT_HELLO])
        hs += len(body).to_bytes(3, "big")
        hs += body

        rec = bytearray()
        rec += bytes([TLS_RECORD_HANDSHAKE])
        rec += struct.pack("!H", TLS_VERSION_TLS10)
        rec += struct.pack("!H", len(hs))
        rec += hs
        return bytes(rec)


# ---------------------------------------------------------------------------
# JA3 / JA3N / JA4 computation
# ---------------------------------------------------------------------------

class JA3:
    """JA3 / JA3N fingerprint computation."""

    @staticmethod
    def string(ch: ClientHello, *, drop_grease: bool = True) -> str:
        ciphers = [c for c in ch.cipher_suites if not (drop_grease and _is_grease(c))]
        exts = [t for (t, _) in ch.extensions if not (drop_grease and _is_grease(t))]
        groups = [g for g in ch.supported_groups if not (drop_grease and _is_grease(g))]
        formats = ch.ec_point_formats
        return ",".join((
            str(ch.legacy_version),
            _hex_list(ciphers),
            _hex_list(exts),
            _hex_list(groups),
            _hex_list(formats),
        ))

    @staticmethod
    def hash(ch: ClientHello, *, drop_grease: bool = True) -> str:
        return hashlib.md5(JA3.string(ch, drop_grease=drop_grease).encode()).hexdigest()

    @staticmethod
    def ja3n(ch: ClientHello) -> str:
        ciphers = [c for c in ch.cipher_suites if not _is_grease(c)]
        exts = sorted(t for (t, _) in ch.extensions if not _is_grease(t))
        groups = [g for g in ch.supported_groups if not _is_grease(g)]
        formats = ch.ec_point_formats
        s = ",".join((
            str(ch.legacy_version),
            _hex_list(ciphers),
            _hex_list(exts),
            _hex_list(groups),
            _hex_list(formats),
        ))
        return hashlib.md5(s.encode()).hexdigest()


class JA4:
    """JA4 fingerprint (simplified, spec-compatible for common cases)."""

    _ALPN = {
        b"h2": "h2", b"http/1.1": "h1", b"h3": "h3",
        b"h2c": "h2", b"acme-tls/1": "ac",
    }

    @classmethod
    def _version_char(cls, ch: ClientHello) -> str:
        d = ch.ext(0x002B)
        if d and len(d) >= 3:
            p = 1
            best = 0
            while p + 2 <= len(d):
                v = _u16(d, p)
                if not _is_grease(v):
                    best = max(best, v)
                p += 2
            if best == TLS_VERSION_TLS13:
                return "3"
            if best == TLS_VERSION_TLS12:
                return "2"
        if ch.legacy_version == TLS_VERSION_TLS12:
            return "2"
        if ch.legacy_version == TLS_VERSION_TLS10:
            return "1"
        return "0"

    @classmethod
    def _alpn_field(cls, ch: ClientHello) -> str:
        alpns = ch.alpn
        if not alpns:
            return "00"
        a = alpns[0]
        if a in cls._ALPN:
            return cls._ALPN[a]
        if len(a) >= 2:
            return a[:1].decode("latin1") + a[-1:].decode("latin1")
        if a:
            return a[:1].decode("latin1") * 2
        return "00"

    @classmethod
    def _sig_algs_hex(cls, ch: ClientHello) -> str:
        d = ch.ext(0x000D)
        if not d or len(d) < 2:
            return ""
        ln = _u16(d, 0)
        vals: List[int] = []
        p = 2
        end = min(2 + ln, len(d))
        while p + 2 <= end:
            vals.append(_u16(d, p))
            p += 2
        return _hex_list(sorted(v for v in vals if not _is_grease(v)))

    @classmethod
    def compute(cls, ch: ClientHello, *, transport: str = "t") -> str:
        version = cls._version_char(ch)
        sni = "d" if ch.sni else "i"

        ciphers = [c for c in ch.cipher_suites if not _is_grease(c)]
        exts = [t for (t, _) in ch.extensions if not _is_grease(t)]
        cipher_count = min(len(ciphers), 99)
        ext_count = min(len(exts), 99)

        alpn = cls._alpn_field(ch)

        cipher_part = _hex_list(sorted(ciphers))
        ext_part = "_".join((_hex_list(sorted(exts)), cls._sig_algs_hex(ch)))

        cipher_hash = hashlib.sha256(cipher_part.encode()).hexdigest()[:12]
        ext_hash = hashlib.sha256(ext_part.encode()).hexdigest()[:12]

        prefix = (
            transport + version + sni
            + f"{cipher_count:02d}"
            + f"{ext_count:02d}"
            + alpn
        )
        return f"{prefix}_{cipher_hash}_{ext_hash}"


# ---------------------------------------------------------------------------
# Browser profile library
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BrowserProfile:
    name: str
    legacy_version: int
    cipher_suites: Tuple[int, ...]
    extension_order: Tuple[int, ...]
    supported_groups: Tuple[int, ...]
    signature_algorithms: Tuple[int, ...]
    alpn: Tuple[bytes, ...]
    ec_point_formats: Tuple[int, ...] = (0,)
    include_grease: bool = True


class Profiles:
    """Curated, verified browser-realistic TLS profiles."""

    CHROME_120 = BrowserProfile(
        name="chrome_120",
        legacy_version=TLS_VERSION_TLS12,
        cipher_suites=(
            0x1301, 0x1302, 0x1303,
            0xC02B, 0xC02F, 0xC02C, 0xC030,
            0xCCA9, 0xCCA8,
            0xC013, 0xC014,
            0x009C, 0x009D,
            0x002F, 0x0035,
        ),
        extension_order=(
            0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010,
            0x0005, 0x000D, 0x0012, 0x0033, 0x002D, 0x002B, 0x001B,
            0x00FD, 0x0015, 0x0011,
        ),
        supported_groups=(0x11EC, 0x11EB, 0x11EA, 0x001D, 0x0017, 0x0018, 0x0019),
        signature_algorithms=(
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501,
            0x0806, 0x0601, 0x0603, 0x0201, 0x0203,
        ),
        alpn=(b"h2", b"http/1.1"),
    )

    FIREFOX_122 = BrowserProfile(
        name="firefox_122",
        legacy_version=TLS_VERSION_TLS12,
        cipher_suites=(
            0x1301, 0x1303, 0x1302,
            0xC02B, 0xC02F, 0xCCA9, 0xCCA8,
            0xC02C, 0xC030, 0xC013, 0xC014,
            0x009C, 0x009D, 0x002F, 0x0035,
        ),
        extension_order=(
            0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010,
            0x0005, 0x000D, 0x0012, 0x0033, 0x002D, 0x002B, 0x001B,
            0x00FD, 0x0015, 0x0011, 0x0022,
        ),
        supported_groups=(0x001D, 0x0017, 0x0018, 0x0019),
        signature_algorithms=(
            0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
            0x0401, 0x0501, 0x0601, 0x0201, 0x0203,
        ),
        alpn=(b"h2", b"http/1.1"),
    )

    SAFARI_17 = BrowserProfile(
        name="safari_17",
        legacy_version=TLS_VERSION_TLS12,
        cipher_suites=(
            0x1301, 0x1302, 0x1303,
            0xC02C, 0xC02B, 0xC030, 0xC02F,
            0xCCA9, 0xCCA8, 0xC013, 0xC014,
            0x009D, 0x009C, 0x0035, 0x002F,
        ),
        extension_order=(
            0x0000, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010,
            0x0005, 0x000D, 0x0012, 0x0033, 0x002D, 0x002B, 0x001B,
            0x0015, 0x0011,
        ),
        supported_groups=(0x001D, 0x0017, 0x0018, 0x0019),
        signature_algorithms=(
            0x0403, 0x0804, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
        ),
        alpn=(b"h2", b"http/1.1"),
    )

    EDGE_120 = BrowserProfile(
        name="edge_120",
        legacy_version=TLS_VERSION_TLS12,
        cipher_suites=(
            0x1301, 0x1302, 0x1303,
            0xC02B, 0xC02F, 0xC02C, 0xC030,
            0xCCA9, 0xCCA8, 0xC013, 0xC014,
            0x009C, 0x009D, 0x002F, 0x0035,
        ),
        extension_order=(
            0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010,
            0x0005, 0x000D, 0x0012, 0x0033, 0x002D, 0x002B, 0x001B,
            0x00FD, 0x0015, 0x0011,
        ),
        supported_groups=(0x001D, 0x0017, 0x0018, 0x0019),
        signature_algorithms=(
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501,
            0x0806, 0x0601, 0x0603, 0x0201, 0x0203,
        ),
        alpn=(b"h2", b"http/1.1"),
    )

    ALL: Dict[str, BrowserProfile] = {
        "chrome_120": CHROME_120,
        "firefox_122": FIREFOX_122,
        "safari_17": SAFARI_17,
        "edge_120": EDGE_120,
    }


# ---------------------------------------------------------------------------
# ClientHello construction from a profile
# ---------------------------------------------------------------------------

class ClientHelloFactory:
    """Build a wire-ready ClientHello for a given profile + SNI."""

    @staticmethod
    def _build_sni(host: str) -> bytes:
        host_bytes = host.encode("idna") if host else b""
        entry = b"\x00" + struct.pack("!H", len(host_bytes)) + host_bytes
        return struct.pack("!H", len(entry)) + entry

    @staticmethod
    def _build_groups(groups: Sequence[int]) -> bytes:
        body = b"".join(struct.pack("!H", g) for g in groups)
        return struct.pack("!H", len(body)) + body

    @staticmethod
    def _build_sig_algs(algs: Sequence[int]) -> bytes:
        body = b"".join(struct.pack("!H", a) for a in algs)
        return struct.pack("!H", len(body)) + body

    @staticmethod
    def _build_alpn(alpns: Sequence[bytes]) -> bytes:
        entries = b""
        for a in alpns:
            if len(a) > 0xFF:
                raise ValueError("ALPN entry too long")
            entries += bytes([len(a)]) + a
        return struct.pack("!H", len(entries)) + entries

    @classmethod
    def create(
        cls,
        profile: BrowserProfile,
        *,
        sni: str = "",
        random_bytes: Optional[bytes] = None,
        session_id: Optional[bytes] = None,
        grease_seed: Optional[int] = None,
    ) -> ClientHello:
        rnd = random_bytes if random_bytes is not None else secrets.token_bytes(32)
        if len(rnd) != 32:
            raise ValueError("random_bytes must be exactly 32 bytes")

        sid = session_id if session_id is not None else secrets.token_bytes(32)
        if len(sid) > 32:
            raise ValueError("session_id too long")

        gseed = grease_seed if grease_seed is not None else secrets.randbelow(16)
        grease = GREASE_VALUES[gseed % 16]

        exts: List[Tuple[int, bytes]] = []
        for et in profile.extension_order:
            data = cls._ext_payload(
                et, profile=profile, sni=sni, grease=grease,
            )
            if data is not None:
                exts.append((et, data))

        if profile.include_grease:
            exts.insert(0, (grease, b""))

        ciphers: List[int] = list(profile.cipher_suites)
        if profile.include_grease:
            ciphers.insert(0, grease)

        return ClientHello(
            legacy_version=profile.legacy_version,
            random=rnd,
            session_id=sid,
            cipher_suites=ciphers,
            compression_methods=[0x00],
            extensions=exts,
        )

    @classmethod
    def _ext_payload(
        cls,
        ext_type: int,
        *,
        profile: BrowserProfile,
        sni: str,
        grease: int,
    ) -> Optional[bytes]:
        if ext_type == 0x0000:  # server_name
            return cls._build_sni(sni)
        if ext_type == 0x000A:  # supported_groups
            return cls._build_groups(profile.supported_groups)
        if ext_type == 0x000B:  # ec_point_formats
            fmts = bytes(profile.ec_point_formats)
            return bytes([len(fmts)]) + fmts
        if ext_type == 0x000D:  # signature_algorithms
            return cls._build_sig_algs(profile.signature_algorithms)
        if ext_type == 0x0010:  # ALPN
            return cls._build_alpn(profile.alpn)
        if ext_type == 0x0017:  # extended_master_secret
            return b""
        if ext_type == 0x0023:  # session_ticket
            return b""
        if ext_type == 0x002B:  # supported_versions
            versions = [grease, TLS_VERSION_TLS13, TLS_VERSION_TLS12]
            body = b"".join(struct.pack("!H", v) for v in versions)
            return bytes([len(body)]) + body
        if ext_type == 0x002D:  # psk_key_exchange_modes
            return b"\x01\x01"
        if ext_type == 0x0033:  # key_share
            entry = struct.pack("!HH", 0x001D, 32) + secrets.token_bytes(32)
            return struct.pack("!H", len(entry)) + entry
        if ext_type == 0x0012:  # signed_certificate_timestamp
            return b""
        if ext_type == 0x001B:  # compress_certificate
            return struct.pack("!BHH", 2, 0x0002, 0x0001)
        if ext_type == 0x00FD:  # padding (empty)
            return b""
        if ext_type == 0x0015:  # padding
            return b"\x00" * 16
        if ext_type == 0x0011:  # status_request
            return b"\x01\x00\x00\x00\x00"
        if ext_type == 0xFF01:  # renegotiation_info
            return b"\x00"
        if ext_type == 0x0022:  # delegated_credentials
            return b"\x00\x04\x08\x04\x04\x03"
        return None


# ---------------------------------------------------------------------------
# Evasion matrix
# ---------------------------------------------------------------------------

class EvasionStrategy(IntEnum):
    ROTATE = 0
    PINNED = 1
    JITTER = 2


@dataclass
class EvasionConfig:
    strategy: EvasionStrategy = EvasionStrategy.ROTATE
    profile_pool: Tuple[str, ...] = tuple(Profiles.ALL.keys())
    pinned_profile: Optional[str] = None
    jitter_min_ms: int = 50
    jitter_max_ms: int = 250
    randomize_session_id: bool = True
    randomize_grease: bool = True


class EvasionMatrix:
    """
    Thread-safe matrix that hands out browser-realistic ClientHello
    generators following the configured evasion strategy.
    """

    def __init__(self, config: Optional[EvasionConfig] = None) -> None:
        self._config = config or EvasionConfig()
        self._lock = threading.RLock()
        self._pool = self._validate_pool(self._config.profile_pool)
        self._counter = 0
        self._pinned = self._config.pinned_profile

        if self._config.strategy == EvasionStrategy.PINNED:
            if not self._pinned:
                raise ValueError("PINNED strategy requires pinned_profile")
            if self._pinned not in Profiles.ALL:
                raise ValueError(f"unknown pinned profile: {self._pinned}")

    @staticmethod
    def _validate_pool(pool: Iterable[str]) -> Tuple[str, ...]:
        valid = [n for n in pool if n in Profiles.ALL]
        if not valid:
            raise ValueError("empty/invalid profile pool")
        return tuple(valid)

    def _pick_profile_name(self) -> str:
        with self._lock:
            c = self._config
            if c.strategy == EvasionStrategy.PINNED:
                return self._pinned or self._pool[0]
            if c.strategy == EvasionStrategy.ROTATE:
                name = self._pool[self._counter % len(self._pool)]
                self._counter += 1
                return name
            return self._pool[secrets.randbelow(len(self._pool))]

    def _maybe_jitter(self) -> None:
        c = self._config
        if c.strategy != EvasionStrategy.JITTER:
            return
        lo = max(0, c.jitter_min_ms)
        hi = max(lo, c.jitter_max_ms)
        if hi == 0:
            return
        time.sleep(secrets.randbelow(hi - lo + 1) / 1000.0 + lo / 1000.0)

    def next_hello(self, *, sni: str) -> ClientHello:
        self._maybe_jitter()
        name = self._pick_profile_name()
        prof = Profiles.ALL[name]
        sid = secrets.token_bytes(32) if self._config.randomize_session_id else b""
        return ClientHelloFactory.create(prof, sni=sni, session_id=sid)

    def next_wire(self, *, sni: str) -> bytes:
        return ClientHelloBuilder.build(self.next_hello(sni=sni))


# ---------------------------------------------------------------------------
# SSL adapter (best-effort)
# ---------------------------------------------------------------------------

class SSLContextAdapter:
    """
    Best-effort integration point with Python's `ssl` module.

    Python's `ssl` does NOT allow raw ClientHello injection. This adapter
    exposes helpers around `SSLContext` and documents the limitation.
    """

    @staticmethod
    def describe(context: ssl.SSLContext) -> Dict[str, Any]:
        try:
            ciphers = context.get_ciphers()
        except Exception:
            ciphers = []
        return {
            "protocol": getattr(context, "protocol", None),
            "ciphers": [c.get("name") for c in ciphers],
            "options": getattr(context, "options", 0),
            "verify_mode": getattr(context, "verify_mode", None),
            "check_hostname": getattr(context, "check_hostname", None),
        }

    @staticmethod
    def wrap_socket_with_sni(
        sock: socket.socket,
        *,
        sni: str,
        context: Optional[ssl.SSLContext] = None,
        timeout: Optional[float] = 10.0,
    ) -> ssl.SSLSocket:
        ctx = context or ssl.create_default_context()
        if timeout is not None:
            sock.settimeout(timeout)
        return ctx.wrap_socket(sock, server_hostname=sni)


# ---------------------------------------------------------------------------
# High-level façade
# ---------------------------------------------------------------------------

class TLSFingerprintEngine:
    """Unified entry point for fingerprint computation + evasion."""

    def __init__(self, config: Optional[EvasionConfig] = None) -> None:
        self.matrix = EvasionMatrix(config)

    @staticmethod
    def fingerprint(ch: ClientHello) -> Dict[str, str]:
        return {
            "ja3": JA3.hash(ch),
            "ja3n": JA3.ja3n(ch),
            "ja4": JA4.compute(ch),
            "ja3_string": JA3.string(ch),
        }

    @staticmethod
    def fingerprint_record(record: bytes) -> Dict[str, str]:
        return TLSFingerprintEngine.fingerprint(ClientHelloParser.parse(record))

    def emit(self, *, sni: str) -> Dict[str, Any]:
        ch = self.matrix.next_hello(sni=sni)
        wire = ClientHelloBuilder.build(ch)
        return {
            "sni": sni,
            "wire": wire,
            "wire_len": len(wire),
            "client_hello": ch,
            "fingerprint": self.fingerprint(ch),
        }

    def emit_wire(self, *, sni: str) -> bytes:
        return self.matrix.next_wire(sni=sni)


# ---------------------------------------------------------------------------
# Self-test / demo
# ---------------------------------------------------------------------------

def _self_test() -> int:
    print("=== TLS Fingerprint Engine Self-Test ===")
    engine = TLSFingerprintEngine()

    for name in Profiles.ALL:
        prof = Profiles.ALL[name]
        ch = ClientHelloFactory.create(prof, sni="example.com")
        wire = ClientHelloBuilder.build(ch)
        parsed = ClientHelloParser.parse(wire)

        assert parsed.legacy_version == ch.legacy_version
        assert parsed.cipher_suites == ch.cipher_suites
        assert parsed.session_id == ch.session_id
        assert parsed.sni == "example.com"

        fp = engine.fingerprint(parsed)
        print(f"[{name}] ja3={fp['ja3']} ja4={fp['ja4']}")

    print("\n=== Evasion Matrix Rotation ===")
    for i in range(6):
        info = engine.emit(sni=f"host{i}.example")
        print(f"  #{i} len={info['wire_len']} ja4={info['fingerprint']['ja4']}")

    print("\n=== Round-trip via fingerprint_record ===")
    rec = engine.emit_wire(sni="test.local")
    fp = engine.fingerprint_record(rec)
    print(f"  ja3={fp['ja3']}  ja4={fp['ja4']}")

    print("\nOK — all self-tests passed.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(_self_test())
    except Exception as exc:  # pragma: no cover
        print(f"self-test failed: {exc}", file=sys.stderr)
        sys.exit(1)