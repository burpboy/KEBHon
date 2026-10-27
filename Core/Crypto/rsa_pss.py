# rsa_pss.py
# RSA-4096 / Ed25519 Cryptographic Handshake & Key Exchange
# Production-ready, high-level Python

"""
Module: rsa_pss.py

Provides:
- RSA-4096 key generation, PSS signing/verification (RSASSA-PSS with SHA-256)
- Ed25519 key generation, signing/verification
- Hybrid handshake protocol (X25519 ECDH + Ed25519 auth + AES-GCM session)
- Key exchange with forward secrecy
- Serialization helpers (PEM/DER/raw)

Dependencies:
    pip install cryptography
"""

from __future__ import annotations

import os
import hmac
import hashlib
import struct
from dataclasses import dataclass
from typing import Optional, Tuple, Any
from enum import Enum

# ---------------------------------------------------------------------------
# Optional cryptography backend
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.asymmetric import (
        rsa,
        padding,
        ed25519,
        x25519,
    )
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidSignature
    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTO = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
RSA_KEY_SIZE = 4096
RSA_PUBLIC_EXPONENT = 65537
PSS_SALT_LENGTH = 32          # SHA-256 digest size
HANDSHAKE_VERSION = 1
SESSION_KEY_LEN = 32
NONCE_LEN = 12
HKDF_INFO = b"rsa-pss-ed25519-handshake-v1"


class HandshakeState(Enum):
    INIT = "init"
    CLIENT_HELLO = "client_hello"
    SERVER_HELLO = "server_hello"
    KEY_EXCHANGE = "key_exchange"
    ESTABLISHED = "established"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _require_crypto() -> None:
    if not _HAVE_CRYPTO:
        raise RuntimeError(
            "The 'cryptography' package is required for this operation. "
            "Install it with: pip install cryptography"
        )


def _b64(data: bytes) -> str:
    import base64
    return base64.b64encode(data).decode("ascii")


def _unb64(s: str) -> bytes:
    import base64
    return base64.b64decode(s.encode("ascii"))


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _constant_time_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


# ---------------------------------------------------------------------------
# RSA-4096 (PSS) wrapper
# ---------------------------------------------------------------------------
@dataclass
class RSAKeyPair:
    """RSA-4096 keypair using RSASSA-PSS with SHA-256."""
    private_key: Any = None
    public_key: Any = None

    @classmethod
    def generate(cls) -> "RSAKeyPair":
        _require_crypto()
        priv = rsa.generate_private_key(
            public_exponent=RSA_PUBLIC_EXPONENT,
            key_size=RSA_KEY_SIZE,
        )
        return cls(private_key=priv, public_key=priv.public_key())

    def sign(self, message: bytes) -> bytes:
        _require_crypto()
        if self.private_key is None:
            raise ValueError("Private key not available for signing.")
        return self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=PSS_SALT_LENGTH,
            ),
            hashes.SHA256(),
        )

    def verify(self, message: bytes, signature: bytes) -> bool:
        _require_crypto()
        if self.public_key is None:
            raise ValueError("Public key not available for verification.")
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=PSS_SALT_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            return False

    def export_public_pem(self) -> bytes:
        _require_crypto()
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def export_private_pem(self, password: Optional[bytes] = None) -> bytes:
        _require_crypto()
        enc = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )

    @classmethod
    def load_public_pem(cls, pem: bytes) -> "RSAKeyPair":
        _require_crypto()
        pub = serialization.load_pem_public_key(pem)
        return cls(private_key=None, public_key=pub)

    @classmethod
    def load_private_pem(
        cls, pem: bytes, password: Optional[bytes] = None
    ) -> "RSAKeyPair":
        _require_crypto()
        priv = serialization.load_pem_private_key(pem, password=password)
        return cls(private_key=priv, public_key=priv.public_key())


# ---------------------------------------------------------------------------
# Ed25519 wrapper
# ---------------------------------------------------------------------------
@dataclass
class Ed25519KeyPair:
    private_key: Any = None
    public_key: Any = None

    @classmethod
    def generate(cls) -> "Ed25519KeyPair":
        _require_crypto()
        priv = ed25519.Ed25519PrivateKey.generate()
        return cls(private_key=priv, public_key=priv.public_key())

    def sign(self, message: bytes) -> bytes:
        _require_crypto()
        if self.private_key is None:
            raise ValueError("Private key not available.")
        return self.private_key.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        _require_crypto()
        if self.public_key is None:
            raise ValueError("Public key not available.")
        try:
            self.public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def export_public_raw(self) -> bytes:
        _require_crypto()
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def export_private_raw(self) -> bytes:
        _require_crypto()
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @classmethod
    def from_public_raw(cls, raw: bytes) -> "Ed25519KeyPair":
        _require_crypto()
        pub = ed25519.Ed25519PublicKey.from_public_bytes(raw)
        return cls(private_key=None, public_key=pub)

    @classmethod
    def from_private_raw(cls, raw: bytes) -> "Ed25519KeyPair":
        _require_crypto()
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(raw)
        return cls(private_key=priv, public_key=priv.public_key())


# ---------------------------------------------------------------------------
# X25519 ECDH (for forward secrecy)
# ---------------------------------------------------------------------------
@dataclass
class X25519KeyPair:
    private_key: Any = None
    public_key: Any = None

    @classmethod
    def generate(cls) -> "X25519KeyPair":
        _require_crypto()
        priv = x25519.X25519PrivateKey.generate()
        return cls(private_key=priv, public_key=priv.public_key())

    def exchange(self, peer_public_raw: bytes) -> bytes:
        _require_crypto()
        if self.private_key is None:
            raise ValueError("Private key not available.")
        peer = x25519.X25519PublicKey.from_public_bytes(peer_public_raw)
        return self.private_key.exchange(peer)

    def export_public_raw(self) -> bytes:
        _require_crypto()
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


# ---------------------------------------------------------------------------
# Session cipher (AES-GCM)
# ---------------------------------------------------------------------------
class SessionCipher:
    """AES-256-GCM session cipher with monotonically increasing nonce counter."""

    def __init__(self, key: bytes):
        _require_crypto()
        if len(key) != SESSION_KEY_LEN:
            raise ValueError(f"Session key must be {SESSION_KEY_LEN} bytes.")
        self._aead = AESGCM(key)
        self._counter = 0
        self._lock_iv = os.urandom(4)  # 4-byte prefix for nonce uniqueness

    def _nonce(self) -> bytes:
        # 4-byte random prefix || 8-byte counter => 12 bytes total
        self._counter += 1
        if self._counter >= 2**64:
            raise OverflowError("Session nonce counter exhausted.")
        return self._lock_iv + struct.pack(">Q", self._counter)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
        nonce = self._nonce()
        ct = self._aead.encrypt(nonce, plaintext, aad)
        return nonce, ct

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        return self._aead.decrypt(nonce, ciphertext, aad)


# ---------------------------------------------------------------------------
# HKDF helper
# ---------------------------------------------------------------------------
def _derive_session_key(
    shared_secret: bytes, salt: bytes, context: bytes
) -> bytes:
    _require_crypto()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=SESSION_KEY_LEN,
        salt=salt,
        info=HKDF_INFO + context,
    )
    return hkdf.derive(shared_secret)


# ---------------------------------------------------------------------------
# Handshake messages
# ---------------------------------------------------------------------------
@dataclass
class ClientHello:
    version: int
    client_ed25519_pub: bytes   # 32 bytes
    client_x25519_pub: bytes    # 32 bytes
    client_rsa_pub_pem: bytes   # RSA-4096 public key (PEM)
    nonce_c: bytes              # 32 bytes

    def serialize(self) -> bytes:
        return (
            struct.pack(">H", self.version)
            + self.client_ed25519_pub
            + self.client_x25519_pub
            + struct.pack(">H", len(self.client_rsa_pub_pem))
            + self.client_rsa_pub_pem
            + self.nonce_c
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "ClientHello":
        if len(data) < 2 + 32 + 32 + 2 + 32:
            raise ValueError("ClientHello too short.")
        off = 0
        version = struct.unpack_from(">H", data, off)[0]; off += 2
        ed = data[off:off + 32]; off += 32
        x = data[off:off + 32]; off += 32
        rsa_len = struct.unpack_from(">H", data, off)[0]; off += 2
        rsa_pem = data[off:off + rsa_len]; off += rsa_len
        nonce_c = data[off:off + 32]; off += 32
        return cls(version, ed, x, rsa_pem, nonce_c)


@dataclass
class ServerHello:
    version: int
    server_ed25519_pub: bytes
    server_x25519_pub: bytes
    server_rsa_pub_pem: bytes
    nonce_s: bytes              # 32 bytes
    server_ed25519_sig: bytes   # signature over transcript

    def serialize(self) -> bytes:
        return (
            struct.pack(">H", self.version)
            + self.server_ed25519_pub
            + self.server_x25519_pub
            + struct.pack(">H", len(self.server_rsa_pub_pem))
            + self.server_rsa_pub_pem
            + self.nonce_s
            + struct.pack(">H", len(self.server_ed25519_sig))
            + self.server_ed25519_sig
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "ServerHello":
        off = 0
        version = struct.unpack_from(">H", data, off)[0]; off += 2
        ed = data[off:off + 32]; off += 32
        x = data[off:off + 32]; off += 32
        rsa_len = struct.unpack_from(">H", data, off)[0]; off += 2
        rsa_pem = data[off:off + rsa_len]; off += rsa_len
        nonce_s = data[off:off + 32]; off += 32
        sig_len = struct.unpack_from(">H", data, off)[0]; off += 2
        sig = data[off:off + sig_len]; off += sig_len
        return cls(version, ed, x, rsa_pem, nonce_s, sig)


@dataclass
class ClientFinish:
    client_ed25519_sig: bytes   # signature over transcript
    client_rsa_sig: bytes       # RSA-PSS signature over transcript

    def serialize(self) -> bytes:
        return (
            struct.pack(">H", len(self.client_ed25519_sig))
            + self.client_ed25519_sig
            + struct.pack(">H", len(self.client_rsa_sig))
            + self.client_rsa_sig
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "ClientFinish":
        off = 0
        ed_len = struct.unpack_from(">H", data, off)[0]; off += 2
        ed_sig = data[off:off + ed_len]; off += ed_len
        rsa_len = struct.unpack_from(">H", data, off)[0]; off += 2
        rsa_sig = data[off:off + rsa_len]; off += rsa_len
        return cls(ed_sig, rsa_sig)


# ---------------------------------------------------------------------------
# Handshake engine
# ---------------------------------------------------------------------------
@dataclass
class HandshakeResult:
    session_key: bytes
    cipher: SessionCipher
    peer_identity: bytes
    state: HandshakeState = HandshakeState.ESTABLISHED


class Handshake:
    """
    Hybrid handshake:
    - Identity: Ed25519 + RSA-4096 (PSS)
    - Key exchange: X25519 ECDH (forward secrecy)
    - Transcript binding: SHA-256 over all messages
    - Session: AES-256-GCM via HKDF
    """

    def __init__(
        self,
        rsa_keys: RSAKeyPair,
        ed25519_keys: Ed25519KeyPair,
        x25519_keys: Optional[X25519KeyPair] = None,
    ):
        _require_crypto()
        if rsa_keys.private_key is None:
            raise ValueError("RSA private key required for handshake.")
        if ed25519_keys.private_key is None:
            raise ValueError("Ed25519 private key required for handshake.")
        self.rsa = rsa_keys
        self.ed25519 = ed25519_keys
        self.x25519 = x25519_keys or X25519KeyPair.generate()
        self.state = HandshakeState.INIT
        self._transcript = hashlib.sha256()
        self._session_key: Optional[bytes] = None
        self._nonce_c: Optional[bytes] = None
        self._nonce_s: Optional[bytes] = None
        self._peer_client_hello: Optional[ClientHello] = None
        self._digest_before_finish: Optional[bytes] = None

    # -- transcript ---------------------------------------------------------
    def _bind(self, data: bytes) -> None:
        self._transcript.update(data)

    def _transcript_digest(self) -> bytes:
        h = self._transcript.copy()
        return h.digest()

    # -- client side --------------------------------------------------------
    def client_hello(self) -> Tuple[ClientHello, bytes]:
        if self.state != HandshakeState.INIT:
            raise RuntimeError(f"Invalid state for client_hello: {self.state}")
        hello = ClientHello(
            version=HANDSHAKE_VERSION,
            client_ed25519_pub=self.ed25519.export_public_raw(),
            client_x25519_pub=self.x25519.export_public_raw(),
            client_rsa_pub_pem=self.rsa.export_public_pem(),
            nonce_c=os.urandom(32),
        )
        self._nonce_c = hello.nonce_c
        raw = hello.serialize()
        self._bind(raw)
        self.state = HandshakeState.CLIENT_HELLO
        return hello, raw

    def client_process_server_hello(
        self, raw_server_hello: bytes
    ) -> Tuple[ServerHello, bytes]:
        if self.state != HandshakeState.CLIENT_HELLO:
            raise RuntimeError(f"Invalid state: {self.state}")
        self._bind(raw_server_hello)
        hello = ServerHello.deserialize(raw_server_hello)

        # Verify server Ed25519 signature over transcript-so-far
        transcript_digest = self._transcript_digest()
        server_ed = Ed25519KeyPair.from_public_raw(hello.server_ed25519_pub)
        if not server_ed.verify(transcript_digest, hello.server_ed25519_sig):
            self.state = HandshakeState.FAILED
            raise ValueError("Server Ed25519 signature invalid.")

        # Compute ECDH shared secret
        shared = self.x25519.exchange(hello.server_x25519_pub)
        if len(shared) == 0 or shared == b"\x00" * len(shared):
            self.state = HandshakeState.FAILED
            raise ValueError("Invalid ECDH shared secret.")

        if self._nonce_c is None:
            self.state = HandshakeState.FAILED
            raise RuntimeError("ClientHello nonce missing.")

        salt = bytes(a ^ b for a, b in zip(self._nonce_c, hello.nonce_s))
        session_key = _derive_session_key(
            shared, salt=salt, context=transcript_digest
        )

        # Sign transcript digest for ClientFinish
        client_sig_ed = self.ed25519.sign(transcript_digest)
        client_sig_rsa = self.rsa.sign(transcript_digest)

        finish = ClientFinish(
            client_ed25519_sig=client_sig_ed,
            client_rsa_sig=client_sig_rsa,
        )
        self._bind(finish.serialize())
        self._session_key = session_key
        self.state = HandshakeState.ESTABLISHED
        return hello, finish.serialize()

    # -- server side --------------------------------------------------------
    def server_process_client_hello(
        self, raw_client_hello: bytes
    ) -> Tuple[ClientHello, bytes]:
        if self.state != HandshakeState.INIT:
            raise RuntimeError(f"Invalid state: {self.state}")
        self._bind(raw_client_hello)
        hello = ClientHello.deserialize(raw_client_hello)
        if hello.version != HANDSHAKE_VERSION:
            self.state = HandshakeState.FAILED
            raise ValueError("Unsupported handshake version.")

        self._peer_client_hello = hello

        server_hello = ServerHello(
            version=HANDSHAKE_VERSION,
            server_ed25519_pub=self.ed25519.export_public_raw(),
            server_x25519_pub=self.x25519.export_public_raw(),
            server_rsa_pub_pem=self.rsa.export_public_pem(),
            nonce_s=os.urandom(32),
            server_ed25519_sig=b"",
        )
        self._nonce_s = server_hello.nonce_s

        # Sign transcript-so-far (which includes client hello)
        transcript_digest = self._transcript_digest()
        server_hello.server_ed25519_sig = self.ed25519.sign(transcript_digest)

        raw = server_hello.serialize()
        self._bind(raw)
        self.state = HandshakeState.SERVER_HELLO
        return hello, raw

    def server_accept_client_finish(
        self, raw_client_finish: bytes
    ) -> Tuple[bytes, SessionCipher]:
        if self.state != HandshakeState.SERVER_HELLO:
            raise RuntimeError(f"Invalid state: {self.state}")
        if self._peer_client_hello is None or self._nonce_s is None:
            self.state = HandshakeState.FAILED
            raise RuntimeError("ServerHello or ClientHello missing.")

        # Snapshot transcript BEFORE binding finish
        self._digest_before_finish = self._transcript_digest()
        self._bind(raw_client_finish)
        finish = ClientFinish.deserialize(raw_client_finish)

        # Verify client Ed25519 signature
        client_ed = Ed25519KeyPair.from_public_raw(
            self._peer_client_hello.client_ed25519_pub
        )
        if not client_ed.verify(self._digest_before_finish, finish.client_ed25519_sig):
            self.state = HandshakeState.FAILED
            raise ValueError("Client Ed25519 signature invalid.")

        # Verify client RSA-PSS signature
        client_rsa = RSAKeyPair.load_public_pem(
            self._peer_client_hello.client_rsa_pub_pem
        )
        if not client_rsa.verify(self._digest_before_finish, finish.client_rsa_sig):
            self.state = HandshakeState.FAILED
            raise ValueError("Client RSA-PSS signature invalid.")

        # Compute ECDH shared secret
        shared = self.x25519.exchange(
            self._peer_client_hello.client_x25519_pub
        )
        if len(shared) == 0 or shared == b"\x00" * len(shared):
            self.state = HandshakeState.FAILED
            raise ValueError("Invalid ECDH shared secret.")

        salt = bytes(
            a ^ b
            for a, b in zip(self._peer_client_hello.nonce_c, self._nonce_s)
        )
        session_key = _derive_session_key(
            shared, salt=salt, context=self._digest_before_finish
        )

        self._session_key = session_key
        self.state = HandshakeState.ESTABLISHED
        return session_key, SessionCipher(session_key)


# ---------------------------------------------------------------------------
# Top-level convenience API
# ---------------------------------------------------------------------------
def create_handshake(
    rsa_keys: Optional[RSAKeyPair] = None,
    ed25519_keys: Optional[Ed25519KeyPair] = None,
) -> Handshake:
    rsa_keys = rsa_keys or RSAKeyPair.generate()
    ed25519_keys = ed25519_keys or Ed25519KeyPair.generate()
    return Handshake(rsa_keys, ed25519_keys)


def derive_shared_session_key(
    shared_secret: bytes, salt: bytes, context: bytes
) -> bytes:
    return _derive_session_key(shared_secret, salt, context)


# ---------------------------------------------------------------------------
# Demo / self-test
# ---------------------------------------------------------------------------
def _self_test() -> None:
    _require_crypto()
    print("[*] RSA-4096 / Ed25519 self-test starting...")

    # 1. RSA-PSS roundtrip
    rsa_kp = RSAKeyPair.generate()
    msg = b"hello rsa-pss"
    sig = rsa_kp.sign(msg)
    assert rsa_kp.verify(msg, sig), "RSA-PSS verify failed"
    assert not rsa_kp.verify(b"tampered", sig), "RSA-PSS tamper detection failed"
    print("[+] RSA-4096 PSS OK")

    # 2. Ed25519 roundtrip
    ed_kp = Ed25519KeyPair.generate()
    sig_ed = ed_kp.sign(msg)
    assert ed_kp.verify(msg, sig_ed), "Ed25519 verify failed"
    assert not ed_kp.verify(b"tampered", sig_ed), "Ed25519 tamper detection failed"
    print("[+] Ed25519 OK")

    # 3. X25519 ECDH symmetry
    a = X25519KeyPair.generate()
    b = X25519KeyPair.generate()
    s1 = a.exchange(b.export_public_raw())
    s2 = b.exchange(a.export_public_raw())
    assert _constant_time_eq(s1, s2), "ECDH symmetry failed"
    print("[+] X25519 ECDH OK")

    # 4. Session cipher roundtrip
    key = os.urandom(SESSION_KEY_LEN)
    c = SessionCipher(key)
    nonce, ct = c.encrypt(b"secret data", aad=b"hdr")
    pt = c.decrypt(nonce, ct, aad=b"hdr")
    assert pt == b"secret data", "AES-GCM roundtrip failed"
    print("[+] AES-256-GCM OK")

    # 5. Full handshake simulation
    client = Handshake(RSAKeyPair.generate(), Ed25519KeyPair.generate())
    server = Handshake(RSAKeyPair.generate(), Ed25519KeyPair.generate())

    _, raw_ch = client.client_hello()
    _, raw_sh = server.server_process_client_hello(raw_ch)
    _, raw_finish = client.client_process_server_hello(raw_sh)
    session_key_server, cipher_server = server.server_accept_client_finish(raw_finish)

    assert _constant_time_eq(client._session_key, session_key_server), \
        "Session key mismatch"
    print("[+] Full handshake OK")

    # 6. Post-handshake encrypted communication
    cipher_client = SessionCipher(client._session_key)
    payload = b"secure payload over handshake"
    n, ct = cipher_client.encrypt(payload)
    assert cipher_server.decrypt(n, ct) == payload, "Post-handshake encryption failed"
    print("[+] Post-handshake encryption OK")

    print("[*] All self-tests passed.")


if __name__ == "__main__":
    _self_test()