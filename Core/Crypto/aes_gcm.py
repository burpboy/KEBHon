# aes_gcm.py
"""AES-256-GCM Authenticated Encryption for Payload Obfuscation.

Python 3.8+ | Requires: cryptography>=41.0.0
Install: pip install cryptography
"""

from __future__ import annotations

import base64
import secrets
from typing import Optional, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
SALT_SIZE = 16
PBKDF2_ITERATIONS = 600_000
VERSION = 1
HEADER_SIZE = 1 + SALT_SIZE + NONCE_SIZE


class AesGcmError(Exception):
    """Base exception for AES-GCM module."""


class DecryptionError(AesGcmError):
    """Raised when authentication fails or payload is malformed."""


class KeyDerivationError(AesGcmError):
    """Raised when key derivation input is invalid."""


class AesGcmKey:
    """Holds a raw 256-bit AES key."""

    __slots__ = ("_key",)

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes")
        if len(key) != KEY_SIZE:
            raise ValueError(f"key must be {KEY_SIZE} bytes (got {len(key)})")
        self._key: bytes = bytes(key)

    @classmethod
    def generate(cls) -> "AesGcmKey":
        return cls(secrets.token_bytes(KEY_SIZE))

    @classmethod
    def from_passphrase(
        cls,
        passphrase: Union[str, bytes],
        salt: Optional[bytes] = None,
        iterations: int = PBKDF2_ITERATIONS,
    ) -> tuple["AesGcmKey", bytes]:
        if isinstance(passphrase, str):
            passphrase_bytes = passphrase.encode("utf-8")
        elif isinstance(passphrase, (bytes, bytearray)):
            passphrase_bytes = bytes(passphrase)
        else:
            raise KeyDerivationError("passphrase must be str or bytes")
        if not passphrase_bytes:
            raise KeyDerivationError("passphrase must not be empty")
        if salt is None:
            salt = secrets.token_bytes(SALT_SIZE)
        elif len(salt) != SALT_SIZE:
            raise KeyDerivationError(f"salt must be {SALT_SIZE} bytes")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=bytes(salt),
            iterations=iterations,
        )
        return cls(kdf.derive(passphrase_bytes)), bytes(salt)

    def to_bytes(self) -> bytes:
        return self._key

    def __repr__(self) -> str:
        return "<AesGcmKey: redacted>"


def _validate_aad(aad: Optional[bytes]) -> bytes:
    if aad is None:
        return b""
    if not isinstance(aad, (bytes, bytearray)):
        raise TypeError("aad must be bytes or None")
    return bytes(aad)


def encrypt(
    key: AesGcmKey,
    plaintext: Union[bytes, bytearray],
    aad: Optional[bytes] = None,
) -> bytes:
    if not isinstance(key, AesGcmKey):
        raise TypeError("key must be AesGcmKey")
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    if len(plaintext) == 0:
        raise ValueError("plaintext must not be empty")
    nonce = secrets.token_bytes(NONCE_SIZE)
    salt = secrets.token_bytes(SALT_SIZE)
    header = bytes([VERSION]) + salt + nonce
    full_aad = header + _validate_aad(aad)
    aesgcm = AESGCM(key.to_bytes())
    body = aesgcm.encrypt(nonce, bytes(plaintext), full_aad)
    return header + body


def decrypt(
    key: AesGcmKey,
    container: Union[bytes, bytearray],
    aad: Optional[bytes] = None,
) -> bytes:
    if not isinstance(key, AesGcmKey):
        raise TypeError("key must be AesGcmKey")
    if not isinstance(container, (bytes, bytearray)):
        raise TypeError("container must be bytes")
    data = bytes(container)
    if len(data) < HEADER_SIZE + 1 + TAG_SIZE:
        raise DecryptionError("container too short / truncated")
    if data[0] != VERSION:
        raise DecryptionError(f"unsupported container version: {data[0]}")
    nonce = data[1 + SALT_SIZE:HEADER_SIZE]
    body = data[HEADER_SIZE:]
    header = data[:HEADER_SIZE]
    full_aad = header + _validate_aad(aad)
    try:
        plaintext = AESGCM(key.to_bytes()).decrypt(nonce, body, full_aad)
    except InvalidTag as exc:
        raise DecryptionError("authentication failed") from exc
    if not plaintext:
        raise DecryptionError("empty plaintext after decryption")
    return plaintext


def encrypt_with_passphrase(
    passphrase: Union[str, bytes],
    plaintext: Union[bytes, bytearray],
    aad: Optional[bytes] = None,
) -> bytes:
    if not isinstance(plaintext, (bytes, bytearray)) or len(plaintext) == 0:
        raise ValueError("plaintext must be non-empty bytes")
    salt = secrets.token_bytes(SALT_SIZE)
    key, _ = AesGcmKey.from_passphrase(passphrase, salt=salt)
    nonce = secrets.token_bytes(NONCE_SIZE)
    header = bytes([VERSION]) + salt + nonce
    full_aad = header + _validate_aad(aad)
    body = AESGCM(key.to_bytes()).encrypt(nonce, bytes(plaintext), full_aad)
    return header + body


def decrypt_with_passphrase(
    passphrase: Union[str, bytes],
    container: Union[bytes, bytearray],
    aad: Optional[bytes] = None,
) -> bytes:
    if not isinstance(container, (bytes, bytearray)):
        raise TypeError("container must be bytes")
    data = bytes(container)
    if len(data) < HEADER_SIZE + 1 + TAG_SIZE:
        raise DecryptionError("container too short / truncated")
    if data[0] != VERSION:
        raise DecryptionError(f"unsupported container version: {data[0]}")
    salt = data[1:1 + SALT_SIZE]
    nonce = data[1 + SALT_SIZE:HEADER_SIZE]
    body = data[HEADER_SIZE:]
    header = data[:HEADER_SIZE]
    full_aad = header + _validate_aad(aad)
    key, _ = AesGcmKey.from_passphrase(passphrase, salt=salt)
    try:
        plaintext = AESGCM(key.to_bytes()).decrypt(nonce, body, full_aad)
    except InvalidTag as exc:
        raise DecryptionError("authentication failed") from exc
    if not plaintext:
        raise DecryptionError("empty plaintext after decryption")
    return plaintext


def to_base64(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    return base64.b64encode(bytes(data)).decode("ascii")


def from_base64(text: str) -> bytes:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:
        raise DecryptionError("invalid base64 input") from exc


def _self_test() -> None:
    print("[*] Running self-test...")
    key = AesGcmKey.generate()
    msg = b"Hello, AES-256-GCM!"
    blob = encrypt(key, msg, aad=b"meta:1")
    assert decrypt(key, blob, aad=b"meta:1") == msg

    try:
        decrypt(key, blob, aad=b"meta:2")
        raise AssertionError("expected DecryptionError")
    except DecryptionError:
        pass

    tampered = bytearray(blob)
    tampered[-1] ^= 0x01
    try:
        decrypt(key, bytes(tampered))
        raise AssertionError("expected DecryptionError")
    except DecryptionError:
        pass

    pw = "correct horse battery staple"
    blob2 = encrypt_with_passphrase(pw, msg, aad=b"meta:1")
    assert decrypt_with_passphrase(pw, blob2, aad=b"meta:1") == msg

    assert from_base64(to_base64(blob)) == blob
    print("[+] All self-tests passed.")


if __name__ == "__main__":
    _self_test()