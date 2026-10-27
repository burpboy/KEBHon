"""
test_crypto.py
A high-level, production-grade test suite and utility wrapper for cryptographic operations.
Features strict typing, protocol compliance, and robust error handling.
"""

import base64
from typing import Final, Protocol, runtime_checkable
import pytest
from cryptography.fernet import Fernet, InvalidToken


# --- Protocols & Core Implementation ---

@runtime_checkable
class CryptoManagerProtocol(Protocol):
    def encrypt(self, plaintext: str) -> str: ...
    def decrypt(self, ciphertext: str) -> str: ...


class SecureVault:
    """High-level wrapper for Fernet symmetric encryption with strict validation."""

    def __init__(self, key: bytes | None = None) -> None:
        self._key: Final[bytes] = key or Fernet.generate_key()
        self._fernet: Final[Fernet] = Fernet(self._key)

    @property
    def key(self) -> bytes:
        return self._key

    def encrypt(self, plaintext: str) -> str:
        """Encrypts a string plaintext into a URL-safe base64-encoded ciphertext."""
        if not isinstance(plaintext, str):
            raise TypeError("Plaintext must be a string.")
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        """Decrypts a ciphertext string back into the original plaintext."""
        if not isinstance(ciphertext, str):
            raise TypeError("Ciphertext must be a string.")
        try:
            return self._fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
        except InvalidToken as e:
            raise ValueError("Decryption failed: Invalid token or corrupted data.") from e


# --- Pytest Fixtures ---

@pytest.fixture
def secure_vault() -> SecureVault:
    """Provides a fresh SecureVault instance for test execution."""
    return SecureVault()


@pytest.fixture
def sample_secrets() -> tuple[str, ...]:
    """Provides diverse test payloads including special characters and Unicode."""
    return (
        "Confidential API Key: sk_live_999999",
        "Special characters: üñîçøđé & 🚀",
        "1234567890"
    )


# --- Test Suite ---

def test_protocol_compliance(secure_vault: SecureVault) -> None:
    """Ensures SecureVault strictly adheres to the CryptoManagerProtocol."""
    assert isinstance(secure_vault, CryptoManagerProtocol)


def test_encryption_decryption_roundtrip(secure_vault: SecureVault, sample_secrets: tuple[str, ...]) -> None:
    """Verifies successful roundtrip encryption and decryption for all sample data."""
    for secret in sample_secrets:
        ciphertext = secure_vault.encrypt(secret)
        assert ciphertext != secret
        decrypted = secure_vault.decrypt(ciphertext)
        assert decrypted == secret


def test_invalid_token_raises_value_error(secure_vault: SecureVault) -> None:
    """Ensures decrypting malformed or invalid tokens raises a controlled ValueError."""
    fake_ciphertext = base64.urlsafe_b64encode(b"invalid_token_bytes_payload").decode("utf-8")
    with pytest.raises(ValueError, match="Decryption failed"):
        secure_vault.decrypt(fake_ciphertext)


def test_type_enforcement(secure_vault: SecureVault) -> None:
    """Ensures passing invalid data types correctly triggers a TypeError."""
    with pytest.raises(TypeError):
        secure_vault.encrypt(12345)  # type: ignore

    with pytest.raises(TypeError):
        secure_vault.decrypt(None)  # type: ignore


def test_unique_ciphertexts(secure_vault: SecureVault) -> None:
    """Verifies that encrypting identical plaintexts yields unique ciphertexts due to dynamic IVs."""
    plaintext = "Constant Secret Payload"
    c1 = secure_vault.encrypt(plaintext)
    c2 = secure_vault.encrypt(plaintext)
    
    assert c1 != c2
    assert secure_vault.decrypt(c1) == secure_vault.decrypt(c2) == plaintext
