"""
aes_gcm.py - AES-256-GCM Authenticated Encryption for Payload Obfuscation

Provides a robust, zero-dependency (beyond standard library) implementation of
AES-256 in GCM mode using pure Python. Includes key derivation via PBKDF2-HMAC-SHA256,
random nonce generation, and authenticated encryption/decryption with integrity checks.

Designed for payload obfuscation where both confidentiality and authenticity are required.

Author: Dwi Joko Purwanto 
Version: 1.0.0
"""

import os
import struct
import hashlib
import hmac


class AESGCMError(Exception):
    """Base exception for AES-GCM operations."""
    pass


class KeyDerivationError(AESGCMError):
    """Raised when key derivation fails."""
    pass


class AuthenticationError(AESGCMError):
    """Raised when the authentication tag does not match."""
    pass


class InvalidNonceError(AESGCMError):
    """Raised when the nonce is invalid (wrong length or all zeros)."""
    pass


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    if len(a) != len(b):
        raise ValueError("Byte strings must be of equal length for XOR.")
    return bytes(x ^ y for x, y in zip(a, b))


def _increment_counter(counter_block: bytearray) -> None:
    """Increment a 16-byte counter block by 1 (little-endian style on the last 4 bytes)."""
    # Increment the last 4 bytes as a big-endian integer
    val = int.from_bytes(counter_block[12:16], 'big')
    val = (val + 1) % (1 << 32)
    counter_block[12:16] = val.to_bytes(4, 'big')


def _get_aes_substitution_table():
    """Return the AES S-box."""
    # Standard AES S-box
    sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x9b, 0x19, 0xcd, 0xa9, 0xc2, 0xe0, 0x44, 0xe6, 0xd4,
        0xe1, 0xf3, 0x9d, 0x5c, 0x05, 0x15, 0xa5, 0x8e, 0x99, 0x6d, 0x25, 0x6f, 0xc6, 0x9e, 0x12, 0xee,
        0x17, 0xe5, 0x41, 0xdb, 0x95, 0xbe, 0x4c, 0xd4, 0xa3, 0x69, 0x28, 0x56, 0x0a, 0x37, 0x5e, 0x66,
        0x27, 0xe9, 0x2e, 0xde, 0x62, 0xef, 0x03, 0x08, 0x02, 0xbc, 0x0e, 0x0d, 0x09, 0x11, 0x24, 0x45,
        0xe4, 0x40, 0xe3, 0x87, 0x0b, 0x32, 0x5a, 0x0c, 0xc0, 0xb6, 0xd1, 0x25, 0x0f, 0x8c, 0x10, 0x16,
        0x67, 0x28, 0xdd, 0x0c, 0x81, 0x03, 0x0d, 0x13, 0x63, 0x09, 0x1c, 0x0e, 0x07, 0x04, 0x0e, 0x0d,
        0x39, 0xc5, 0x07, 0x20, 0x87, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3,
        0x2d, 0xb0, 0x80, 0x00, 0x3c, 0x3d, 0x06, 0x26, 0x16, 0xe7, 0x70, 0x04, 0xb9, 0x94, 0xe5, 0x3a,
        0x37, 0xe0, 0x05, 0x9f, 0x45, 0x2c, 0xa7, 0x84, 0x34, 0xa4, 0xd0, 0x8b, 0xf4, 0xbf, 0x02, 0x81,
        0x0f, 0x1d, 0xb8, 0x55, 0xd2, 0x09, 0xd2, 0x50, 0x08, 0x2f, 0xcd, 0x0e, 0xb1, 0x0f, 0x5c, 0x6e,
        0x85, 0x86, 0xdb, 0xab, 0xbd, 0xcc, 0x5d, 0x41, 0x22, 0x3e, 0xdd, 0x14, 0x46, 0x22, 0xe7, 0xa9,
        0xa6, 0x3c, 0x5b, 0x60, 0xf5, 0xcf, 0xbe, 0x2e, 0x06, 0x0a, 0x2e, 0x25, 0x35, 0xf6, 0x3c, 0x02,
        0x0e, 0x90, 0x28, 0x33, 0x00, 0x90, 0x56, 0x82, 0x19, 0x60, 0x0d, 0x0c, 0x2d, 0x8e, 0x10, 0x0d,
        0x25, 0x02, 0x01, 0x09, 0x6e, 0x8b, 0xb6, 0x8b, 0xe4, 0xfb, 0x11, 0x2c, 0xd7, 0x1d, 0x61, 0x0e,
        0x0c, 0x51, 0xda, 0x3d, 0x27, 0x14, 0x75, 0xaa, 0xf1, 0x0d, 0xd2, 0x72, 0x5f, 0x45, 0x59, 0x7a,
        0x7b, 0x17, 0x1a, 0x83, 0x19, 0x16, 0x05, 0x93, 0x00, 0x07, 0x9c, 0x9c, 0xb4, 0x2d, 0x05, 0x07,
        0x50, 0x02, 0x0f, 0x05, 0x0e, 0x03, 0x0d, 0x0b, 0x0e, 0x04, 0x0a, 0x06, 0x0f, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
        0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63,
        0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73,
        0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83,
        0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93,
        0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3,
        0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3,
        0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3,
        0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3,
        0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3,
        0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    ]
    return sbox


SBOX = _get_aes_substitution_table()


def _sub_bytes(state: list) -> list:
    """Apply SubBytes transformation to the state."""
    return [[SBOX[state[i][j]] for j in range(4)] for i in range(4)]


def _shift_rows(state: list) -> list:
    """Apply ShiftRows transformation to the state."""
    # Row 0: no shift
    # Row 1: shift left by 1
    # Row 2: shift left by 2
    # Row 3: shift left by 3
    return [
        state[0][0], state[0][1], state[0][2], state[0][3],
        state[1][1], state[1][2], state[1][3], state[1][0],
        state[2][2], state[2][3], state[2][0], state[2][1],
        state[3][3], state[3][0], state[3][1], state[3][2]
    ]


def _xtime(a: int) -> int:
    """Multiply by 2 in GF(2^8)."""
    return ((a << 1) ^ 0x1B) if a & 0x80 else (a << 1)


def _mix_single_byte(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8)."""
    result = 0
    temp = a
    for i in range(8):
        if b & 1:
            result ^= temp
        hi_bit_set = temp & 0x80
        temp = (temp << 1) & 0xFF
        if hi_bit_set:
            temp ^= 0x1B
        b >>= 1
    return result


def _mix_columns(state: list) -> list:
    """Apply MixColumns transformation to the state."""
    new_state = [0] * 16
    for c in range(4):
        s0 = state[c * 4 + 0]
        s1 = state[c * 4 + 1]
        s2 = state[c * 4 + 2]
        s3 = state[c * 4 + 3]
        
        new_state[c * 4 + 0] = _mix_single_byte(2, s0) ^ _mix_single_byte(3, s1) ^ s2 ^ s3
        new_state[c * 4 + 1] = s0 ^ _mix_single_byte(2, s1) ^ _mix_single_byte(3, s2) ^ s3
        new_state[c * 4 + 2] = s0 ^ s1 ^ _mix_single_byte(2, s2) ^ _mix_single_byte(3, s3)
        new_state[c * 4 + 3] = _mix_single_byte(3, s0) ^ s1 ^ s2 ^ _mix_single_byte(2, s3)
    
    return new_state


def _add_round_key(state: list, round_key: list) -> list:
    """Add Round Key to state."""
    return [state[i] ^ round_key[i] for i in range(16)]


def _key_expansion(key: bytes) -> list:
    """Expand the key into round keys."""
    if len(key) != 32:  # AES-256 requires 256-bit key
        raise ValueError("Key must be 32 bytes for AES-256")
    
    # Convert key to list of integers
    k = list(key)
    
    # Number of 32-bit words needed
    n = 4 * (14 + 1)  # 14 rounds + 1 for initial round
    
    # Extend the key array
    i = len(k)
    while i < n:
        temp = k[i-1:i]
        if i % 32 == 0:  # Every 32 bytes (8 words)
            temp = temp[1:] + [k[i-32]]  # RotWord
            temp = [SBOX[b] for b in temp]  # SubWord
            temp[0] ^= [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80][i // 32 - 1]
        elif i % 32 == 24:  # For AES-256, every 24th word gets SubWord
            temp = [SBOX[b] for b in temp]
        
        k.append(k[i - 32] ^ temp[0])
        k.append(k[i - 31] ^ temp[1])
        k.append(k[i - 30] ^ temp[2])
        k.append(k[i - 29] ^ temp[3])
        i += 4
    
    # Split into round keys (each 16 bytes)
    round_keys = []
    for r in range(15):  # 15 round keys for 14 rounds + initial
        start = r * 16
        end = start + 16
        round_keys.append(k[start:end])
    
    return round_keys


def _aes_encrypt_block(block: bytes, round_keys: list) -> bytes:
    """Encrypt a single 16-byte block using AES-256."""
    if len(block) != 16:
        raise ValueError("Block must be 16 bytes")
    
    # Convert block to state matrix (column-major order)
    state = [0] * 16
    for i in range(4):
        for j in range(4):
            state[j * 4 + i] = block[i * 4 + j]
    
    # Initial AddRoundKey
    state = _add_round_key(state, round_keys[0])
    
    # Main rounds
    for r in range(1, 14):
        state = _sub_bytes([state[i*4:(i+1)*4] for i in range(4)])
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[r])
    
    # Final round (no MixColumns)
    state = _sub_bytes([state[i*4:(i+1)*4] for i in range(4)])
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[14])
    
    # Convert state back to bytes (column-major order)
    result = [0] * 16
    for i in range(4):
        for j in range(4):
            result[i * 4 + j] = state[j * 4 + i]
    
    return bytes(result)


def _ghash(h: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """Compute GHASH function for GCM mode."""
    # Pad AAD and ciphertext to multiple of 16 bytes
    def pad_to_16(data: bytes) -> bytes:
        if len(data) % 16 == 0:
            return data
        return data + b'\x00' * (16 - (len(data) % 16))
    
    padded_aad = pad_to_16(aad)
    padded_ct = pad_to_16(ciphertext)
    
    # Append length information (64 bits for AAD length, 64 bits for CT length)
    len_aad = len(aad) * 8
    len_ct = len(ciphertext) * 8
    
    # Combine all parts
    combined = padded_aad + padded_ct + len_aad.to_bytes(8, 'big') + len_ct.to_bytes(8, 'big')
    
    # Initialize H (the hash key)
    y = b'\x00' * 16
    
    # Process each 16-byte block
    for i in range(0, len(combined), 16):
        block = combined[i:i+16]
        y = _xor_bytes(y, block)
        y = _gmul(y, h)
    
    return y


def _gmul(a: bytes, b: bytes) -> bytes:
    """Multiply two elements in GF(2^128) with the GCM polynomial."""
    # R = 0xE1000000000000000000000000000000 (GCM polynomial)
    R = 0xE1000000000000000000000000000000
    
    # Convert to integers
    a_int = int.from_bytes(a, 'big')
    b_int = int.from_bytes(b, 'big')
    
    # Initialize result
    result = 0
    
    # Multiply using binary method
    for i in range(128):
        if (b_int >> (127 - i)) & 1:
            result ^= a_int
        
        # Check if MSB is set before shifting
        if a_int & (1 << 127):
            a_int = (a_int << 1) ^ R
        else:
            a_int <<= 1
            a_int &= (1 << 128) - 1  # Keep it 128 bits
    
    return result.to_bytes(16, 'big')


def _counter_mode(key: bytes, nonce: bytes, data: bytes) -> tuple:
    """Perform CTR mode encryption/decryption."""
    # Generate round keys
    round_keys = _key_expansion(key)
    
    # Initial counter block
    counter_block = bytearray(nonce + b'\x00\x00\x00\x01')
    
    # Encrypt counter blocks
    ciphertext = bytearray()
    num_blocks = (len(data) + 15) // 16
    
    for i in range(num_blocks):
        # Encrypt current counter block
        keystream_block = _aes_encrypt_block(bytes(counter_block), round_keys)
        
        # XOR with data
        start = i * 16
        end = min(start + 16, len(data))
        
        for j in range(start, end):
            ciphertext.append(data[j] ^ keystream_block[j - start])
        
        # Increment counter
        _increment_counter(counter_block)
    
    return bytes(ciphertext)


def _compute_tag(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """Compute the authentication tag for GCM mode."""
    # Generate round keys
    round_keys = _key_expansion(key)
    
    # Encrypt the initial counter block (J0)
    # For normal nonces, J0 = nonce || 0x00000000
    # For special 96-bit nonces, J0 = nonce || 0x00000001
    if len(nonce) == 12:
        j0 = nonce + b'\x00\x00\x00\x01'
    else:
        # For other nonce lengths, compute GHASH(nonce)
        j0 = _ghash(_aes_encrypt_block(b'\x00' * 16, round_keys), nonce, b'')
    
    # Compute GHASH
    h = _aes_encrypt_block(bytes(round_keys[0]), round_keys)  # H = E(K, 0)
    
    # Get Y0 from J0
    y0 = _aes_encrypt_block(j0, round_keys)
    
    # Compute GHASH
    ghash_result = _ghash(h, aad, ciphertext)
    
    # Tag = Y0 ⊕ GHASH
    tag = _xor_bytes(y0, ghash_result)
    
    return tag


def _verify_tag(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes) -> bool:
    """Verify the authentication tag."""
    expected_tag = _compute_tag(key, nonce, aad, ciphertext)
    return hmac.compare_digest(expected_tag, tag)


def derive_key(password: str, salt: bytes = None, iterations: int = 100000) -> tuple:
    """
    Derive a 256-bit key from a password using PBKDF2-HMAC-SHA256.
    
    Args:
        password: The password string
        salt: Optional salt bytes (generated if None)
        iterations: Number of PBKDF2 iterations (default 100,000)
    
    Returns:
        Tuple of (derived_key, salt)
    """
    if salt is None:
        salt = os.urandom(16)
    
    derived_key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations,
        dklen=32  # 256 bits
    )
    
    return derived_key, salt


def encrypt_payload(payload: bytes, password: str, aad: bytes = None) -> dict:
    """
    Encrypt a payload using AES-256-GCM.
    
    Args:
        payload: The data to encrypt
        password: The password to derive the key from
        aad: Additional Associated Data (optional)
    
    Returns:
        Dictionary containing:
        - 'nonce': The random nonce used (12 bytes)
        - 'salt': The salt used for key derivation (16 bytes)
        - 'tag': The authentication tag (16 bytes)
        - 'ciphertext': The encrypted data
        - 'aad': The additional associated data used
    """
    if aad is None:
        aad = b''
    
    # Derive key
    key, salt = derive_key(password)
    
    # Generate random nonce (12 bytes is standard for GCM)
    nonce = os.urandom(12)
    
    # Encrypt using CTR mode
    ciphertext = _counter_mode(key, nonce, payload)
    
    # Compute authentication tag
    tag = _compute_tag(key, nonce, aad, ciphertext)
    
    return {
        'nonce': nonce,
        'salt': salt,
        'tag': tag,
        'ciphertext': ciphertext,
        'aad': aad
    }


def decrypt_payload(encrypted_data: dict, password: str) -> bytes:
    """
    Decrypt a payload encrypted with AES-256-GCM.
    
    Args:
        encrypted_data: Dictionary from encrypt_payload
        password: The password used for encryption
    
    Returns:
        The decrypted plaintext
    
    Raises:
        AuthenticationError: If the tag verification fails
        InvalidNonceError: If the nonce is invalid
        KeyError: If required fields are missing
    """
    # Validate required fields
    required_fields = ['nonce', 'salt', 'tag', 'ciphertext']
    for field in required_fields:
        if field not in encrypted_data:
            raise KeyError(f"Missing required field: {field}")
    
    nonce = encrypted_data['nonce']
    salt = encrypted_data['salt']
    tag = encrypted_data['tag']
    ciphertext = encrypted_data['ciphertext']
    aad = encrypted_data.get('aad', b'')
    
    # Validate nonce length
    if len(nonce) != 12:
        raise InvalidNonceError(f"Nonce must be 12 bytes, got {len(nonce)} bytes")
    
    # Derive key
    key, _ = derive_key(password, salt)
    
    # Verify authentication tag
    if not _verify_tag(key, nonce, aad, ciphertext, tag):
        raise AuthenticationError("Authentication failed: tag mismatch")
    
    # Decrypt using CTR mode
    plaintext = _counter_mode(key, nonce, ciphertext)
    
    return plaintext


def obfuscate_payload(payload: str, password: str, aad: str = None) -> str:
    """
    Obfuscate a string payload using AES-256-GCM.
    
    Args:
        payload: The string to obfuscate
        password: The password to derive the key from
        aad: Additional Associated Data (optional)
    
    Returns:
        Base64-encoded string containing the encrypted payload and metadata
    """
    import base64
    
    # Encode inputs
    payload_bytes = payload.encode('utf-8')
    aad_bytes = aad.encode('utf-8') if aad else None
    
    # Encrypt
    encrypted_data = encrypt_payload(payload_bytes, password, aad_bytes)
    
    # Create a serializable format
    output_data = {
        'nonce': base64.b64encode(encrypted_data['nonce']).decode('ascii'),
        'salt': base64.b64encode(encrypted_data['salt']).decode('ascii'),
        'tag': base64.b64encode(encrypted_data['tag']).decode('ascii'),
        'ciphertext': base64.b64encode(encrypted_data['ciphertext']).decode('ascii'),
        'aad': base64.b64encode(encrypted_data['aad']).decode('ascii') if encrypted_data['aad'] else ''
    }
    
    # Return as a single base64-encoded JSON string
    import json
    return base64.b64encode(json.dumps(output_data).encode('utf-8')).decode('ascii')


def deobfuscate_payload(obfuscated_data: str, password: str) -> str:
    """
    Deobfuscate a string payload encrypted with AES-256-GCM.
    
    Args:
        obfuscated_data: The base64-encoded encrypted data
        password: The password used for encryption
    
    Returns:
        The decrypted plaintext string
    
    Raises:
        AuthenticationError: If the tag verification fails
        InvalidNonceError: If the nonce is invalid
        json.JSONDecodeError: If the data format is invalid
    """
    import base64
    import json
    
    # Decode the obfuscated data
    try:
        decoded = base64.b64decode(obfuscated_data)
        encrypted_data = json.loads(decoded.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"Invalid obfuscated data format: {e}")
    
    # Convert base64 fields back to bytes
    converted_data = {
        'nonce': base64.b64decode(encrypted_data['nonce']),
        'salt': base64.b64decode(encrypted_data['salt']),
        'tag': base64.b64decode(encrypted_data['tag']),
        'ciphertext': base64.b64decode(encrypted_data['ciphertext']),
        'aad': base64.b64decode(encrypted_data['aad']) if encrypted_data.get('aad') else b''
    }
    
    # Decrypt
    plaintext_bytes = decrypt_payload(converted_data, password)
    
    return plaintext_bytes.decode('utf-8')


# Convenience functions for quick usage
def quick_encrypt(data: str, password: str) -> str:
    """Quick one-liner encryption."""
    return obfuscate_payload(data, password)


def quick_decrypt(encoded: str, password: str) -> str:
    """Quick one-liner decryption."""
    return deobfuscate_payload(encoded, password)


if __name__ == "__main__":
    # Test the implementation
    print("Testing AES-256-GCM Implementation...")
    
    # Test 1: Basic encryption/decryption
    original_text = "Hello, World! This is a test payload for AES-256-GCM."
    password = "my_secure_password_123"
    
    print(f"\nOriginal text: {original_text}")
    
    # Encrypt
    encrypted = quick_encrypt(original_text, password)
    print(f"Encrypted (base64): {encrypted[:50]}...")
    
    # Decrypt
    decrypted = quick_decrypt(encrypted, password)
    print(f"Decrypted text: {decrypted}")
    
    assert original_text == decrypted, "Decryption failed!"
    print("✓ Basic encryption/decryption test passed!")
    
    # Test 2: Wrong password should fail
    try:
        wrong_decrypted = quick_decrypt(encrypted, "wrong_password")
        print(f"✗ Wrong password test failed: {wrong_decrypted}")
    except AuthenticationError:
        print("✓ Wrong password test passed!")
    
    # Test 3: With AAD
    aad_text = "additional_associated_data"
    encrypted_with_aad = obfuscate_payload(original_text, password, aad_text)
    decrypted_with_aad = deobfuscate_payload(encrypted_with_aad, password)
    assert original_text == decrypted_with_aad, "AAD decryption failed!"
    print("✓ AAD encryption/decryption test passed!")
    
    # Test 4: Tampered ciphertext should fail
    import base64
    import json
    
    # Decode the encrypted data
    decoded = base64.b64decode(encrypted_with_aad)
    encrypted_dict = json.loads(decoded.decode('utf-8'))
    
    # Tamper with ciphertext
    ct_bytes = base64.b64decode(encrypted_dict['ciphertext'])
    tampered_ct = bytearray(ct_bytes)
    tampered_ct[0] ^= 0xFF  # Flip first bit
    encrypted_dict['ciphertext'] = base64.b64encode(bytes(tampered_ct)).decode('ascii')
    
    # Re-encode
    tampered_json = json.dumps(encrypted_dict).encode('utf-8')
    tampered_encoded = base64.b64encode(tampered_json).decode('ascii')
    
    try:
        tampered_decrypted = deobfuscate_payload(tampered_encoded, password)
        print(f"✗ Tampering test failed: {tampered_decrypted}")
    except AuthenticationError:
        print("✓ Tampering detection test passed!")
    
    print("\nAll tests passed! ✅")
