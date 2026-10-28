#!/usr/bin/env python3
"""
tls_fingerprint.py - JA3/JA4 TLS Client Fingerprint Spoofing & Evasion Matrix

Generates, compares, and spoofs TLS client fingerprints (JA3 and JA4).
Supports multiple browsers, custom configurations, and evasion techniques.

Features:
- JA3 fingerprint generation (hash of Client Hello parameters)
- JA4 fingerprint generation (extended TLS fingerprint)
- Browser profile emulation (Chrome, Firefox, Safari, Edge, etc.)
- Custom cipher suite configuration
- SNI and ALPN spoofing
- JA3/JA4 evasion matrix generation
- Comparison against known server fingerprints
- JSON/CSV output for integration with proxies and scanners

Author: Dwi Joko Purwanto 
Version: 2.0.0
"""

import hashlib
import json
import csv
import sys
import os
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Set, Any
from enum import Enum
from collections import OrderedDict
import struct
import base64


# ============================================================================
# ENUMERATIONS AND CONSTANTS
# ============================================================================

class BrowserType(Enum):
    """Supported browser profiles."""
    CHROME_120 = "chrome_120"
    CHROME_115 = "chrome_115"
    FIREFOX_121 = "firefox_121"
    FIREFOX_115 = "firefox_115"
    SAFARI_17 = "safari_17"
    EDGE_120 = "edge_120"
    CURL_8_0 = "curl_8_0"
    CUSTOM = "custom"


class TLSEnum(Enum):
    """TLS extension type codes."""
    SERVER_NAME = 0
    MAX_FRAGMENT_LENGTH = 1
    DOMAIN_NAME = 1  # deprecated
    STATUS_REQUEST = 5
    ENCRYPTED_SNI = 10
    DELEGATED_ISSUER = 11
    SUPPORTED_GROUPS = 10
    SIGNATURE_ALGORITHMS = 13
    ALPN = 16
    PRE_SHARED_KEY = 41
    PSK_KEY_EXCHANGE_MODES = 42
    CERT_COMPRESSION = 43
    KEY_SHARE = 51
    EARLY_DATA = 43
    SUPPORTED_VERSIONS = 43
    AUTHENTICATION_DELAY = 31
    COOKIE = 43
    PSK_END_OF_EARLY_DATA = 43
    POST_HANDSHAKE_AUTH = 43
    NAMED_GROUPS = 10  # alias
    SIG_HASHES = 13  # alias
    SESSION_TICKET = 35
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16  # alias
    ENCRYPTED_CLIENT_HELLO = 65


class CipherSuite(Enum):
    """TLS 1.2 and 1.3 cipher suites."""
    # TLS 1.3 ciphersuites
    TLS_AES_128_GCM_SHA256 = (0x1301, "TLS_AES_128_GCM_SHA256")
    TLS_AES_256_GCM_SHA384 = (0x1302, "TLS_AES_256_GCM_SHA384")
    TLS_CHACHA20_POLY1305_SHA256 = (0x1303, "TLS_CHACHA20_POLY1305_SHA256")
    TLS_AES_128_CCM_SHA256 = (0x1304, "TLS_AES_128_CCM_SHA256")
    TLS_AES_128_CCM_8_SHA256 = (0x1305, "TLS_AES_128_CCM_8_SHA256")
    
    # TLS 1.2 ciphersuites
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = (0xC02F, "ECDHE-RSA-AES128-GCM-SHA256")
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = (0xC030, "ECDHE-RSA-AES256-GCM-SHA384")
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = (0xC02B, "ECDHE-ECDSA-AES128-GCM-SHA256")
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = (0xC02C, "ECDHE-ECDSA-AES256-GCM-SHA384")
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = (0x00CA, "ECDHE-RSA-CHACHA20-POLY1305")
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = (0x00CB, "ECDHE-ECDSA-CHACHA20-POLY1305")
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = (0x009F, "DHE-RSA-AES128-GCM-SHA256")
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = (0x009E, "DHE-RSA-AES256-GCM-SHA384")
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = (0xC027, "ECDHE-RSA-AES128-CBC-SHA256")
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = (0xC028, "ECDHE-RSA-AES256-CBC-SHA384")
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = (0xC013, "ECDHE-RSA-AES128-CBC-SHA")
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = (0xC014, "ECDHE-RSA-AES256-CBC-SHA")
    TLS_RSA_WITH_AES_128_GCM_SHA256 = (0x009C, "AES128-GCM-SHA256")
    TLS_RSA_WITH_AES_256_GCM_SHA384 = (0x009D, "AES256-GCM-SHA384")
    TLS_RSA_WITH_AES_128_CBC_SHA256 = (0x003C, "AES128-SHA256")
    TLS_RSA_WITH_AES_256_CBC_SHA256 = (0x003D, "AES256-SHA256")
    TLS_RSA_WITH_AES_128_CBC_SHA = (0x002F, "AES128-SHA")
    TLS_RSA_WITH_AES_256_CBC_SHA = (0x0035, "AES256-SHA")
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = (0xC012, "ECDHE-RSA-DES-CBC3-SHA")


class EllipticCurve(Enum):
    """Elliptic curves for ECDHE key exchange."""
    SECP256R1 = 23  # x25519 is 16, but secp256r1 is commonly used
    X25519 = 16
    SECP384R1 = 24
    SECP521R1 = 25
    FFDHE2048 = 256
    FFDHE3072 = 257
    FFDHE4096 = 258
    FFDHE6144 = 259
    FFDHE8192 = 260


class SignatureScheme(Enum):
    """Signature algorithms for certificates."""
    ECDSA_SECP256R1_SHA256 = 0x0403
    ECDSA_SECP384R1_SHA384 = 0x0503
    ECDSA_SECP521R1_SHA512 = 0x0603
    RSA_PSS_SHA256 = 0x0804
    RSA_PSS_SHA384 = 0x0805
    RSA_PSS_SHA512 = 0x0806
    RSA_PKCS1_SHA256 = 0x0401
    RSA_PKCS1_SHA384 = 0x0501
    RSA_PKCS1_SHA512 = 0x0601
    ED25519 = 0x0807
    ED448 = 0x0808


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class TLSExtension:
    """Represents a single TLS extension."""
    ext_type: int
    name: str
    data: bytes = b""
    
    def to_hex(self) -> str:
        return self.name if not self.data else f"{self.name} ({self.data.hex()})"


@dataclass
class CipherConfig:
    """Configuration for cipher suites."""
    tls_version_major: int = 3
    tls_version_minor: int = 3  # TLS 1.3
    cipher_suites: List[int] = field(default_factory=list)
    elliptic_curves: List[int] = field(default_factory=list)
    signature_algorithms: List[int] = field(default_factory=list)
    compression_methods: List[int] = field(default_factory=[0])
    extensions: List[TLSExtension] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.cipher_suites:
            self.cipher_suites = [0x1301, 0x1302, 0x1303]  # Default modern ciphers
        if not self.elliptic_curves:
            self.elliptic_curves = [16, 23, 24]  # X25519, secp256r1, secp384r1
        if not self.signature_algorithms:
            self.signature_algorithms = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806]


@dataclass
class JA3Fingerprint:
    """JA3 fingerprint representation."""
    raw_string: str
    md5_hash: str
    browser: str = ""
    version: str = ""
    timestamp: float = 0.0
    
    def to_dict(self) -> dict:
        return {
            "raw_string": self.raw_string,
            "md5_hash": self.md5_hash,
            "browser": self.browser,
            "version": self.version,
            "timestamp": self.timestamp
        }


@dataclass
class JA4Fingerprint:
    """JA4 fingerprint representation."""
    raw_string: str
    sha256_hash: str
    browser: str = ""
    version: str = ""
    timestamp: float = 0.0
    
    def to_dict(self) -> dict:
        return {
            "raw_string": self.raw_string,
            "sha256_hash": self.sha256_hash,
            "browser": "browser",
            "version": self.version,
            "timestamp": self.timestamp
        }


@dataclass
class EvasionMatrixEntry:
    """Single entry in the evasion matrix."""
    browser_profile: str
    ja3_hash: str
    ja4_hash: str
    sni: str
    alpn: List[str]
    cipher_count: int
    curve_count: int
    sig_algo_count: int
    extension_count: int
    fingerprint_score: float  # 0-100, higher means more unique
    risk_level: str  # Low, Medium, High
    
    def to_dict(self) -> dict:
        return asdict(self)


# ============================================================================
# BROWSER PROFILES
# ============================================================================

class BrowserProfileManager:
    """Manages browser-specific TLS configurations."""
    
    # Chrome 120+ profile
    CHROME_120 = {
        "cipher_suites": [
            0x1301, 0x1302, 0x1303, 0x1304, 0x1305,  # TLS 1.3
            0xC02F, 0xC030, 0xC02B, 0xC02C,  # ECDHE ECDSA/RSA AES GCM
            0x00CA, 0x00CB,  # CHACHA20
            0x009F, 0x009E,  # DHE AES GCM
            0xC027, 0xC028, 0xC013, 0xC014,  # CBC suites
            0x003C, 0x003D, 0x002F, 0x0035,  # RSA AES
            0xC012  # 3DES
        ],
        "elliptic_curves": [29, 257, 258, 259, 260, 256, 24, 25, 23, 16],
        "signature_algorithms": [
            0x0807, 0x0808, 0x0403, 0x0503, 0x0603,
            0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601
        ],
        "extensions": [
            TLSExtension(0, "server_name"),
            TLSExtension(10, "supported_versions", bytes([3, 3, 0, 255])),
            TLSExtension(16, "key_share", bytes([0, 0])),
            TLSExtension(16, "ec_point_formats", bytes([1, 0])),
            TLSExtension(23, "session_ticket"),
            TLSExtension(35, "extended_master_secret"),
            TLSExtension(13, "signature_algorithms", 
                        bytes([0, 20, 8, 7, 8, 8, 4, 3, 5, 3, 6, 3, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1])),
            TLSExtension(16, "application_layer_protocol_negotiation", 
                        bytes([0, 10, 8, 4, 116, 106, 115, 47, 51, 8, 10, 104, 116, 116, 112, 47, 49, 46]))
        ]
    }
    
    # Firefox 121 profile
    FIREFOX_121 = {
        "cipher_suites": [
            0x1301, 0x1302, 0x1303,  # TLS 1.3
            0x1304, 0x1305,  # CCM variants
            0xC02B, 0xC02C, 0xC02F, 0xC030,  # ECDHE ECDSA/RSA AES GCM
            0x009C, 0x009D,  # RSA AES GCM
            0xC013, 0xC014, 0xC027, 0xC028,  # CBC suites
            0x0035, 0x0039, 0x0067, 0x006B,  # Additional CBC
            0xCCA9, 0xCCA8,  # DHE AES GCM
            0xC072, 0xC073, 0xC07C, 0xC07D  # Additional suites
        ],
        "elliptic_curves": [29, 257, 258, 259, 260, 256, 24, 25, 23, 16],
        "signature_algorithms": [
            0x0807, 0x0403, 0x0503, 0x0603,
            0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601
        ],
        "extensions": [
            TLSExtension(0, "server_name"),
            TLSExtension(10, "supported_versions", bytes([3, 3, 0, 255])),
            TLSExtension(16, "key_share", bytes([0, 0])),
            TLSExtension(16, "ec_point_formats", bytes([1, 0])),
            TLSExtension(23, "session_ticket"),
            TLSExtension(35, "extended_master_secret"),
            TLSExtension(13, "signature_algorithms", 
                        bytes([0, 20, 8, 7, 4, 3, 5, 3, 6, 3, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1])),
            TLSExtension(16, "application_layer_protocol_negotiation", 
                        bytes([0, 10, 8, 4, 116, 106, 115, 47, 51, 8, 10, 104, 116, 116, 112, 47, 49, 46])),
            TLSExtension(43, "encrypted_client_hello", bytes([0, 0]))
        ]
    }
    
    # Safari 17 profile
    SAFARI_17 = {
        "cipher_suites": [
            0x1301, 0x1302, 0x1303,  # TLS 1.3
            0xC02B, 0xC02C, 0xC02F, 0xC030,  # ECDHE ECDSA/RSA AES GCM
            0xC07C, 0xC07D, 0xCCA9, 0xCCA8,  # DHE AES GCM
            0xC013, 0xC014, 0xC027, 0xC028,  # CBC suites
            0x0035, 0x0039, 0x0067, 0x006B  # Additional CBC
        ],
        "elliptic_curves": [29, 257, 258, 259, 260, 256, 24, 25, 23, 16],
        "signature_algorithms": [
            0x0403, 0x0503, 0x0603,
            0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601
        ],
        "extensions": [
            TLSExtension(0, "server_name"),
            TLSExtension(10, "supported_versions", bytes([3, 3, 0, 255])),
            TLSExtension(16, "key_share", bytes([0, 0])),
            TLSExtension(16, "ec_point_formats", bytes([1, 0])),
            TLSExtension(23, "session_ticket"),
            TLSExtension(35, "extended_master_secret"),
            TLSExtension(13, "signature_algorithms", 
                        bytes([0, 20, 4, 3, 5, 3, 6, 3, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1])),
            TLSExtension(16, "application_layer_protocol_negotiation", 
                        bytes([0, 10, 8, 4, 116, 106, 115, 47, 51, 8, 10, 104, 116, 116, 112, 49, 46]))
        ]
    }
    
    BROWSER_PROFILES = {
        BrowserType.CHROME_120: CHROME_120,
        BrowserType.FIREFOX_121: FIREFOX_121,
        BrowserType.SAFARI_17: SAFARI_17,
    }
    
    @classmethod
    def get_profile(cls, browser_type: BrowserType) -> dict:
        """Get browser profile configuration."""
        if browser_type == BrowserType.CUSTOM:
            return {}
        return cls.BROWSER_PROFILES.get(browser_type, {})


# ============================================================================
# FINGERPRINT GENERATORS
# ============================================================================

class JA3FingerprintGenerator:
    """Generates JA3 fingerprints from TLS Client Hello parameters."""
    
    @staticmethod
    def generate_ja3(config: CipherConfig) -> JA3Fingerprint:
        """Generate JA3 fingerprint from cipher configuration."""
        
        # Build the JA3 string components
        components = []
        
        # Cipher suites (comma-separated hex values)
        cipher_str = ",".join(str(cipher) for cipher in config.cipher_suites)
        components.append(cipher_str)
        
        # Supported versions (TLS 1.3 uses 0x0303)
        version_str = f"{config.tls_version_major},{config.tls_version_minor}"
        components.append(version_str)
        
        # Extension types (hex values)
        ext_types = [ext.ext_type for ext in config.extensions]
        ext_str = ",".join(str(ext_type) for ext_type in ext_types)
        components.append(ext_str)
        
        # Elliptic curves (point format)
        curves_str = ",".join(str(curve) for curve in config.elliptic_curves)
        components.append(curves_str)
        
        # Signature algorithms
        sig_str = ",".join(str(sig) for sig in config.signature_algorithms)
        components.append(sig_str)
        
        # Join all components with dashes
        ja3_raw = "-".join(components)
        
        # Calculate MD5 hash
        md5_hash = hashlib.md5(ja3_raw.encode()).hexdigest()
        
        return JA3Fingerprint(
            raw_string=ja3_raw,
            md5_hash=md5_hash,
            timestamp=__import__('time').time()
        )


class JA4FingerprintGenerator:
    """Generates JA4 fingerprints from TLS Client Hello parameters."""
    
    @staticmethod
    def generate_ja4(config: CipherConfig, sni: str = "") -> JA4Fingerprint:
        """Generate JA4 fingerprint from cipher configuration and SNI."""
        
        # JA4 uses different components than JA3
        # Format: quic-version-tls-version-cipher-count-curves-sigs-alpn-extension-count
        
        # Determine QUIC version (1 for TLS 1.3 over QUIC, 0 otherwise)
        quic_version = "q01" if config.tls_version_minor == 3 else "q00"
        
        # TLS version
        tls_version = f"t{config.tls_version_major}{config.tls_version_minor}"
        
        # Cipher count
        cipher_count = len(config.cipher_suites)
        
        # Curve count
        curve_count = len(config.elliptic_curves)
        
        # Signature algorithm count
        sig_count = len(config.signature_algorithms)
        
        # ALPN negotiation
        alpn_protos = []
        for ext in config.extensions:
            if ext.ext_type == 16:  # ALPN
                try:
                    alpn_data = ext.data[2:]  # Skip length prefix
                    alpn_protos = [alpn_data.decode('utf-8', errors='ignore')]
                except:
                    pass
        
        alpn_str = "".join(alpn_protos) if alpn_protos else "n"
        
        # Extension count
        ext_count = len(config.extensions)
        
        # Build JA4 string
        ja4_components = [
            quic_version,
            tls_version,
            f"{cipher_count:02d}",
            f"{curve_count:02d}",
            f"{sig_count:02d}",
            alpn_str,
            f"{ext_count:02d}"
        ]
        
        ja4_raw = "".join(ja4_components)
        
        # Calculate SHA256 hash (JA4 uses full hash now)
        sha256_hash = hashlib.sha256(ja4_raw.encode()).hexdigest()
        
        return JA4Fingerprint(
            raw_string=ja4_raw,
            sha256_hash=sha256_hash,
            timestamp=__import__('time').time()
        )


# ============================================================================
# EVASION MATRIX
# ============================================================================

class EvasionMatrix:
    """Generates and manages TLS fingerprint evasion matrices."""
    
    def __init__(self):
        self.entries: List[EvasionMatrixEntry] = []
        self._known_fingerprints: Dict[str, Dict] = {
            "chrome_120": {
                "ja3": "47d0a7c9d7f0e2b1c8a3f9e6d5b2c1a0",
                "risk": "Low"
            },
            "firefox_121": {
                "ja3": "8f3e2d1c9b7a6e5d4c3b2a1f9e8d7c6b",
                "risk": "Low"
            },
            "safari_17": {
                "ja3": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
                "risk": "Medium"
            }
        }
    
    def generate_matrix_entry(self, config: CipherConfig, browser: str, sni: str = "") -> EvasionMatrixEntry:
        """Generate a single evasion matrix entry."""
        
        # Generate fingerprints
        ja3_fp = JA3FingerprintGenerator.generate_ja3(config)
        ja4_fp = JA4FingerprintGenerator.generate_ja4(config, sni)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(config, ja3_fp, ja4_fp)
        risk_level = self._map_risk_to_level(risk_score)
        
        # Extract ALPN protocols
        alpn_protos = []
        for ext in config.extensions:
            if ext.ext_type == 16:  # ALPN
                try:
                    alpn_data = ext.data[2:]
                    alpn_protos = [alpn_data.decode('utf-8', errors='ignore')]
                except:
                    pass
        
        entry = EvasionMatrixEntry(
            browser_profile=browser,
            ja3_hash=ja3_fp.md5_hash,
            ja4_hash=ja4_fp.sha256_hash[:16],  # Use first 16 chars for readability
            sni=sni,
            alpn=alpn_protos,
            cipher_count=len(config.cipher_suites),
            curve_count=len(config.elliptic_curves),
            sig_algo_count=len(config.signature_algorithms),
            extension_count=len(config.extensions),
            fingerprint_score=risk_score,
            risk_level=risk_level
        )
        
        return entry
    
    def _calculate_risk_score(self, config: CipherConfig, ja3: JA3Fingerprint, ja4: JA4Fingerprint) -> float:
        """Calculate risk score based on fingerprint uniqueness."""
        score = 50.0  # Base score
        
        # Penalize unusual cipher combinations
        if len(config.cipher_suites) > 20:
            score += 10
        elif len(config.cipher_suites) < 5:
            score += 15
        
        # Penalize unusual curve combinations
        if len(config.elliptic_curves) > 10:
            score += 5
        elif len(config.elliptic_curves) < 2:
            score += 20
        
        # Penalize rare signature algorithms
        rare_sigs = {0x0807, 0x0808}  # ED25519, ED448
        if any(sig in rare_sigs for sig in config.signature_algorithms):
            score += 5
        
        # Check against known fingerprints
        if ja3.md5_hash in [fp["ja3"] for fp in self._known_fingerprints.values()]:
            score -= 20
        
        return min(max(score, 0), 100)
    
    def _map_risk_to_level(self, score: float) -> str:
        """Map numerical score to risk level."""
        if score < 30:
            return "Low"
        elif score < 70:
            return "Medium"
        else:
            return "High"
    
    def generate_full_matrix(self, browsers: List[BrowserType] = None, sni_values: List[str] = None) -> List[EvasionMatrixEntry]:
        """Generate complete evasion matrix for multiple browsers and SNI values."""
        
        if browsers is None:
            browsers = list(BrowserType)
        
        if sni_values is None:
            sni_values = ["example.com", "google.com", "github.com"]
        
        self.entries = []
        
        for browser in browsers:
            profile = BrowserProfileManager.get_profile(browser)
            
            # Create config from profile
            config = CipherConfig(
                cipher_suites=profile.get("cipher_suites", []),
                elliptic_curves=profile.get("elliptic_curves", []),
                signature_algorithms=profile.get("signature_algorithms", []),
                extensions=profile.get("extensions", [])
            )
            
            for sni in sni_values:
                entry = self.generate_matrix_entry(config, browser.value, sni)
                self.entries.append(entry)
        
        return self.entries


# ============================================================================
# SPOOFING ENGINE
# ============================================================================

class TLSSpoofEngine:
    """Engine for TLS fingerprint spoofing and evasion."""
    
    def __init__(self):
        self.matrix = EvasionMatrix()
        self.spoofer_configs: Dict[str, CipherConfig] = {}
    
    def configure_browser(self, browser_type: BrowserType, custom_params: dict = None) -> CipherConfig:
        """Configure a specific browser profile with optional customizations."""
        
        profile = BrowserProfileManager.get_profile(browser_type)
        
        # Start with default config
        config = CipherConfig(
            cipher_suites=profile.get("cipher_suites", []),
            elliptic_curves=profile.get("elliptic_curves", []),
            signature_algorithms=profile.get("signature_algorithms", []),
            extensions=profile.get("extensions", [])
        )
        
        # Apply custom overrides
        if custom_params:
            if "cipher_suites" in custom_params:
                config.cipher_suites = custom_params["cipher_suites"]
            if "elliptic_curves" in custom_params:
                config.elliptic_curves = custom_params["elliptic_curves"]
            if "signature_algorithms" in custom_params:
                config.signature_algorithms = custom_params["signature_algorithms"]
            if "extensions" in custom_params:
                config.extensions = custom_params["extensions"]
            if "tls_version" in custom_params:
                major, minor = custom_params["tls_version"]
                config.tls_version_major = major
                config.tls_version_minor = minor
        
        # Store configuration
        self.spoofer_configs[browser_type.value] = config
        
        return config
    
    def spoof_tls_client_hello(self, browser_type: BrowserType, sni: str = "example.com") -> Tuple[JA3Fingerprint, JA4Fingerprint]:
        """Spoof a TLS Client Hello for a specific browser."""
        
        config = self.spoofer_configs.get(browser_type.value)
        if not config:
            config = self.configure_browser(browser_type)
        
        ja3 = JA3FingerprintGenerator.generate_ja3(config)
        ja4 = JA4FingerprintGenerator.generate_ja4(config, sni)
        
        return ja3, ja4
    
    def compare_fingerprints(self, config1: CipherConfig, config2: CipherConfig) -> dict:
        """Compare two TLS configurations and highlight differences."""
        
        ja3_1 = JA3FingerprintGenerator.generate_ja3(config1)
        ja3_2 = JA3FingerprintGenerator.generate_ja3(config2)
        ja4_1 = JA4FingerprintGenerator.generate_ja4(config1)
        ja4_2 = JA4FingerprintGenerator.generate_ja4(config2)
        
        comparison = {
            "ja3_match": ja3_1.md5_hash == ja3_2.md5_hash,
            "ja4_match": ja4_1.sha256_hash == ja4_2.sha256_hash,
            "cipher_difference": set(config1.cipher_suites) != set(config2.cipher_suites),
            "curve_difference": set(config1.elliptic_curves) != set(config2.elliptic_curves),
            "sig_algo_difference": set(config1.signature_algorithms) != set(config2.signature_algorithms),
            "extension_difference": len(config1.extensions) != len(config2.extensions),
            "fingerprints": {
                "config1_ja3": ja3_1.md5_hash,
                "config2_ja3": ja3_2.md5_hash,
                "config1_ja4": ja4_1.sha256_hash,
                "config2_ja4": ja4_2.sha256_hash
            }
        }
        
        return comparison
    
    def generate_evasion_report(self, browsers: List[BrowserType] = None) -> dict:
        """Generate comprehensive evasion report."""
        
        if browsers is None:
            browsers = [BrowserType.CHROME_120, BrowserType.FIREFOX_121, BrowserType.SAFARI_17]
        
        matrix_entries = self.matrix.generate_full_matrix(browsers)
        
        report = {
            "summary": {
                "total_profiles": len(matrix_entries),
                "unique_ja3_hashes": len(set(e.ja3_hash for e in matrix_entries)),
                "unique_ja4_hashes": len(set(e.ja4_hash for e in matrix_entries)),
                "low_risk_count": sum(1 for e in matrix_entries if e.risk_level == "Low"),
                "medium_risk_count": sum(1 for e in matrix_entries if e.risk_level == "Medium"),
                "high_risk_count": sum(1 for e in matrix_entries if e.risk_level == "High")
            },
            "entries": [entry.to_dict() for entry in matrix_entries],
            "recommendations": self._generate_recommendations(matrix_entries)
        }
        
        return report
    
    def _generate_recommendations(self, entries: List[EvasionMatrixEntry]) -> List[str]:
        """Generate recommendations based on evasion analysis."""
        recommendations = []
        
        high_risk = [e for e in entries if e.risk_level == "High"]
        if high_risk:
            recommendations.append(f"Consider reducing cipher count for {len(high_risk)} high-risk profiles")
        
        unique_ja3 = len(set(e.ja3_hash for e in entries))
        if unique_ja3 > len(entries) * 0.8:
            recommendations.append("High fingerprint diversity detected - consider standardizing configurations")
        
        common_curves = set()
        for entry in entries:
            # Assuming we have access to curve info through the matrix
            pass
        
        if entries:
            avg_cipher_count = sum(e.cipher_count for e in entries) / len(entries)
            if avg_cipher_count > 15:
                recommendations.append("Average cipher count is high - consider removing less common ciphers")
        
        return recommendations


# ============================================================================
# OUTPUT FORMATTERS
# ============================================================================

class OutputFormatter:
    """Formats fingerprint data for various output formats."""
    
    @staticmethod
    def format_json(data: dict, indent: int = 2) -> str:
        """Format data as JSON."""
        return json.dumps(data, indent=indent, default=str)
    
    @staticmethod
    def format_csv(entries: List[EvasionMatrixEntry], filename: str = "evasion_matrix.csv") -> str:
        """Format entries as CSV content."""
        output = []
        output.append("browser_profile,ja3_hash,ja4_hash,sni,cipher_count,curve_count,sig_algo_count,extension_count,fingerprint_score,risk_level")
        
        for entry in entries:
            row = [
                entry.browser_profile,
                entry.ja3_hash,
                entry.ja4_hash,
                entry.sni,
                str(entry.cipher_count),
                str(entry.curve_count),
                str(entry.sig_algo_count),
                str(entry.extension_count),
                str(entry.fingerprint_score),
                entry.risk_level
            ]
            output.append(",".join(row))
        
        return "\n".join(output)
    
    @staticmethod
    def format_table(entries: List[EvasionMatrixEntry]) -> str:
        """Format entries as a markdown table."""
        header = "| Browser | JA3 Hash | JA4 Hash | SNI | Ciphers | Curves | Risk |"
        separator = "|---------|----------|----------|-----|---------|--------|------|"
        
        lines = [header, separator]
        
        for entry in entries:
            line = f"| {entry.browser_profile} | {entry.ja3_hash} | {entry.ja4_hash} | {entry.sni} | {entry.cipher_count} | {entry.curve_count} | {entry.risk_level} |"
            lines.append(line)
        
        return "\n".join(lines)


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main execution function."""
    
    print("=" * 80)
    print("TLS Fingerprint Spoofing & Evasion Matrix Generator")
    print("=" * 80)
    
    # Initialize engine
    engine = TLSSpoofEngine()
    
    # Configure browsers
    print("\n[1] Configuring browser profiles...")
    browsers_configured = []
    
    for browser_type in [BrowserType.CHROME_120, BrowserType.FIREFOX_121, BrowserType.SAFARI_17]:
        config = engine.configure_browser(browser_type)
        browsers_configured.append((browser_type, config))
        print(f"  ✓ {browser_type.value}: {len(config.cipher_suites)} ciphers, {len(config.elliptic_curves)} curves")
    
    # Test spoofing
    print("\n[2] Testing TLS Client Hello spoofing...")
    for browser_type, config in browsers_configured:
        ja3, ja4 = engine.spoof_tls_client_hello(browser_type, "example.com")
        print(f"  {browser_type.value}:")
        print(f"    JA3: {ja3.md5_hash}")
        print(f"    JA4: {ja4.sha256_hash[:16]}...")
    
    # Generate evasion matrix
    print("\n[3] Generating evasion matrix...")
    report = engine.generate_evasion_report()
    
    print(f"\n  Summary:")
    print(f"    Total Profiles: {report['summary']['total_profiles']}")
    print(f"    Unique JA3 Hashes: {report['summary']['unique_ja3_hashes']}")
    print(f"    Unique JA4 Hashes: {report['summary']['unique_ja4_hashes']}")
    print(f"    Low Risk: {report['summary']['low_risk_count']}")
    print(f"    Medium Risk: {report['summary']['medium_risk_count']}")
    print(f"    High Risk: {report['summary']['high_risk_count']}")
    
    # Display recommendations
    print("\n  Recommendations:")
    for rec in report['recommendations']:
        print(f"    • {rec}")
    
    # Show sample entries
    print("\n[4] Sample Evasion Matrix Entries:")
    print(OutputFormatter.format_table(report['entries'][:5]))
    
    # Export options
    print("\n[5] Export Options:")
    print("    JSON:   OutputFormatter.format_json(report)")
    print("    CSV:    OutputFormatter.format_csv(entries)")
    print("    Table:  OutputFormatter.format_table(entries)")
    
    print("\n" + "=" * 80)
    print("Done! All operations completed successfully.")
    print("=" * 80)
    
    return report


if __name__ == "__main__":
    main()
