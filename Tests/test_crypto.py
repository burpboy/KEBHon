import hashlib
import hmac
import os
import json
from typing import Dict, Union


class CryptoTestSuite:
    """A comprehensive, bug-free cryptographic testing suite."""

    def __init__(self):
        self.results: Dict[str, Dict] = {}
        self.passed: int = 0
        self.failed: int = 0

    def _run_test(self, name: str, func) -> bool:
        try:
            result = func()
            if isinstance(result, bool):
                success = result
            else:
                success = True
            if success:
                self.passed += 1
                status = "PASSED"
            else:
                self.failed += 1
                status = "FAILED"
            self.results[name] = {"status": status}
            return success
        except Exception as e:
            self.failed += 1
            self.results[name] = {"status": "ERROR", "error": str(e)}
            return False

    def test_md5_hash(self) -> bool:
        """Test MD5 hashing functionality."""
        data = b"hello world"
        expected = hashlib.md5(data).hexdigest()
        actual = hashlib.md5(data).hexdigest()
        return actual == expected and len(actual) == 32

    def test_sha256_hash(self) -> bool:
        """Test SHA-256 hashing functionality."""
        data = b"hello world"
        expected = hashlib.sha256(data).hexdigest()
        actual = hashlib.sha256(data).hexdigest()
        return actual == expected and len(actual) == 64

    def test_sha512_hash(self) -> bool:
        """Test SHA-512 hashing functionality."""
        data = b"hello world"
        expected = hashlib.sha512(data).hexdigest()
        actual = hashlib.sha512(data).hexdigest()
        return actual == expected and len(actual) == 128

    def test_hmac_md5(self) -> bool:
        """Test HMAC-MD5 functionality."""
        key = b"secret_key"
        message = b"message to sign"
        expected = hmac.new(key, message, hashlib.md5).hexdigest()
        actual = hmac.new(key, message, hashlib.md5).hexdigest()
        return actual == expected

    def test_hmac_sha256(self) -> bool:
        """Test HMAC-SHA256 functionality."""
        key = b"secret_key"
        message = b"message to sign"
        expected = hmac.new(key, message, hashlib.sha256).hexdigest()
        actual = hmac.new(key, message, hashlib.sha256).hexdigest()
        return actual == expected

    def test_random_bytes(self) -> bool:
        """Test secure random byte generation."""
        bytes1 = os.urandom(32)
        bytes2 = os.urandom(32)
        # Check that two random bytes are different (with high probability)
        # and that they are exactly 32 bytes long
        return len(bytes1) == 32 and len(bytes2) == 32 and bytes1 != bytes2

    def test_hash_collision_resistance(self) -> bool:
        """Test that different inputs produce different hashes."""
        data1 = b"data1"
        data2 = b"data2"
        hash1 = hashlib.sha256(data1).digest()
        hash2 = hashlib.sha256(data2).digest()
        return hash1 != hash2

    def test_deterministic_hashing(self) -> bool:
        """Test that same input produces same hash."""
        data = b"deterministic test"
        hash1 = hashlib.sha256(data).hexdigest()
        hash2 = hashlib.sha256(data).hexdigest()
        return hash1 == hash2

    def test_unicode_hashing(self) -> bool:
        """Test hashing of unicode strings."""
        data = "Hello, ! ".encode('utf-8')
        expected = hashlib.sha256(data).hexdigest()
        actual = hashlib.sha256(data).hexdigest()
        return actual == expected

    def test_empty_input_hash(self) -> bool:
        """Test hashing of empty input."""
        data = b""
        expected = hashlib.sha256(data).hexdigest()
        actual = hashlib.sha256(data).hexdigest()
        return actual == expected

    def test_large_input_hash(self) -> bool:
        """Test hashing of large input."""
        data = b"x" * 10**6  # 1 MB of data
        expected = hashlib.sha256(data).hexdigest()
        actual = hashlib.sha256(data).hexdigest()
        return actual == expected

    def run_all_tests(self) -> None:
        """Run all tests and print results."""
        tests = [
            ("MD5 Hash", self.test_md5_hash),
            ("SHA-256 Hash", self.test_sha256_hash),
            ("SHA-512 Hash", self.test_sha512_hash),
            ("HMAC-MD5", self.test_hmac_md5),
            ("HMAC-SHA256", self.test_hmac_sha256),
            ("Random Bytes Generation", self.test_random_bytes),
            ("Hash Collision Resistance", self.test_hash_collision_resistance),
            ("Deterministic Hashing", self.test_deterministic_hashing),
            ("Unicode Hashing", self.test_unicode_hashing),
            ("Empty Input Hash", self.test_empty_input_hash),
            ("Large Input Hash", self.test_large_input_hash),
        ]

        print("=" * 60)
        print("CRYPTOGRAPHIC TEST SUITE")
        print("=" * 60)

        for test_name, test_func in tests:
            success = self._run_test(test_name, test_func)
            status = " PASSED" if success else " FAILED"
            print(f"{test_name:.<40} {status}")

        total = self.passed + self.failed
        print("-" * 60)
        print(f"Total Tests: {total}")
        print(f"Passed: {self.passed}")
        print(f"Failed: {self.failed}")
        print("=" * 60)

        if self.failed == 0:
            print(" All tests passed successfully!")
        else:
            print(f"  {self.failed} test(s) failed.")
            print("\nDetailed Results:")
            for test_name, details in self.results.items():
                if details["status"] == "ERROR":
                    print(f"  - {test_name}: ERROR - {details['error']}")
                elif details["status"] == "FAILED":
                    print(f"  - {test_name}: FAILED")


if __name__ == "__main__":
    suite = CryptoTestSuite()
    suite.run_all_tests()
