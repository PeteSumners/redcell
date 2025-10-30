"""
Unit tests for C2 cryptography module.
"""

import pytest
import base64
import json
from c2.server.crypto import C2Crypto, generate_implant_key


class TestC2Crypto:
    """Test C2Crypto functionality."""

    def test_generate_key(self):
        """Test key generation."""
        key = C2Crypto.generate_key()
        assert len(key) == 32  # 256 bits
        assert isinstance(key, bytes)

    def test_init_with_key(self):
        """Test initialization with provided key."""
        key = C2Crypto.generate_key()
        crypto = C2Crypto(key=key)
        assert crypto.key == key

    def test_init_without_key(self):
        """Test initialization with auto-generated key."""
        crypto = C2Crypto()
        assert crypto.key is not None
        assert len(crypto.key) == 32

    def test_init_invalid_key_length(self):
        """Test initialization with invalid key length."""
        with pytest.raises(ValueError):
            C2Crypto(key=b'too_short')

    def test_encrypt_decrypt_bytes(self):
        """Test encryption and decryption of bytes."""
        crypto = C2Crypto()
        plaintext = b"Hello, World!"

        # Encrypt
        encrypted = crypto.encrypt(plaintext)
        assert 'nonce' in encrypted
        assert 'ciphertext' in encrypted

        # Decrypt
        decrypted = crypto.decrypt(encrypted)
        assert decrypted == plaintext

    def test_encrypt_decrypt_json(self):
        """Test encryption and decryption of JSON data."""
        crypto = C2Crypto()
        data = {
            'command': 'shell',
            'arguments': {'cmd': 'whoami'},
            'task_id': '12345'
        }

        # Encrypt
        encrypted = crypto.encrypt_json(data)
        assert 'nonce' in encrypted
        assert 'ciphertext' in encrypted

        # Decrypt
        decrypted = crypto.decrypt_json(encrypted)
        assert decrypted == data

    def test_encryption_with_aad(self):
        """Test encryption with additional authenticated data."""
        crypto = C2Crypto()
        plaintext = b"Secret message"
        aad = b"implant_id_12345"

        # Encrypt with AAD
        encrypted = crypto.encrypt(plaintext, associated_data=aad)

        # Decrypt with correct AAD
        decrypted = crypto.decrypt(encrypted, associated_data=aad)
        assert decrypted == plaintext

        # Decrypt with incorrect AAD should fail
        with pytest.raises(Exception):  # cryptography.exceptions.InvalidTag
            crypto.decrypt(encrypted, associated_data=b"wrong_aad")

    def test_different_nonces(self):
        """Test that different nonces are generated for each encryption."""
        crypto = C2Crypto()
        plaintext = b"Same message"

        encrypted1 = crypto.encrypt(plaintext)
        encrypted2 = crypto.encrypt(plaintext)

        assert encrypted1['nonce'] != encrypted2['nonce']
        assert encrypted1['ciphertext'] != encrypted2['ciphertext']

    def test_key_base64_encoding(self):
        """Test key base64 encoding and decoding."""
        crypto1 = C2Crypto()
        key_b64 = crypto1.get_key_b64()

        assert isinstance(key_b64, str)

        # Create new instance from base64 key
        crypto2 = C2Crypto.from_b64_key(key_b64)
        assert crypto2.key == crypto1.key

    def test_derive_key_from_password(self):
        """Test key derivation from password."""
        password = "my_secure_password"

        # Derive key
        key1, salt = C2Crypto.derive_key_from_password(password)
        assert len(key1) == 32
        assert len(salt) == 16

        # Same password and salt should produce same key
        key2, _ = C2Crypto.derive_key_from_password(password, salt=salt)
        assert key1 == key2

        # Different salt should produce different key
        key3, salt3 = C2Crypto.derive_key_from_password(password)
        assert key3 != key1

    def test_generate_implant_key(self):
        """Test implant key generation."""
        key_b64 = generate_implant_key()
        assert isinstance(key_b64, str)

        # Should be valid base64
        key_bytes = base64.b64decode(key_b64)
        assert len(key_bytes) == 32

    def test_encrypt_large_data(self):
        """Test encryption of larger data."""
        crypto = C2Crypto()
        large_data = {'data': 'x' * 10000}  # 10KB of data

        encrypted = crypto.encrypt_json(large_data)
        decrypted = crypto.decrypt_json(encrypted)

        assert decrypted == large_data

    def test_decrypt_tampered_ciphertext(self):
        """Test that tampering with ciphertext is detected."""
        crypto = C2Crypto()
        plaintext = b"Important message"

        encrypted = crypto.encrypt(plaintext)

        # Tamper with ciphertext
        ciphertext_bytes = base64.b64decode(encrypted['ciphertext'])
        tampered = bytearray(ciphertext_bytes)
        tampered[0] ^= 0xFF  # Flip bits in first byte
        encrypted['ciphertext'] = base64.b64encode(bytes(tampered)).decode()

        # Decryption should fail
        with pytest.raises(Exception):  # cryptography.exceptions.InvalidTag
            crypto.decrypt(encrypted)
