"""
C2 Cryptography Module

Handles encryption and decryption of C2 communications using AES-256-GCM.
"""

import os
import base64
import json
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class C2Crypto:
    """
    Cryptography handler for C2 communications.

    Uses AES-256-GCM for authenticated encryption with associated data (AEAD).
    """

    def __init__(self, key: bytes = None):
        """
        Initialize crypto handler.

        Args:
            key: 32-byte encryption key (if None, generates new key)
        """
        if key is None:
            key = AESGCM.generate_key(bit_length=256)
        elif len(key) != 32:
            raise ValueError("Key must be exactly 32 bytes for AES-256")

        self.key = key
        self.aesgcm = AESGCM(key)

    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a new 256-bit AES key.

        Returns:
            32-byte key
        """
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """
        Derive a 256-bit key from a password using PBKDF2.

        Args:
            password: Password string
            salt: Salt for key derivation (generates new if None)

        Returns:
            Tuple of (derived_key, salt)
        """
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,  # OWASP recommendation as of 2023
        )

        key = kdf.derive(password.encode('utf-8'))
        return key, salt

    def encrypt(self, plaintext: bytes, associated_data: bytes = None) -> Dict[str, str]:
        """
        Encrypt plaintext with AES-256-GCM.

        Args:
            plaintext: Data to encrypt
            associated_data: Additional authenticated data (AAD)

        Returns:
            Dictionary with base64-encoded nonce and ciphertext
        """
        # Generate a random 96-bit nonce (12 bytes is recommended for GCM)
        nonce = os.urandom(12)

        # Encrypt
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, associated_data)

        # Return base64-encoded components for easy transmission
        return {
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }

    def decrypt(self, encrypted_data: Dict[str, str], associated_data: bytes = None) -> bytes:
        """
        Decrypt ciphertext with AES-256-GCM.

        Args:
            encrypted_data: Dictionary with base64-encoded nonce and ciphertext
            associated_data: Additional authenticated data (AAD) - must match encryption

        Returns:
            Decrypted plaintext

        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails
        """
        nonce = base64.b64decode(encrypted_data['nonce'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])

        # Decrypt and verify
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext

    def encrypt_json(self, data: Dict[str, Any], associated_data: bytes = None) -> Dict[str, str]:
        """
        Encrypt JSON-serializable data.

        Args:
            data: Dictionary to encrypt
            associated_data: Additional authenticated data

        Returns:
            Dictionary with encrypted payload
        """
        plaintext = json.dumps(data).encode('utf-8')
        return self.encrypt(plaintext, associated_data)

    def decrypt_json(self, encrypted_data: Dict[str, str], associated_data: bytes = None) -> Dict[str, Any]:
        """
        Decrypt and parse JSON data.

        Args:
            encrypted_data: Encrypted payload
            associated_data: Additional authenticated data

        Returns:
            Decrypted and parsed dictionary
        """
        plaintext = self.decrypt(encrypted_data, associated_data)
        return json.loads(plaintext.decode('utf-8'))

    def get_key_b64(self) -> str:
        """
        Get base64-encoded key for sharing.

        Returns:
            Base64-encoded key
        """
        return base64.b64encode(self.key).decode('utf-8')

    @classmethod
    def from_b64_key(cls, b64_key: str) -> 'C2Crypto':
        """
        Create C2Crypto instance from base64-encoded key.

        Args:
            b64_key: Base64-encoded 32-byte key

        Returns:
            C2Crypto instance
        """
        key = base64.b64decode(b64_key)
        return cls(key=key)


def generate_implant_key() -> str:
    """
    Generate a new key for an implant and return as base64.

    Returns:
        Base64-encoded 256-bit key
    """
    key = C2Crypto.generate_key()
    return base64.b64encode(key).decode('utf-8')
