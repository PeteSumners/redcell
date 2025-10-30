"""
Helper utilities for RedCell operations.

Common utility functions used across the framework.
"""

import random
import string
import base64
import hashlib
from datetime import datetime
from typing import Union, Optional


def generate_random_string(length: int = 16, charset: Optional[str] = None) -> str:
    """
    Generate a random string for various purposes.

    Args:
        length: Length of the random string
        charset: Character set to use (default: alphanumeric)

    Returns:
        Random string
    """
    if charset is None:
        charset = string.ascii_letters + string.digits

    return ''.join(random.choice(charset) for _ in range(length))


def encode_payload(data: Union[str, bytes], encoding: str = 'base64') -> str:
    """
    Encode payload for obfuscation.

    Args:
        data: Data to encode
        encoding: Encoding method (base64, hex)

    Returns:
        Encoded data as string
    """
    if isinstance(data, str):
        data = data.encode('utf-8')

    if encoding == 'base64':
        return base64.b64encode(data).decode('utf-8')
    elif encoding == 'hex':
        return data.hex()
    else:
        raise ValueError(f"Unsupported encoding: {encoding}")


def decode_payload(data: str, encoding: str = 'base64') -> bytes:
    """
    Decode obfuscated payload.

    Args:
        data: Encoded data
        encoding: Encoding method (base64, hex)

    Returns:
        Decoded data as bytes
    """
    if encoding == 'base64':
        return base64.b64decode(data)
    elif encoding == 'hex':
        return bytes.fromhex(data)
    else:
        raise ValueError(f"Unsupported encoding: {encoding}")


def xor_encrypt_decrypt(data: bytes, key: bytes) -> bytes:
    """
    XOR encryption/decryption (symmetric).

    Args:
        data: Data to encrypt/decrypt
        key: Encryption key

    Returns:
        Encrypted/decrypted data
    """
    key_length = len(key)
    return bytes([data[i] ^ key[i % key_length] for i in range(len(data))])


def get_timestamp(format_str: str = 'iso') -> str:
    """
    Get current timestamp in various formats.

    Args:
        format_str: Format type ('iso', 'unix', 'human')

    Returns:
        Formatted timestamp string
    """
    now = datetime.utcnow()

    if format_str == 'iso':
        return now.isoformat()
    elif format_str == 'unix':
        return str(int(now.timestamp()))
    elif format_str == 'human':
        return now.strftime('%Y-%m-%d %H:%M:%S UTC')
    else:
        raise ValueError(f"Unsupported timestamp format: {format_str}")


def calculate_hash(data: Union[str, bytes], algorithm: str = 'sha256') -> str:
    """
    Calculate hash of data.

    Args:
        data: Data to hash
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)

    Returns:
        Hex digest of hash
    """
    if isinstance(data, str):
        data = data.encode('utf-8')

    hash_func = getattr(hashlib, algorithm)()
    hash_func.update(data)
    return hash_func.hexdigest()


def format_bytes(size: int) -> str:
    """
    Format byte size to human-readable format.

    Args:
        size: Size in bytes

    Returns:
        Formatted size string
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def sanitize_input(user_input: str, max_length: int = 1000) -> str:
    """
    Sanitize user input for security.

    Args:
        user_input: Raw user input
        max_length: Maximum allowed length

    Returns:
        Sanitized input
    """
    # Truncate to max length
    sanitized = user_input[:max_length]

    # Remove null bytes and other control characters
    sanitized = ''.join(char for char in sanitized if ord(char) >= 32 or char in '\n\r\t')

    return sanitized


def jitter_delay(base_delay: float, jitter_percent: float = 0.2) -> float:
    """
    Calculate randomized delay for beacon jitter.

    Args:
        base_delay: Base delay in seconds
        jitter_percent: Percentage of jitter (0.0-1.0)

    Returns:
        Randomized delay
    """
    jitter_amount = base_delay * jitter_percent
    jitter = random.uniform(-jitter_amount, jitter_amount)
    return max(0, base_delay + jitter)
