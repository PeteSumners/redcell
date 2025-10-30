"""
RedCell Utilities Module

Shared utilities for the RedCell red team operations framework.
"""

from .logger import get_logger, setup_logging
from .config import Config, load_config
from .helpers import generate_random_string, encode_payload, decode_payload, get_timestamp

__all__ = [
    'get_logger',
    'setup_logging',
    'Config',
    'load_config',
    'generate_random_string',
    'encode_payload',
    'decode_payload',
    'get_timestamp'
]

__version__ = '1.0.0'
