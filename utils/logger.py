"""
Logging utilities for RedCell operations.

Provides structured logging with operation tracking and OPSEC considerations.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional
import json


class OperationLogger(logging.Logger):
    """Custom logger that tracks red team operations."""

    def __init__(self, name: str, level: int = logging.INFO):
        super().__init__(name, level)
        self.operations = []

    def log_operation(self, operation_type: str, target: str, status: str, details: dict = None):
        """Log a red team operation with structured data."""
        operation = {
            'timestamp': datetime.utcnow().isoformat(),
            'operation_type': operation_type,
            'target': target,
            'status': status,
            'details': details or {}
        }
        self.operations.append(operation)
        self.info(f"[{operation_type}] {target} - {status}")

    def save_operations(self, filepath: str):
        """Save operations log to JSON file."""
        with open(filepath, 'w') as f:
            json.dump(self.operations, f, indent=2)


def setup_logging(
    name: str = 'redcell',
    log_level: str = 'INFO',
    log_file: Optional[str] = None,
    enable_console: bool = True,
    enable_operations_log: bool = True
) -> OperationLogger:
    """
    Set up logging for RedCell operations.

    Args:
        name: Logger name
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (optional)
        enable_console: Enable console output
        enable_operations_log: Enable operation tracking

    Returns:
        Configured OperationLogger instance
    """
    # Create custom logger
    logging.setLoggerClass(OperationLogger)
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level.upper()))

    # Clear existing handlers
    logger.handlers.clear()

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # File handler
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str = 'redcell') -> logging.Logger:
    """
    Get a logger instance.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    return logging.getLogger(name)
