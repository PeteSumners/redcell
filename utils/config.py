"""
Configuration management for RedCell operations.

Handles loading and managing configuration from files and environment variables.
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class C2Config:
    """C2 Server configuration."""
    host: str = '127.0.0.1'
    port: int = 8443
    encryption_key: Optional[str] = None
    beacon_interval: int = 60
    beacon_jitter: float = 0.2
    max_retries: int = 3


@dataclass
class TargetConfig:
    """Target environment configuration."""
    web_app_url: str = 'http://localhost:8080'
    dmz_network: str = '172.20.0.0/24'
    internal_network: str = '172.21.0.0/24'


@dataclass
class Config:
    """Main configuration object."""
    c2: C2Config = field(default_factory=C2Config)
    target: TargetConfig = field(default_factory=TargetConfig)
    log_level: str = 'INFO'
    operation_name: str = 'redcell_default'
    opsec_mode: bool = True

    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'Config':
        """Create Config from dictionary."""
        c2_config = C2Config(**config_dict.get('c2', {}))
        target_config = TargetConfig(**config_dict.get('target', {}))

        return cls(
            c2=c2_config,
            target=target_config,
            log_level=config_dict.get('log_level', 'INFO'),
            operation_name=config_dict.get('operation_name', 'redcell_default'),
            opsec_mode=config_dict.get('opsec_mode', True)
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert Config to dictionary."""
        return {
            'c2': {
                'host': self.c2.host,
                'port': self.c2.port,
                'encryption_key': self.c2.encryption_key,
                'beacon_interval': self.c2.beacon_interval,
                'beacon_jitter': self.c2.beacon_jitter,
                'max_retries': self.c2.max_retries
            },
            'target': {
                'web_app_url': self.target.web_app_url,
                'dmz_network': self.target.dmz_network,
                'internal_network': self.target.internal_network
            },
            'log_level': self.log_level,
            'operation_name': self.operation_name,
            'opsec_mode': self.opsec_mode
        }


def load_config(config_file: Optional[str] = None) -> Config:
    """
    Load configuration from file or environment variables.

    Args:
        config_file: Path to YAML configuration file

    Returns:
        Config object
    """
    config_dict = {}

    # Load from file if provided
    if config_file and Path(config_file).exists():
        with open(config_file, 'r') as f:
            config_dict = yaml.safe_load(f) or {}

    # Override with environment variables
    if os.getenv('C2_HOST'):
        config_dict.setdefault('c2', {})['host'] = os.getenv('C2_HOST')
    if os.getenv('C2_PORT'):
        config_dict.setdefault('c2', {})['port'] = int(os.getenv('C2_PORT'))
    if os.getenv('C2_ENCRYPTION_KEY'):
        config_dict.setdefault('c2', {})['encryption_key'] = os.getenv('C2_ENCRYPTION_KEY')

    return Config.from_dict(config_dict)


def save_config(config: Config, config_file: str):
    """
    Save configuration to YAML file.

    Args:
        config: Config object to save
        config_file: Path to save configuration
    """
    config_path = Path(config_file)
    config_path.parent.mkdir(parents=True, exist_ok=True)

    with open(config_file, 'w') as f:
        yaml.dump(config.to_dict(), f, default_flow_style=False)
