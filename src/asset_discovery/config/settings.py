"""Configuration management for Security Asset Discovery Platform."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class PlatformSettings(BaseSettings):
    """Runtime platform settings with environment variable override support."""

    model_config = SettingsConfigDict(
        env_prefix="ASSET_DISCOVERY_",
        env_file=".env",
        extra="ignore",
    )

    # General Environment
    environment: str = Field(default="development", description="Runtime environment")
    debug: bool = Field(default=False, description="Enable debug logging and diagnostic mode")

    # API & Networking
    host: str = Field(default="127.0.0.1", description="FastAPI bind host")
    port: int = Field(default=8000, ge=1, le=65535, description="FastAPI bind port")

    # Storage & Persistence
    db_path: Path = Field(
        default=Path("data/asset_discovery.db"),
        description="Path to SQLite asset inventory database",
    )

    # Discovery & Scanning Controls
    default_dns_resolvers: list[str] = Field(
        default_factory=lambda: ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
        description="Default upstream recursive DNS resolvers",
    )
    dns_timeout_seconds: float = Field(
        default=3.0, gt=0.0, le=30.0, description="DNS query timeout in seconds"
    )
    tcp_scan_timeout_seconds: float = Field(
        default=2.0, gt=0.0, le=10.0, description="TCP socket connection timeout in seconds"
    )
    tls_handshake_timeout_seconds: float = Field(
        default=4.0, gt=0.0, le=15.0, description="TLS handshake timeout in seconds"
    )
    max_concurrent_probes: int = Field(
        default=50, ge=1, le=500, description="Maximum concurrent async socket probe tasks"
    )
    certificate_expiration_warning_days: int = Field(
        default=30, ge=1, description="Threshold in days to flag certificates nearing expiration"
    )


@lru_cache(maxsize=1)
def get_settings() -> PlatformSettings:
    """Retrieve cached platform settings singleton."""
    return PlatformSettings()
