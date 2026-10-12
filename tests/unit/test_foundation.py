"""Unit tests for foundation configuration and settings."""

from pathlib import Path

from asset_discovery import __version__
from asset_discovery.config.settings import PlatformSettings, get_settings
from asset_discovery.exceptions import (
    AssetDiscoveryError,
    ConfigurationError,
    DnsResolutionError,
    ProbeTimeoutError,
    StorageError,
    TlsInspectionError,
)


def test_package_metadata() -> None:
    """Verify package metadata is accessible and formatted correctly."""
    assert __version__ == "0.1.0"


def test_default_settings() -> None:
    """Verify default platform settings load with expected values."""
    settings = PlatformSettings()
    assert settings.environment == "development"
    assert settings.debug is False
    assert settings.host == "127.0.0.1"
    assert settings.port == 8000
    assert "1.1.1.1" in settings.default_dns_resolvers
    assert settings.dns_timeout_seconds == 3.0
    assert settings.tcp_scan_timeout_seconds == 2.0
    assert settings.tls_handshake_timeout_seconds == 4.0
    assert settings.max_concurrent_probes == 50
    assert settings.certificate_expiration_warning_days == 30


def test_custom_settings_initialization(temp_dir: Path) -> None:
    """Verify custom settings overrides work as intended."""
    db_file = temp_dir / "custom.db"
    settings = PlatformSettings(
        environment="staging",
        debug=True,
        db_path=db_file,
        port=9090,
        dns_timeout_seconds=5.0,
    )
    assert settings.environment == "staging"
    assert settings.debug is True
    assert settings.db_path == db_file
    assert settings.port == 9090
    assert settings.dns_timeout_seconds == 5.0


def test_settings_singleton_caching() -> None:
    """Verify get_settings returns a cached singleton instance."""
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2


def test_exception_hierarchy() -> None:
    """Verify exception classes inherit correctly from AssetDiscoveryError."""
    assert issubclass(ConfigurationError, AssetDiscoveryError)
    assert issubclass(DnsResolutionError, AssetDiscoveryError)
    assert issubclass(ProbeTimeoutError, AssetDiscoveryError)
    assert issubclass(TlsInspectionError, AssetDiscoveryError)
    assert issubclass(StorageError, AssetDiscoveryError)
