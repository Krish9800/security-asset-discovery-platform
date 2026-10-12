"""Shared pytest fixtures and test configuration."""

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from asset_discovery.config.settings import PlatformSettings


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide an isolated temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def custom_settings(temp_dir: Path) -> PlatformSettings:
    """Provide a custom PlatformSettings instance pointing to a temporary database."""
    return PlatformSettings(
        environment="test",
        debug=True,
        db_path=temp_dir / "test_inventory.db",
        dns_timeout_seconds=1.0,
        tcp_scan_timeout_seconds=0.5,
        tls_handshake_timeout_seconds=1.0,
        max_concurrent_probes=10,
    )
