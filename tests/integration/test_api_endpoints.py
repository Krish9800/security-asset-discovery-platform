"""Integration tests for FastAPI control plane endpoints."""

from collections.abc import Generator
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from asset_discovery.api import app as api_app
from asset_discovery.api.app import get_app_state
from asset_discovery.config.settings import PlatformSettings
from asset_discovery.models.enums import DnsRecordType
from asset_discovery.models.schemas import DnsRecord


@pytest.fixture
def test_client(temp_dir: Path) -> Generator[TestClient, None, None]:
    """Test client configured with temporary SQLite database."""
    state = get_app_state()
    # Direct database path to temporary directory for test isolation
    state.settings = PlatformSettings(
        environment="test",
        db_path=temp_dir / "test_api.db",
    )
    # Re-initialize state database to test path
    from asset_discovery.db.database import DatabaseManager

    state.db.close()
    state.db = DatabaseManager(state.settings.db_path)

    with TestClient(api_app) as client:
        yield client


def test_health_check_endpoint(test_client: TestClient) -> None:
    """Verify GET /health returns 200 OK."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "security-asset-discovery-platform"


def test_launch_discovery_scan_and_queries(test_client: TestClient) -> None:
    """Verify POST /api/v1/scans runs discovery and populates assets and exposures."""
    state = get_app_state()

    # Mock DNS resolution for predictable local testing
    async def mock_resolve_all(domain: str) -> list[DnsRecord]:
        return [
            DnsRecord(
                record_type=DnsRecordType.A,
                domain=domain,
                value="192.0.2.1",
            )
        ]

    with (
        patch.object(state.dns_engine, "resolve_all_records", side_effect=mock_resolve_all),
        patch.object(state.dns_engine, "enumerate_subdomains", new_callable=AsyncMock) as mock_subs,
        patch.object(
            state.service_scanner, "scan_target_ports", new_callable=AsyncMock
        ) as mock_ports,
    ):
        mock_subs.return_value = []
        mock_ports.return_value = []

        scan_payload = {
            "target_domain": "corp.internal",
            "subdomain_wordlist": ["api"],
            "probe_ports": [80, 443],
        }

        # 1. Trigger scan
        res = test_client.post("/api/v1/scans", json=scan_payload)
        assert res.status_code == 201
        data = res.json()
        assert data["target_seed"] == "corp.internal"
        assert data["total_assets"] == 1
        assert "scan_id" in data

        # 2. Query assets
        assets_res = test_client.get("/api/v1/assets")
        assert assets_res.status_code == 200
        assets = assets_res.json()
        assert len(assets) >= 1
        asset_id = assets[0]["asset_id"]

        # 3. Query specific asset
        single_res = test_client.get(f"/api/v1/assets/{asset_id}")
        assert single_res.status_code == 200
        assert single_res.json()["identifier"] == "corp.internal"

        # 4. Query exposures
        exp_res = test_client.get("/api/v1/exposures")
        assert exp_res.status_code == 200
        assert isinstance(exp_res.json(), list)


def test_get_nonexistent_asset(test_client: TestClient) -> None:
    """Verify 404 for missing asset."""
    res = test_client.get("/api/v1/assets/AST-NONEXIST")
    assert res.status_code == 404
