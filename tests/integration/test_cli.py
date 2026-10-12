"""Integration tests for Typer CLI commands."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from asset_discovery.cli.main import app
from asset_discovery.db.database import DatabaseManager
from asset_discovery.models.enums import AssetType, ExposureSeverity, ShadowItTag
from asset_discovery.models.schemas import DiscoveredAsset, ExposureFinding

runner = CliRunner()


def test_cli_version() -> None:
    """Verify --version returns package version and name."""
    res = runner.invoke(app, ["--version"])
    assert res.exit_code == 0
    assert "Security Asset Discovery Platform" in res.stdout


def test_cli_assets_empty_and_populated(temp_dir: Path) -> None:
    """Verify 'assets' command outputs."""
    db_file = temp_dir / "cli_test.db"

    # Empty run
    res_empty = runner.invoke(app, ["assets", "--db", str(db_file)])
    assert res_empty.exit_code == 0
    assert "No assets found" in res_empty.stdout

    # Insert an asset
    db = DatabaseManager(db_file)
    asset = DiscoveredAsset(
        asset_type=AssetType.SUBDOMAIN,
        identifier="portal.corp.internal",
        ip_addresses=["10.0.1.5"],
    )
    db.save_asset(asset)
    db.close()

    # Populated run
    res_pop = runner.invoke(app, ["assets", "--db", str(db_file)])
    assert res_pop.exit_code == 0
    assert "portal" in res_pop.stdout
    assert "subdomain" in res_pop.stdout


def test_cli_exposures_command(temp_dir: Path) -> None:
    """Verify 'exposures' command displays security findings."""
    db_file = temp_dir / "cli_exp.db"
    db = DatabaseManager(db_file)
    asset = DiscoveredAsset(
        asset_type=AssetType.DOMAIN,
        identifier="test.corp.internal",
        findings=[
            ExposureFinding(
                title="Staging Exposure",
                description="Dev environment open",
                severity=ExposureSeverity.HIGH,
                tag=ShadowItTag.STAGING_DEV,
            )
        ],
    )
    db.save_asset(asset)
    db.close()

    res = runner.invoke(app, ["exposures", "--db", str(db_file)])
    assert res.exit_code == 0
    assert "Staging Exposure" in res.stdout


def test_cli_scan_command_mocked(temp_dir: Path) -> None:
    """Verify 'scan' command triggers scan and prints summary table."""
    db_file = temp_dir / "cli_scan.db"

    with (
        patch(
            "asset_discovery.discovery.dns_engine.DnsDiscoveryEngine.resolve_all_records",
            new_callable=AsyncMock,
        ) as mock_dns,
        patch(
            "asset_discovery.discovery.dns_engine.DnsDiscoveryEngine.enumerate_subdomains",
            new_callable=AsyncMock,
        ) as mock_subs,
        patch(
            "asset_discovery.scanners.service_scanner.ServiceExposureScanner.scan_target_ports",
            new_callable=AsyncMock,
        ) as mock_ports,
    ):
        mock_dns.return_value = []
        mock_subs.return_value = []
        mock_ports.return_value = []

        res = runner.invoke(app, ["scan", "corp.internal", "--db", str(db_file)])
        assert res.exit_code == 0
        assert "Scan Completed Successfully" in res.stdout
        assert "Scan Summary" in res.stdout


def test_cli_report_command(temp_dir: Path) -> None:
    """Verify 'report' command fetches report by ID."""
    db_file = temp_dir / "cli_rep.db"

    # Non-existent
    res_missing = runner.invoke(app, ["report", "SCN-NONE", "--db", str(db_file)])
    assert res_missing.exit_code != 0

    # Create report via mocked scan
    with (
        patch(
            "asset_discovery.discovery.dns_engine.DnsDiscoveryEngine.resolve_all_records",
            new_callable=AsyncMock,
        ) as mock_dns,
        patch(
            "asset_discovery.discovery.dns_engine.DnsDiscoveryEngine.enumerate_subdomains",
            new_callable=AsyncMock,
        ) as mock_subs,
        patch(
            "asset_discovery.scanners.service_scanner.ServiceExposureScanner.scan_target_ports",
            new_callable=AsyncMock,
        ) as mock_ports,
    ):
        mock_dns.return_value = []
        mock_subs.return_value = []
        mock_ports.return_value = []

        runner.invoke(app, ["scan", "corp.internal", "--db", str(db_file)])

    db = DatabaseManager(db_file)
    cur = db._conn.cursor()
    scan_id = cur.execute("SELECT scan_id FROM scan_reports LIMIT 1;").fetchone()[0]
    cur.close()
    db.close()

    res_ok = runner.invoke(app, ["report", scan_id, "--db", str(db_file)])
    assert res_ok.exit_code == 0
    assert "Scan Report Details" in res_ok.stdout
