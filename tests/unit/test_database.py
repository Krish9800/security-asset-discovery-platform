"""Unit tests for SQLite WAL persistence and asset graph storage."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from asset_discovery.db.database import DatabaseManager
from asset_discovery.models.enums import (
    AssetType,
    CloudProvider,
    DnsRecordType,
    ExposureSeverity,
    ServiceProtocol,
    ShadowItTag,
    TlsVersion,
)
from asset_discovery.models.schemas import (
    DiscoveredAsset,
    DiscoveryScanReport,
    DnsRecord,
    ExposureFinding,
    ServiceEndpoint,
    TlsCertificateDetails,
)


def test_database_init_and_wal(temp_dir: Path) -> None:
    """Verify database initialization and WAL journal mode pragma."""
    db_file = temp_dir / "test_wal.db"
    db = DatabaseManager(db_file)
    cur = db._conn.cursor()
    mode = cur.execute("PRAGMA journal_mode;").fetchone()[0]
    assert mode.lower() == "wal"
    cur.close()
    db.close()


def test_asset_crud_and_relationships(temp_dir: Path) -> None:
    """Verify asset persistence, upsert, and relationship reconstruction."""
    db = DatabaseManager(temp_dir / "inventory.db")
    now = datetime.now(UTC)

    cert = TlsCertificateDetails(
        subject_cn="*.corp.internal",
        issuer_cn="Corp CA",
        subject_alt_names=["corp.internal"],
        valid_from=now - timedelta(days=30),
        valid_until=now + timedelta(days=60),
        days_to_expiration=60,
        is_expired=False,
        tls_version=TlsVersion.TLS1_3,
    )

    svc = ServiceEndpoint(
        ip_address="10.0.0.1",
        port=443,
        protocol=ServiceProtocol.HTTPS,
        service_name="https",
        tls_details=cert,
    )

    finding = ExposureFinding(
        title="Administrative Service",
        description="Admin portal exposed",
        severity=ExposureSeverity.HIGH,
        tag=ShadowItTag.ADMIN_INTERFACE,
    )

    asset = DiscoveredAsset(
        asset_type=AssetType.SUBDOMAIN,
        identifier="admin.corp.internal",
        parent_domain="corp.internal",
        cloud_provider=CloudProvider.AWS,
        tags=[ShadowItTag.ADMIN_INTERFACE],
        dns_records=[
            DnsRecord(
                record_type=DnsRecordType.A,
                domain="admin.corp.internal",
                value="10.0.0.1",
            )
        ],
        services=[svc],
        findings=[finding],
    )
    asset.calculate_risk_score()

    db.save_asset(asset)

    # Retrieve by ID
    loaded = db.get_asset(asset.asset_id)
    assert loaded is not None
    assert loaded.identifier == "admin.corp.internal"
    assert len(loaded.dns_records) == 1
    assert len(loaded.services) == 1
    assert loaded.services[0].tls_details is not None
    assert loaded.services[0].tls_details.subject_cn == "*.corp.internal"
    assert len(loaded.findings) == 1
    assert loaded.findings[0].severity == ExposureSeverity.HIGH

    # Retrieve by identifier
    by_ident = db.get_asset_by_identifier("admin.corp.internal")
    assert by_ident is not None
    assert by_ident.asset_id == asset.asset_id

    # List with filters
    filtered = db.list_assets(asset_type="subdomain", min_risk_score=10.0)
    assert len(filtered) == 1

    # List findings
    findings = db.list_exposure_findings(severity="high")
    assert len(findings) == 1
    assert findings[0].title == "Administrative Service"

    db.close()


def test_scan_report_persistence(temp_dir: Path) -> None:
    """Verify persisting and reading scan reports."""
    db = DatabaseManager(temp_dir / "reports.db")
    report = DiscoveryScanReport(
        target_seed="example.com",
        total_assets=10,
        total_services=25,
        total_findings=3,
        max_risk_score=75.0,
        summary="Automated scan summary",
    )

    db.save_scan_report(report)
    loaded = db.get_scan_report(report.scan_id)
    assert loaded is not None
    assert loaded.target_seed == "example.com"
    assert loaded.max_risk_score == 75.0

    missing = db.get_scan_report("SCN-NONEXIST")
    assert missing is None
    db.close()
