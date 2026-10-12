"""Unit tests for domain models, enums, and risk scoring."""

from datetime import UTC, datetime, timedelta

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


def test_domain_enums() -> None:
    """Verify enum variants and helper methods."""
    assert AssetType.DOMAIN.value == "domain"
    assert AssetType.SUBDOMAIN.value == "subdomain"
    assert AssetType.IP_ADDRESS.value == "ip_address"
    assert AssetType.CIDR.value == "cidr"
    assert AssetType.SERVICE.value == "service"
    assert AssetType.CLOUD_BUCKET.value == "cloud_bucket"

    assert DnsRecordType.A.value == "A"
    assert DnsRecordType.PTR.value == "PTR"
    assert DnsRecordType.CNAME.value == "CNAME"

    assert ExposureSeverity.CRITICAL.score_weight == 80.0
    assert ExposureSeverity.HIGH.score_weight == 50.0
    assert ExposureSeverity.INFO.score_weight == 0.0

    assert TlsVersion.SSLV3.is_deprecated is True
    assert TlsVersion.TLS1_0.is_deprecated is True
    assert TlsVersion.TLS1_2.is_deprecated is False
    assert TlsVersion.TLS1_3.is_deprecated is False


def test_dns_record_creation() -> None:
    """Verify DnsRecord instantiation and frozen immutability."""
    rec = DnsRecord(
        record_type=DnsRecordType.A,
        domain="api.corp.internal",
        value="10.0.1.50",
        ttl=600,
    )
    assert rec.record_type == DnsRecordType.A
    assert rec.domain == "api.corp.internal"
    assert rec.value == "10.0.1.50"
    assert rec.ttl == 600
    assert rec.discovered_at.tzinfo == UTC


def test_tls_certificate_details() -> None:
    """Verify TLS certificate modeling, expiration checking, and SANs."""
    now = datetime.now(UTC)
    cert = TlsCertificateDetails(
        subject_cn="*.corp.internal",
        issuer_cn="Corp Root CA",
        subject_alt_names=["corp.internal", "api.corp.internal", "dev.corp.internal"],
        valid_from=now - timedelta(days=100),
        valid_until=now + timedelta(days=20),
        days_to_expiration=20,
        is_expired=False,
        tls_version=TlsVersion.TLS1_3,
    )
    assert cert.subject_cn == "*.corp.internal"
    assert len(cert.subject_alt_names) == 3
    assert cert.days_to_expiration == 20
    assert cert.is_expired is False


def test_service_endpoint_and_finding() -> None:
    """Verify ServiceEndpoint and ExposureFinding creation."""
    svc = ServiceEndpoint(
        ip_address="192.168.1.10",
        port=6379,
        protocol=ServiceProtocol.TCP,
        service_name="redis",
        banner="Redis server v=7.0.0",
        is_open=True,
    )
    assert svc.port == 6379
    assert svc.service_name == "redis"
    assert svc.service_id.startswith("SVC-")

    finding = ExposureFinding(
        title="Unauthenticated Redis Database",
        description="Publicly exposed Redis cache allows unauthenticated commands",
        severity=ExposureSeverity.CRITICAL,
        tag=ShadowItTag.UNSECURED_DATABASE,
    )
    assert finding.severity == ExposureSeverity.CRITICAL
    assert finding.finding_id.startswith("EXP-")


def test_discovered_asset_risk_calculation() -> None:
    """Verify composite exposure risk calculation for DiscoveredAsset."""
    asset = DiscoveredAsset(
        asset_type=AssetType.SUBDOMAIN,
        identifier="staging-db.corp.internal",
        parent_domain="corp.internal",
        ip_addresses=["198.51.100.25"],
        cloud_provider=CloudProvider.AWS,
        tags=[ShadowItTag.STAGING_DEV],
    )
    # Base risk with staging tag
    assert asset.calculate_risk_score() == 15.0

    # Add exposed database service (port 5432)
    svc = ServiceEndpoint(
        ip_address="198.51.100.25",
        port=5432,
        protocol=ServiceProtocol.TCP,
        service_name="postgresql",
    )
    asset.services.append(svc)
    assert asset.calculate_risk_score() == 40.0  # 15 + 25

    # Add critical exposure finding
    finding = ExposureFinding(
        title="Exposed Database",
        description="Postgres exposed to internet",
        severity=ExposureSeverity.CRITICAL,
        tag=ShadowItTag.UNSECURED_DATABASE,
    )
    asset.findings.append(finding)
    # 40 + (80 * 0.4) = 72.0
    assert asset.calculate_risk_score() == 72.0


def test_discovery_scan_report() -> None:
    """Verify DiscoveryScanReport initialization."""
    report = DiscoveryScanReport(
        target_seed="corp.internal",
        total_assets=5,
        total_services=12,
        total_findings=2,
        max_risk_score=72.0,
        summary="Scan completed with 5 assets discovered.",
    )
    assert report.scan_id.startswith("SCN-")
    assert report.target_seed == "corp.internal"
    assert report.max_risk_score == 72.0
