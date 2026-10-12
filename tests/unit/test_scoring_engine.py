"""Unit tests for exposure and asset criticality scoring engine."""

from datetime import UTC, datetime, timedelta

from asset_discovery.engine.scoring_engine import ExposureScoringEngine
from asset_discovery.models.enums import (
    AssetType,
    ExposureSeverity,
    ServiceProtocol,
    ShadowItTag,
    TlsVersion,
)
from asset_discovery.models.schemas import (
    DiscoveredAsset,
    ExposureFinding,
    ServiceEndpoint,
    TlsCertificateDetails,
)


def test_scoring_clean_asset() -> None:
    """Verify clean asset with no findings or open ports scores 0.0."""
    engine = ExposureScoringEngine()
    asset = DiscoveredAsset(
        asset_type=AssetType.DOMAIN,
        identifier="corp.internal",
    )
    score = engine.score_asset(asset)
    assert score == 0.0


def test_scoring_high_risk_exposed_ports() -> None:
    """Verify scoring weights for administrative and database ports."""
    engine = ExposureScoringEngine()
    asset = DiscoveredAsset(
        asset_type=AssetType.IP_ADDRESS,
        identifier="198.51.100.10",
        services=[
            ServiceEndpoint(
                ip_address="198.51.100.10",
                port=22,
                protocol=ServiceProtocol.SSH,
                service_name="ssh",
            ),
            ServiceEndpoint(
                ip_address="198.51.100.10",
                port=6379,
                protocol=ServiceProtocol.REDIS,
                service_name="redis",
            ),
        ],
    )
    # 22 gives 25.0, 6379 gives 45.0 = 70.0
    score = engine.score_asset(asset)
    assert score == 70.0


def test_scoring_tls_and_shadow_it() -> None:
    """Verify scoring includes expired TLS certificates and shadow IT tags."""
    engine = ExposureScoringEngine()
    now = datetime.now(UTC)
    cert = TlsCertificateDetails(
        subject_cn="test.corp.internal",
        issuer_cn="Internal CA",
        valid_from=now - timedelta(days=400),
        valid_until=now - timedelta(days=10),
        days_to_expiration=-10,
        is_expired=True,
        tls_version=TlsVersion.TLS1_0,  # Deprecated (+20)
    )

    asset = DiscoveredAsset(
        asset_type=AssetType.SUBDOMAIN,
        identifier="test-api.corp.internal",
        services=[
            ServiceEndpoint(
                ip_address="10.0.0.5",
                port=443,
                service_name="https",
                tls_details=cert,
            )
        ],
        tags=[ShadowItTag.STAGING_DEV],  # +15
        findings=[
            ExposureFinding(
                title="Expired Cert",
                description="Cert expired",
                severity=ExposureSeverity.HIGH,  # +30
                tag=ShadowItTag.EXPIRED_CERT,
            )
        ],
    )
    # 25 (expired) + 20 (deprecated tls) + 15 (staging) + 30 (high finding) = 90.0
    score = engine.score_asset(asset)
    assert score == 90.0


def test_score_inventory_aggregation() -> None:
    """Verify aggregate inventory risk metrics calculation."""
    engine = ExposureScoringEngine()

    a1 = DiscoveredAsset(asset_type=AssetType.DOMAIN, identifier="a.com")
    a2 = DiscoveredAsset(
        asset_type=AssetType.SUBDOMAIN,
        identifier="b.com",
        services=[ServiceEndpoint(ip_address="1.1.1.1", port=3389)],
    )

    summary = engine.score_inventory([a1, a2])
    assert summary["max_risk"] == 40.0
    assert summary["average_risk"] == 20.0
    assert summary["high_risk_count"] == 0.0

    empty_summary = engine.score_inventory([])
    assert empty_summary["max_risk"] == 0.0
