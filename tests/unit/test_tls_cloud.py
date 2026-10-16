"""Unit tests for TLS certificate inspector and cloud shadow IT detector."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from asset_discovery.models.enums import (
    AssetType,
    CloudProvider,
    DnsRecordType,
    ShadowItTag,
    TlsVersion,
)
from asset_discovery.models.schemas import (
    DiscoveredAsset,
    DnsRecord,
)
from asset_discovery.scanners.cloud_detector import CloudShadowItDetector
from asset_discovery.scanners.tls_inspector import TlsCertificateInspector


def _generate_test_x509_der(
    cn: str = "example.com",
    sans: list[str] | None = None,
    days_valid: int = 30,
) -> bytes:
    """Generate self-signed X.509 certificate DER bytes for unit testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])

    san_list: list[x509.GeneralName] = []
    if sans:
        san_list = [x509.DNSName(s) for s in sans]

    now = datetime.now(UTC)
    start_time = (
        now - timedelta(days=abs(days_valid) + 10) if days_valid <= 0 else now - timedelta(days=1)
    )
    end_time = now + timedelta(days=days_valid)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start_time)
        .not_valid_after(end_time)
    )

    if san_list:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )

    cert = builder.sign(key, hashes.SHA256(), default_backend())
    return cert.public_bytes(serialization.Encoding.DER)


def test_parse_der_certificate() -> None:
    """Verify DER certificate parsing, subject, issuer, and SANs extraction."""
    inspector = TlsCertificateInspector()
    der_bytes = _generate_test_x509_der(
        cn="auth.corp.internal",
        sans=["auth.corp.internal", "sso.corp.internal"],
        days_valid=45,
    )

    details = inspector.parse_der_certificate(
        der_bytes=der_bytes,
        tls_version_str="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
    )

    assert details.subject_cn == "auth.corp.internal"
    assert "sso.corp.internal" in details.subject_alt_names
    assert details.days_to_expiration >= 44
    assert details.is_expired is False
    assert details.tls_version == TlsVersion.TLS1_3
    assert details.cipher_suite == "TLS_AES_256_GCM_SHA384"


def test_parse_expired_certificate() -> None:
    """Verify expired certificate detection."""
    inspector = TlsCertificateInspector()
    expired_der = _generate_test_x509_der(cn="expired.corp.internal", days_valid=-5)
    details = inspector.parse_der_certificate(der_bytes=expired_der)
    assert details.is_expired is True
    assert details.days_to_expiration < 0


def test_cloud_shadow_it_detector_staging_and_admin() -> None:
    """Verify detection of staging and administrative subdomains."""
    detector = CloudShadowItDetector()
    asset = DiscoveredAsset(
        asset_type=AssetType.SUBDOMAIN,
        identifier="staging-admin.example.com",
    )

    findings = detector.analyze_asset(asset)
    assert len(findings) == 2
    tags = asset.tags
    assert ShadowItTag.STAGING_DEV in tags
    assert ShadowItTag.ADMIN_INTERFACE in tags
    assert asset.risk_score > 0.0


def test_cloud_provider_and_storage_bucket_detection() -> None:
    """Verify cloud provider inference and S3 bucket heuristic flagging."""
    detector = CloudShadowItDetector()
    s3_asset = DiscoveredAsset(
        asset_type=AssetType.SUBDOMAIN,
        identifier="assets-bucket.example.com",
        dns_records=[
            DnsRecord(
                record_type=DnsRecordType.CNAME,
                domain="assets-bucket.example.com",
                value="mybucket.s3.amazonaws.com",
            )
        ],
    )

    findings = detector.analyze_asset(s3_asset)
    assert s3_asset.cloud_provider == CloudProvider.AWS
    assert ShadowItTag.PUBLIC_BUCKET in s3_asset.tags
    assert len(findings) == 1
    assert "Cloud Storage Bucket" in findings[0].title


@pytest.mark.asyncio
async def test_tls_inspector_unreachable_host() -> None:
    """Verify unreachable host returns None without unhandled exception."""
    inspector = TlsCertificateInspector(handshake_timeout_seconds=0.1)
    with patch.object(inspector, "_sync_inspect_tls", side_effect=TimeoutError()):
        res = await inspector.inspect_certificate("192.0.2.1", port=443)
        assert res is None
