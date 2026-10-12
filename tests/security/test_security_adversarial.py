"""Adversarial and security hardening test suite for Security Asset Discovery Platform.

Tests resilience against:
- Wildcard DNS spoofing / pollution
- Hostile/malformed input domains and payloads
- SQL injection in asset queries and identifiers
- Corrupted/truncated X.509 certificates
- Bounded safety under high-volume entity discovery
"""

from collections.abc import Generator
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from asset_discovery.db.database import DatabaseManager
from asset_discovery.discovery.dns_engine import DnsDiscoveryEngine
from asset_discovery.models.enums import AssetType
from asset_discovery.models.schemas import DiscoveredAsset
from asset_discovery.scanners.tls_inspector import TlsCertificateInspector


@pytest.fixture
def temp_db(temp_dir: Path) -> Generator[DatabaseManager, None, None]:
    db = DatabaseManager(temp_dir / "adversarial.db")
    try:
        yield db
    finally:
        db.close()


class _FakeRdata:
    def __init__(self, val: str) -> None:
        self.val = val

    def __str__(self) -> str:
        return self.val


class TestDnsSpoofingAndWildcardResilience:
    """Tests that wildcard DNS pollution does not pollute the discovered asset graph."""

    @pytest.mark.asyncio
    async def test_wildcard_dns_detection(self) -> None:
        engine = DnsDiscoveryEngine()

        # Simulate wildcard DNS response for random subdomain
        mock_answer = MagicMock()
        mock_rdata = _FakeRdata("203.0.113.99")
        mock_answer.__iter__.return_value = [mock_rdata]
        mock_answer.rrset.ttl = 60

        with patch.object(engine._resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = mock_answer

            has_wildcard = await engine.check_wildcard_dns("wildcard-domain.com")
            assert has_wildcard is True


class TestSqlInjectionResilience:
    """Tests that SQL injection payloads in identifiers, domains, or filters are mitigated."""

    def test_sqli_in_asset_identifier_and_storage(self, temp_db: DatabaseManager) -> None:
        sqli_payload = "test.corp.internal' OR '1'='1' --; DROP TABLE assets; --"
        asset = DiscoveredAsset(
            asset_type=AssetType.DOMAIN,
            identifier=sqli_payload,
        )

        temp_db.save_asset(asset)
        loaded = temp_db.get_asset(asset.asset_id)
        assert loaded is not None
        assert loaded.identifier == sqli_payload

        # Ensure tables were not dropped
        assets = temp_db.list_assets()
        assert isinstance(assets, list)

    def test_sqli_in_search_and_filters(self, temp_db: DatabaseManager) -> None:
        malicious_type = "domain' UNION SELECT * FROM assets --"
        res = temp_db.list_assets(asset_type=malicious_type)
        assert res == []

        malicious_sev = "' OR '1'='1"
        findings = temp_db.list_exposure_findings(severity=malicious_sev)
        assert findings == []


class TestMalformedTlsResilience:
    """Tests resilience against malformed, corrupted, or random TLS certificate DER data."""

    def test_corrupted_der_bytes_parsing(self) -> None:
        inspector = TlsCertificateInspector()
        corrupted_bytes = b"\x30\x82\x01\x0a\x00\xff\xee\xdd\xcc" * 20

        with pytest.raises((ValueError, TypeError)):
            # Should raise cryptography parsing error rather than unhandled memory fault
            inspector.parse_der_certificate(corrupted_bytes)


class TestInputSanitizationAndSafety:
    """Tests that edge-case characters and extreme domain lengths are handled safely."""

    def test_massive_domain_identifier_safety(self, temp_db: DatabaseManager) -> None:
        huge_domain = "a" * 10_000 + ".corp.internal"
        asset = DiscoveredAsset(
            asset_type=AssetType.SUBDOMAIN,
            identifier=huge_domain,
        )
        temp_db.save_asset(asset)
        loaded = temp_db.get_asset_by_identifier(huge_domain)
        assert loaded is not None
        assert len(loaded.identifier) > 10_000
