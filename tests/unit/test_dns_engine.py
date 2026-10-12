"""Unit tests for multi-source DNS resolution and subdomain enumeration engine."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from asset_discovery.discovery.dns_engine import DnsDiscoveryEngine
from asset_discovery.models.enums import AssetType, DnsRecordType
from asset_discovery.models.schemas import DnsRecord


@pytest.mark.asyncio
async def test_dns_engine_initialization() -> None:
    """Verify DnsDiscoveryEngine constructor with custom nameservers."""
    engine = DnsDiscoveryEngine(nameservers=["9.9.9.9"], timeout_seconds=1.5)
    assert engine.nameservers == ["9.9.9.9"]
    assert engine.timeout_seconds == 1.5


class _FakeRdata:
    def __init__(self, val: str) -> None:
        self.val = val

    def __str__(self) -> str:
        return self.val


@pytest.mark.asyncio
async def test_dns_resolve_record_success() -> None:
    """Verify DNS record resolution parsing responses into DnsRecord models."""
    engine = DnsDiscoveryEngine()

    mock_answer = MagicMock()
    mock_rdata = _FakeRdata("93.184.216.34")
    mock_answer.__iter__.return_value = [mock_rdata]
    mock_answer.rrset.ttl = 300

    with patch.object(engine._resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
        mock_resolve.return_value = mock_answer

        records = await engine.resolve_record("example.com", DnsRecordType.A)
        assert len(records) == 1
        assert records[0].record_type == DnsRecordType.A
        assert records[0].domain == "example.com"
        assert records[0].value == "93.184.216.34"
        assert records[0].ttl == 300


@pytest.mark.asyncio
async def test_dns_resolve_record_error_handling() -> None:
    """Verify resolver errors return an empty list gracefully."""
    import dns.resolver

    engine = DnsDiscoveryEngine()

    with patch.object(engine._resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NXDOMAIN
        records = await engine.resolve_record("nonexistent.local", DnsRecordType.A)
        assert records == []


@pytest.mark.asyncio
async def test_dns_reverse_ptr() -> None:
    """Verify reverse DNS PTR resolution."""
    engine = DnsDiscoveryEngine()

    mock_answer = MagicMock()
    mock_rdata = _FakeRdata("ptr.example.com.")
    mock_answer.__iter__.return_value = [mock_rdata]

    with patch.object(engine._resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
        mock_resolve.return_value = mock_answer
        hostname = await engine.reverse_dns_ptr("192.0.2.1")
        assert hostname == "ptr.example.com"


@pytest.mark.asyncio
async def test_subdomain_enumeration() -> None:
    """Verify subdomain enumeration with simulated wordlist."""
    engine = DnsDiscoveryEngine()

    async def mock_resolve_record(domain: str, record_type: DnsRecordType) -> list[DnsRecord]:
        if "api.corp.internal" in domain and record_type == DnsRecordType.A:
            return [
                DnsRecord(
                    record_type=DnsRecordType.A,
                    domain="api.corp.internal",
                    value="10.0.0.1",
                    ttl=300,
                )
            ]
        return []

    with (
        patch.object(engine, "resolve_record", side_effect=mock_resolve_record),
        patch.object(engine, "check_wildcard_dns", new_callable=AsyncMock) as mock_wildcard,
    ):
        mock_wildcard.return_value = False

        discovered = await engine.enumerate_subdomains(
            "corp.internal", wordlist=["api", "dev", "test"]
        )

        assert len(discovered) == 1
        asset = discovered[0]
        assert asset.asset_type == AssetType.SUBDOMAIN
        assert asset.identifier == "api.corp.internal"
        assert asset.parent_domain == "corp.internal"
        assert asset.ip_addresses == ["10.0.0.1"]
