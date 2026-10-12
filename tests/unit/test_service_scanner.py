"""Unit tests for asynchronous TCP port and service exposure scanner."""

from unittest.mock import AsyncMock, patch

import pytest

from asset_discovery.models.enums import ServiceProtocol
from asset_discovery.scanners.service_scanner import ServiceExposureScanner


@pytest.mark.asyncio
async def test_service_scanner_initialization() -> None:
    """Verify ServiceExposureScanner constructor defaults."""
    scanner = ServiceExposureScanner(timeout_seconds=1.0, max_concurrency=25)
    assert scanner.timeout_seconds == 1.0
    assert scanner.max_concurrency == 25


@pytest.mark.asyncio
async def test_probe_port_open_service() -> None:
    """Verify successful detection of an open port with banner."""
    scanner = ServiceExposureScanner()

    mock_reader = AsyncMock()
    mock_reader.read.return_value = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

    mock_writer = AsyncMock()
    mock_writer.close = lambda: None
    mock_writer.wait_closed = AsyncMock()

    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_connect:
        mock_connect.return_value = (mock_reader, mock_writer)

        endpoint = await scanner.probe_port("192.168.1.1", 22)
        assert endpoint is not None
        assert endpoint.port == 22
        assert endpoint.service_name == "ssh"
        assert endpoint.protocol == ServiceProtocol.SSH
        assert endpoint.banner == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        assert endpoint.is_open is True


@pytest.mark.asyncio
async def test_probe_port_closed_or_timeout() -> None:
    """Verify connection timeout/refusal gracefully returns None."""
    scanner = ServiceExposureScanner(timeout_seconds=0.1)

    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_connect:
        mock_connect.side_effect = TimeoutError()

        endpoint = await scanner.probe_port("192.168.1.1", 3389)
        assert endpoint is None


@pytest.mark.asyncio
async def test_scan_target_ports() -> None:
    """Verify scanning multiple ports on a target IP."""
    scanner = ServiceExposureScanner()

    async def mock_probe_port(ip: str, port: int) -> object:
        if port in (80, 443):
            return await ServiceExposureScanner.probe_port(scanner, ip, port)
        return None

    mock_reader = AsyncMock()
    mock_reader.read.return_value = b""
    mock_writer = AsyncMock()
    mock_writer.close = lambda: None
    mock_writer.wait_closed = AsyncMock()

    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_connect:
        mock_connect.return_value = (mock_reader, mock_writer)

        endpoints = await scanner.scan_target_ports("10.0.0.5", ports=[80, 443])
        assert len(endpoints) == 2
        ports = [e.port for e in endpoints]
        assert 80 in ports
        assert 443 in ports


@pytest.mark.asyncio
async def test_scan_multiple_hosts() -> None:
    """Verify scanning across multiple hosts."""
    scanner = ServiceExposureScanner()

    with patch.object(scanner, "scan_target_ports", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = []
        res = await scanner.scan_multiple_hosts(["10.0.0.1", "10.0.0.2"], ports=[22])
        assert "10.0.0.1" in res
        assert "10.0.0.2" in res
