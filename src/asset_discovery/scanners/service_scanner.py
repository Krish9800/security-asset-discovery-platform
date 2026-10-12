"""Asynchronous TCP port and service exposure scanner."""

import asyncio
import time
from datetime import UTC, datetime

from asset_discovery.models.enums import ServiceProtocol
from asset_discovery.models.schemas import ServiceEndpoint


class ServiceExposureScanner:
    """Asynchronous, non-intrusive TCP socket scanner for exposed network services."""

    DEFAULT_PROBE_PORTS: dict[int, tuple[str, ServiceProtocol]] = {
        # Remote Administration
        22: ("ssh", ServiceProtocol.SSH),
        3389: ("rdp", ServiceProtocol.RDP),
        # Databases & In-Memory Stores
        3306: ("mysql", ServiceProtocol.MYSQL),
        5432: ("postgresql", ServiceProtocol.POSTGRESQL),
        6379: ("redis", ServiceProtocol.REDIS),
        27017: ("mongodb", ServiceProtocol.MONGODB),
        # Web & HTTP APIs
        80: ("http", ServiceProtocol.HTTP),
        443: ("https", ServiceProtocol.HTTPS),
        8080: ("http-proxy", ServiceProtocol.HTTP),
        8443: ("https-alt", ServiceProtocol.HTTPS),
    }

    def __init__(
        self,
        timeout_seconds: float = 2.0,
        max_concurrency: int = 50,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_concurrency = max_concurrency
        self._semaphore = asyncio.Semaphore(self.max_concurrency)

    async def probe_port(
        self,
        ip_address: str,
        port: int,
        default_service_name: str | None = None,
        protocol: ServiceProtocol = ServiceProtocol.TCP,
    ) -> ServiceEndpoint | None:
        """Probe an individual TCP port on an IP address asynchronously."""
        target_ip = ip_address.strip()
        svc_name = (
            default_service_name
            or self.DEFAULT_PROBE_PORTS.get(port, ("unknown", ServiceProtocol.TCP))[0]
        )
        svc_proto = (
            protocol
            if default_service_name
            else self.DEFAULT_PROBE_PORTS.get(port, ("unknown", ServiceProtocol.TCP))[1]
        )

        async with self._semaphore:
            start_time = time.monotonic()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target_ip, port),
                    timeout=self.timeout_seconds,
                )
                elapsed_ms = round((time.monotonic() - start_time) * 1000.0, 2)

                banner: str | None = None
                # Non-intrusively read initial banner (if sent immediately by SSH/FTP/etc)
                try:
                    raw_banner = await asyncio.wait_for(reader.read(256), timeout=0.5)
                    if raw_banner:
                        banner = raw_banner.decode("utf-8", errors="replace").strip()
                except Exception:
                    banner = None

                writer.close()
                await writer.wait_closed()

                return ServiceEndpoint(
                    ip_address=target_ip,
                    port=port,
                    protocol=svc_proto,
                    service_name=svc_name,
                    banner=banner,
                    is_open=True,
                    response_time_ms=elapsed_ms,
                    discovered_at=datetime.now(UTC),
                )
            except (TimeoutError, OSError):
                # Port closed or timed out
                return None
            except Exception:
                return None

    async def scan_target_ports(
        self,
        ip_address: str,
        ports: list[int] | None = None,
    ) -> list[ServiceEndpoint]:
        """Scan a list of ports (or default exposed ports) on a target IP address."""
        target_ports = ports or list(self.DEFAULT_PROBE_PORTS.keys())
        tasks = [self.probe_port(ip_address, p) for p in target_ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_endpoints: list[ServiceEndpoint] = []
        for res in results:
            if isinstance(res, ServiceEndpoint) and res.is_open:
                open_endpoints.append(res)

        return open_endpoints

    async def scan_multiple_hosts(
        self,
        ip_addresses: list[str],
        ports: list[int] | None = None,
    ) -> dict[str, list[ServiceEndpoint]]:
        """Scan multiple host IPs concurrently."""
        results: dict[str, list[ServiceEndpoint]] = {}
        for ip in ip_addresses:
            endpoints = await self.scan_target_ports(ip, ports)
            results[ip] = endpoints
        return results
