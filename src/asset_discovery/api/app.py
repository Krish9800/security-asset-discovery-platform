"""FastAPI application control plane for Security Asset Discovery Platform."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, status
from pydantic import BaseModel, Field

from asset_discovery.config.settings import PlatformSettings, get_settings
from asset_discovery.db.database import DatabaseManager
from asset_discovery.discovery.dns_engine import DnsDiscoveryEngine
from asset_discovery.engine.scoring_engine import ExposureScoringEngine
from asset_discovery.models.enums import AssetType
from asset_discovery.models.schemas import DiscoveredAsset, DiscoveryScanReport, ExposureFinding
from asset_discovery.scanners.cloud_detector import CloudShadowItDetector
from asset_discovery.scanners.service_scanner import ServiceExposureScanner
from asset_discovery.scanners.tls_inspector import TlsCertificateInspector


class ScanRequest(BaseModel):
    """Payload to initiate an external attack surface discovery scan."""

    target_domain: str = Field(description="Root domain seed (e.g. corp.internal)")
    subdomain_wordlist: list[str] | None = Field(
        default=None, description="Optional custom subdomain wordlist"
    )
    probe_ports: list[int] | None = Field(
        default=None, description="Optional custom ports to probe"
    )


class ScanResponse(BaseModel):
    """Scan execution result summary."""

    scan_id: str
    target_seed: str
    total_assets: int
    total_services: int
    total_findings: int
    max_risk_score: float
    summary: str


class AppState:
    """Singleton application state holding dependencies."""

    def __init__(self, settings: PlatformSettings) -> None:
        self.settings = settings
        self.db = DatabaseManager(settings.db_path)
        self.dns_engine = DnsDiscoveryEngine(
            nameservers=settings.default_dns_resolvers,
            timeout_seconds=settings.dns_timeout_seconds,
        )
        self.service_scanner = ServiceExposureScanner(
            timeout_seconds=settings.tcp_scan_timeout_seconds,
            max_concurrency=settings.max_concurrent_probes,
        )
        self.tls_inspector = TlsCertificateInspector(
            handshake_timeout_seconds=settings.tls_handshake_timeout_seconds
        )
        self.cloud_detector = CloudShadowItDetector()
        self.scoring_engine = ExposureScoringEngine()


_state: AppState | None = None


def get_app_state() -> AppState:
    """Retrieve initialized application state singleton."""
    global _state
    if _state is None:
        _state = AppState(get_settings())
    return _state


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager for startup and shutdown."""
    state = get_app_state()
    yield
    state.db.close()


app = FastAPI(
    title="Security Asset Discovery Platform",
    description="External Attack Surface Management (EASM) and Shadow IT Discovery Control Plane",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health", tags=["System"])
async def health_check() -> dict[str, str]:
    """Liveness probe returning service health status."""
    return {"status": "ok", "service": "security-asset-discovery-platform"}


@app.post(
    "/api/v1/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Scans"],
)
async def launch_discovery_scan(req: ScanRequest) -> ScanResponse:
    """Run an attack surface discovery scan on target domain and persist discovered assets."""
    state = get_app_state()
    target = req.target_domain.strip().lower()

    if not target:
        raise HTTPException(status_code=400, detail="Target domain cannot be empty")

    # 1. Resolve root domain records
    root_records = await state.dns_engine.resolve_all_records(target)
    root_ips = [r.value for r in root_records if r.record_type.value in ("A", "AAAA")]

    root_asset = DiscoveredAsset(
        asset_type=AssetType.DOMAIN,
        identifier=target,
        ip_addresses=root_ips,
        dns_records=root_records,
    )

    # 2. Enumerate subdomains
    discovered_subdomains = await state.dns_engine.enumerate_subdomains(
        base_domain=target,
        wordlist=req.subdomain_wordlist,
    )

    all_assets = [root_asset] + discovered_subdomains
    total_services_count = 0
    total_findings_count = 0

    # 3. Port scan and enrich each asset
    for asset in all_assets:
        for ip in asset.ip_addresses:
            endpoints = await state.service_scanner.scan_target_ports(
                ip_address=ip,
                ports=req.probe_ports,
            )
            # Inspect TLS certificates on web/TLS ports
            for ep in endpoints:
                if ep.port in (443, 8443):
                    cert = await state.tls_inspector.inspect_certificate(asset.identifier, ep.port)
                    ep.tls_details = cert

            asset.services.extend(endpoints)
            total_services_count += len(endpoints)

        # 4. Run cloud and shadow IT heuristics
        findings = state.cloud_detector.analyze_asset(asset)
        total_findings_count += len(findings)

        # 5. Score asset risk
        state.scoring_engine.score_asset(asset)

        # 6. Save asset to database
        state.db.save_asset(asset)

    # Calculate overall inventory risk metrics
    inventory_metrics = state.scoring_engine.score_inventory(all_assets)
    summary_text = (
        f"Discovery scan on '{target}' completed with {len(all_assets)} assets, "
        f"{total_services_count} open services, and {total_findings_count} exposure findings."
    )

    report = DiscoveryScanReport(
        target_seed=target,
        total_assets=len(all_assets),
        total_services=total_services_count,
        total_findings=total_findings_count,
        max_risk_score=inventory_metrics["max_risk"],
        summary=summary_text,
    )
    state.db.save_scan_report(report)

    return ScanResponse(
        scan_id=report.scan_id,
        target_seed=report.target_seed,
        total_assets=report.total_assets,
        total_services=report.total_services,
        total_findings=report.total_findings,
        max_risk_score=report.max_risk_score,
        summary=report.summary,
    )


@app.get("/api/v1/assets", response_model=list[DiscoveredAsset], tags=["Assets"])
async def list_assets(
    asset_type: str | None = Query(default=None, description="Filter by asset type"),
    min_risk_score: float | None = Query(default=None, description="Filter by minimum risk score"),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[DiscoveredAsset]:
    """List discovered infrastructure assets in the repository."""
    state = get_app_state()
    return state.db.list_assets(asset_type=asset_type, min_risk_score=min_risk_score, limit=limit)


@app.get("/api/v1/assets/{asset_id}", response_model=DiscoveredAsset, tags=["Assets"])
async def get_asset_by_id(asset_id: str) -> DiscoveredAsset:
    """Retrieve full details of an asset by ID."""
    state = get_app_state()
    asset = state.db.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@app.get("/api/v1/exposures", response_model=list[ExposureFinding], tags=["Exposures"])
async def list_exposures(
    severity: str | None = Query(default=None, description="Filter by severity level"),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[ExposureFinding]:
    """List exposure findings across all assets."""
    state = get_app_state()
    return state.db.list_exposure_findings(severity=severity, limit=limit)
