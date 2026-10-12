"""Typer command-line interface for Security Asset Discovery Platform."""

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from asset_discovery import __version__
from asset_discovery.config.settings import get_settings
from asset_discovery.db.database import DatabaseManager
from asset_discovery.discovery.dns_engine import DnsDiscoveryEngine
from asset_discovery.engine.scoring_engine import ExposureScoringEngine
from asset_discovery.models.enums import AssetType
from asset_discovery.models.schemas import DiscoveredAsset, DiscoveryScanReport
from asset_discovery.scanners.cloud_detector import CloudShadowItDetector
from asset_discovery.scanners.service_scanner import ServiceExposureScanner
from asset_discovery.scanners.tls_inspector import TlsCertificateInspector

app = typer.Typer(
    name="asset-discovery",
    help="Security Asset Discovery and External Attack Surface Management (EASM) CLI",
    add_completion=False,
)
console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold cyan]Security Asset Discovery Platform[/bold cyan] v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """Security Asset Discovery Platform CLI."""


@app.command("scan")
def scan_command(
    target: str = typer.Argument(..., help="Target domain to discover (e.g. corp.internal)"),
    db_path: Path | None = typer.Option(None, "--db", help="Path to SQLite inventory database"),
) -> None:
    """Run an attack surface discovery scan against a target domain."""
    settings = get_settings()
    active_db = Path(db_path) if db_path else settings.db_path

    console.print(
        f"[bold green]Starting EASM discovery scan on:[/bold green] [yellow]{target}[/yellow]"
    )

    async def _run() -> DiscoveryScanReport:
        db = DatabaseManager(active_db)
        dns_engine = DnsDiscoveryEngine(nameservers=settings.default_dns_resolvers)
        scanner = ServiceExposureScanner()
        tls_inspector = TlsCertificateInspector()
        detector = CloudShadowItDetector()
        scoring = ExposureScoringEngine()

        # 1. DNS discovery
        records = await dns_engine.resolve_all_records(target)
        ips = [r.value for r in records if r.record_type.value in ("A", "AAAA")]
        root_asset = DiscoveredAsset(
            asset_type=AssetType.DOMAIN,
            identifier=target,
            ip_addresses=ips,
            dns_records=records,
        )
        subs = await dns_engine.enumerate_subdomains(target)
        all_assets = [root_asset] + subs

        total_services = 0
        total_findings = 0

        # 2. Port scan & enrichment
        for a in all_assets:
            for ip in a.ip_addresses:
                endpoints = await scanner.scan_target_ports(ip)
                for ep in endpoints:
                    if ep.port in (443, 8443):
                        ep.tls_details = await tls_inspector.inspect_certificate(
                            a.identifier, ep.port
                        )
                a.services.extend(endpoints)
                total_services += len(endpoints)

            findings = detector.analyze_asset(a)
            total_findings += len(findings)
            scoring.score_asset(a)
            db.save_asset(a)

        metrics = scoring.score_inventory(all_assets)
        report = DiscoveryScanReport(
            target_seed=target,
            total_assets=len(all_assets),
            total_services=total_services,
            total_findings=total_findings,
            max_risk_score=metrics["max_risk"],
            summary=f"Discovered {len(all_assets)} assets across {target}",
        )
        db.save_scan_report(report)
        db.close()
        return report

    report = asyncio.run(_run())

    console.print("\n[bold green]Scan Completed Successfully![/bold green]")
    table = Table(title=f"Scan Summary: {target}")
    table.add_column("Metric", style="bold")
    table.add_column("Value", style="cyan")

    table.add_row("Scan ID", report.scan_id)
    table.add_row("Assets Discovered", str(report.total_assets))
    table.add_row("Services Exposed", str(report.total_services))
    table.add_row("Security Findings", str(report.total_findings))
    table.add_row("Max Risk Score", f"{report.max_risk_score:.1f} / 100")

    console.print(table)


@app.command("assets")
def list_assets_command(
    db_path: Path | None = typer.Option(None, "--db", help="Path to SQLite inventory database"),
    min_risk: float = typer.Option(0.0, "--min-risk", help="Minimum risk score filter"),
) -> None:
    """List discovered infrastructure assets in the repository."""
    settings = get_settings()
    active_db = Path(db_path) if db_path else settings.db_path

    db = DatabaseManager(active_db)
    assets = db.list_assets(min_risk_score=min_risk)
    db.close()

    if not assets:
        console.print("[yellow]No assets found matching criteria.[/yellow]")
        return

    table = Table(title="Discovered Infrastructure Assets")
    table.add_column("ID", style="dim")
    table.add_column("Type", style="magenta")
    table.add_column("Identifier", style="bold")
    table.add_column("IPs", style="green")
    table.add_column("Services", style="cyan")
    table.add_column("Cloud", style="blue")
    table.add_column("Risk Score", style="red")

    for a in assets:
        svc_str = ", ".join(f"{s.port}/{s.service_name}" for s in a.services) or "none"
        ip_str = ", ".join(a.ip_addresses) or "none"
        table.add_row(
            a.asset_id,
            a.asset_type.value,
            a.identifier,
            ip_str,
            svc_str,
            a.cloud_provider.value,
            f"{a.risk_score:.1f}",
        )

    console.print(table)


@app.command("exposures")
def list_exposures_command(
    db_path: Path | None = typer.Option(None, "--db", help="Path to SQLite inventory database"),
    severity: str | None = typer.Option(None, "--severity", help="Filter by severity"),
) -> None:
    """List security exposures and shadow IT findings."""
    settings = get_settings()
    active_db = Path(db_path) if db_path else settings.db_path

    db = DatabaseManager(active_db)
    findings = db.list_exposure_findings(severity=severity)
    db.close()

    if not findings:
        console.print("[green]No exposure findings identified.[/green]")
        return

    table = Table(title="Security Exposure & Shadow IT Findings")
    table.add_column("ID", style="dim")
    table.add_column("Severity", style="bold red")
    table.add_column("Tag", style="yellow")
    table.add_column("Title", style="bold")
    table.add_column("Remediation", style="green")

    for f in findings:
        table.add_row(
            f.finding_id,
            f.severity.value.upper(),
            f.tag.value,
            f.title,
            f.remediation,
        )

    console.print(table)


@app.command("report")
def show_report_command(
    scan_id: str = typer.Argument(..., help="Scan ID to display report for"),
    db_path: Path | None = typer.Option(None, "--db", help="Path to SQLite inventory database"),
) -> None:
    """Display discovery scan report details."""
    settings = get_settings()
    active_db = Path(db_path) if db_path else settings.db_path

    db = DatabaseManager(active_db)
    report = db.get_scan_report(scan_id)
    db.close()

    if not report:
        console.print(f"[red]Scan report '{scan_id}' not found.[/red]")
        raise typer.Exit(code=1)

    console.print(f"\n[bold cyan]Scan Report Details:[/bold cyan] {report.scan_id}")
    console.print(f"Target: [bold]{report.target_seed}[/bold]")
    console.print(f"Summary: {report.summary}")
    console.print(f"Risk Score: [bold red]{report.max_risk_score:.1f}[/bold red]")
