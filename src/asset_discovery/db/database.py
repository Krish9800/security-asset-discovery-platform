"""Persistence manager for Security Asset Discovery Platform using SQLite in WAL mode."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Any

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


class DatabaseManager:
    """Thread-safe SQLite Write-Ahead Logging (WAL) inventory repository."""

    def __init__(self, db_path: Path | str = ":memory:") -> None:
        self.db_path = Path(db_path) if db_path != ":memory:" else ":memory:"
        self._lock = RLock()

        if isinstance(self.db_path, Path):
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        else:
            self._conn = sqlite3.connect(":memory:", check_same_thread=False)

        self._conn.row_factory = sqlite3.Row
        self._configure_pragmas()
        self.init_db()

    def _configure_pragmas(self) -> None:
        """Configure WAL journal mode, busy timeouts, and foreign key constraints."""
        with self._lock:
            cur = self._conn.cursor()
            if self.db_path != ":memory:":
                cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA synchronous=NORMAL;")
            cur.execute("PRAGMA foreign_keys=ON;")
            cur.execute("PRAGMA busy_timeout=5000;")
            cur.close()

    def init_db(self) -> None:
        """Initialize database schema from schema.sql."""
        schema_file = Path(__file__).parent / "schema.sql"
        schema_sql = schema_file.read_text(encoding="utf-8")
        with self._lock:
            self._conn.executescript(schema_sql)
            self._conn.commit()

    def save_asset(self, asset: DiscoveredAsset) -> None:
        """Save or update an asset and all associated DNS, service, and finding records."""
        with self._lock:
            # 1. Upsert Asset
            self._conn.execute(
                """
                INSERT OR REPLACE INTO assets (
                    asset_id, asset_type, identifier, parent_domain,
                    cloud_provider, risk_score, discovered_at, last_seen_at, tags_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    asset.asset_id,
                    asset.asset_type.value,
                    asset.identifier,
                    asset.parent_domain,
                    asset.cloud_provider.value,
                    asset.risk_score,
                    asset.discovered_at.isoformat(),
                    asset.last_seen_at.isoformat(),
                    json.dumps([t.value for t in asset.tags]),
                ),
            )

            # 2. Save DNS Records
            self._conn.execute("DELETE FROM dns_records WHERE asset_id = ?;", (asset.asset_id,))
            for rec in asset.dns_records:
                self._conn.execute(
                    """
                    INSERT INTO dns_records (asset_id, record_type, domain, value, ttl, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (
                        asset.asset_id,
                        rec.record_type.value,
                        rec.domain,
                        rec.value,
                        rec.ttl,
                        rec.discovered_at.isoformat(),
                    ),
                )

            # 3. Save Service Endpoints
            self._conn.execute(
                "DELETE FROM service_endpoints WHERE asset_id = ?;", (asset.asset_id,)
            )
            for svc in asset.services:
                tls_json = svc.tls_details.model_dump_json() if svc.tls_details else None
                self._conn.execute(
                    """
                    INSERT INTO service_endpoints (
                        service_id, asset_id, ip_address, port, protocol,
                        service_name, banner, is_open, response_time_ms,
                        discovered_at, tls_details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        svc.service_id,
                        asset.asset_id,
                        svc.ip_address,
                        svc.port,
                        svc.protocol.value,
                        svc.service_name,
                        svc.banner,
                        1 if svc.is_open else 0,
                        svc.response_time_ms,
                        svc.discovered_at.isoformat(),
                        tls_json,
                    ),
                )

            # 4. Save Exposure Findings
            self._conn.execute(
                "DELETE FROM exposure_findings WHERE asset_id = ?;", (asset.asset_id,)
            )
            for finding in asset.findings:
                self._conn.execute(
                    """
                    INSERT INTO exposure_findings (
                        finding_id, asset_id, title, description,
                        severity, tag, remediation, evidence_json, detected_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        finding.finding_id,
                        asset.asset_id,
                        finding.title,
                        finding.description,
                        finding.severity.value,
                        finding.tag.value,
                        finding.remediation,
                        json.dumps(finding.evidence),
                        finding.detected_at.isoformat(),
                    ),
                )

            self._conn.commit()

    def get_asset(self, asset_id: str) -> DiscoveredAsset | None:
        """Retrieve full asset model by asset_id including relational entities."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM assets WHERE asset_id = ?;", (asset_id,)
            ).fetchone()
            if not row:
                return None
            return self._row_to_asset(row)

    def get_asset_by_identifier(self, identifier: str) -> DiscoveredAsset | None:
        """Retrieve asset by unique domain, IP, or bucket identifier."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM assets WHERE identifier = ?;", (identifier,)
            ).fetchone()
            if not row:
                return None
            return self._row_to_asset(row)

    def list_assets(
        self,
        asset_type: str | None = None,
        min_risk_score: float | None = None,
        limit: int = 100,
    ) -> list[DiscoveredAsset]:
        """List assets matching optional filters."""
        query = "SELECT * FROM assets WHERE 1=1"
        params: list[Any] = []

        if asset_type:
            query += " AND asset_type = ?"
            params.append(asset_type)
        if min_risk_score is not None:
            query += " AND risk_score >= ?"
            params.append(min_risk_score)

        query += " ORDER BY risk_score DESC LIMIT ?;"
        params.append(limit)

        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
            return [self._row_to_asset(r) for r in rows]

    def list_exposure_findings(
        self,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[ExposureFinding]:
        """List exposure findings across assets."""
        query = "SELECT * FROM exposure_findings WHERE 1=1"
        params: list[Any] = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY detected_at DESC LIMIT ?;"
        params.append(limit)

        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
            findings: list[ExposureFinding] = []
            for r in rows:
                findings.append(
                    ExposureFinding(
                        finding_id=r["finding_id"],
                        title=r["title"],
                        description=r["description"],
                        severity=ExposureSeverity(r["severity"]),
                        tag=ShadowItTag(r["tag"]),
                        remediation=r["remediation"],
                        evidence=json.loads(r["evidence_json"]),
                        detected_at=datetime.fromisoformat(r["detected_at"]),
                    )
                )
            return findings

    def save_scan_report(self, report: DiscoveryScanReport) -> None:
        """Persist DiscoveryScanReport metadata."""
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO scan_reports (
                    scan_id, target_seed, started_at, completed_at,
                    total_assets, total_services, total_findings,
                    max_risk_score, summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    report.scan_id,
                    report.target_seed,
                    report.started_at.isoformat(),
                    report.completed_at.isoformat(),
                    report.total_assets,
                    report.total_services,
                    report.total_findings,
                    report.max_risk_score,
                    report.summary,
                ),
            )
            self._conn.commit()

    def get_scan_report(self, scan_id: str) -> DiscoveryScanReport | None:
        """Retrieve scan report by scan_id."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM scan_reports WHERE scan_id = ?;", (scan_id,)
            ).fetchone()
            if not row:
                return None
            return DiscoveryScanReport(
                scan_id=row["scan_id"],
                target_seed=row["target_seed"],
                started_at=datetime.fromisoformat(row["started_at"]),
                completed_at=datetime.fromisoformat(row["completed_at"]),
                total_assets=row["total_assets"],
                total_services=row["total_services"],
                total_findings=row["total_findings"],
                max_risk_score=row["max_risk_score"],
                summary=row["summary"],
            )

    def _row_to_asset(self, row: sqlite3.Row) -> DiscoveredAsset:
        """Reconstruct DiscoveredAsset with its foreign key relations."""
        asset_id = row["asset_id"]

        # Fetch DNS records
        dns_rows = self._conn.execute(
            "SELECT * FROM dns_records WHERE asset_id = ?;", (asset_id,)
        ).fetchall()
        dns_records = [
            DnsRecord(
                record_type=DnsRecordType(dr["record_type"]),
                domain=dr["domain"],
                value=dr["value"],
                ttl=dr["ttl"],
                discovered_at=datetime.fromisoformat(dr["discovered_at"]),
            )
            for dr in dns_rows
        ]

        # Fetch Service endpoints
        svc_rows = self._conn.execute(
            "SELECT * FROM service_endpoints WHERE asset_id = ?;", (asset_id,)
        ).fetchall()
        services: list[ServiceEndpoint] = []
        for sr in svc_rows:
            tls_details = None
            if sr["tls_details_json"]:
                tls_data = json.loads(sr["tls_details_json"])
                tls_details = TlsCertificateDetails(
                    subject_cn=tls_data["subject_cn"],
                    issuer_cn=tls_data["issuer_cn"],
                    subject_alt_names=tls_data.get("subject_alt_names", []),
                    valid_from=datetime.fromisoformat(tls_data["valid_from"]),
                    valid_until=datetime.fromisoformat(tls_data["valid_until"]),
                    is_expired=tls_data["is_expired"],
                    days_to_expiration=tls_data["days_to_expiration"],
                    tls_version=TlsVersion(tls_data.get("tls_version", "TLSv1.3")),
                    cipher_suite=tls_data.get("cipher_suite"),
                )

            services.append(
                ServiceEndpoint(
                    service_id=sr["service_id"],
                    ip_address=sr["ip_address"],
                    port=sr["port"],
                    protocol=ServiceProtocol(sr["protocol"]),
                    service_name=sr["service_name"],
                    banner=sr["banner"],
                    is_open=bool(sr["is_open"]),
                    response_time_ms=sr["response_time_ms"],
                    discovered_at=datetime.fromisoformat(sr["discovered_at"]),
                    tls_details=tls_details,
                )
            )

        # Fetch Findings
        exp_rows = self._conn.execute(
            "SELECT * FROM exposure_findings WHERE asset_id = ?;", (asset_id,)
        ).fetchall()
        findings = [
            ExposureFinding(
                finding_id=er["finding_id"],
                title=er["title"],
                description=er["description"],
                severity=ExposureSeverity(er["severity"]),
                tag=ShadowItTag(er["tag"]),
                remediation=er["remediation"],
                evidence=json.loads(er["evidence_json"]),
                detected_at=datetime.fromisoformat(er["detected_at"]),
            )
            for er in exp_rows
        ]

        return DiscoveredAsset(
            asset_id=row["asset_id"],
            asset_type=AssetType(row["asset_type"]),
            identifier=row["identifier"],
            parent_domain=row["parent_domain"],
            cloud_provider=CloudProvider(row["cloud_provider"]),
            tags=[ShadowItTag(t) for t in json.loads(row["tags_json"])],
            risk_score=row["risk_score"],
            discovered_at=datetime.fromisoformat(row["discovered_at"]),
            last_seen_at=datetime.fromisoformat(row["last_seen_at"]),
            dns_records=dns_records,
            services=services,
            findings=findings,
        )

    def close(self) -> None:
        """Close SQLite database connection safely."""
        with self._lock:
            self._conn.close()
