"""Domain schemas and entities for Security Asset Discovery Platform."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from asset_discovery.models.enums import (
    AssetType,
    CloudProvider,
    DnsRecordType,
    ExposureSeverity,
    ServiceProtocol,
    ShadowItTag,
    TlsVersion,
)


class DnsRecord(BaseModel):
    """Normalized representation of a resolved DNS record."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    record_type: DnsRecordType
    domain: str
    value: str
    ttl: int = Field(default=300, ge=0)
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TlsCertificateDetails(BaseModel):
    """Detailed metadata and hygiene attributes of a TLS/SSL certificate."""

    model_config = ConfigDict(extra="ignore")

    subject_cn: str = Field(description="Common Name in Certificate Subject")
    issuer_cn: str = Field(description="Issuer Common Name")
    subject_alt_names: list[str] = Field(
        default_factory=list, description="Subject Alternative Names (SANs)"
    )
    valid_from: datetime
    valid_until: datetime
    is_expired: bool = False
    days_to_expiration: int
    tls_version: TlsVersion = Field(default=TlsVersion.TLS1_3)
    cipher_suite: str | None = None
    serial_number: str | None = None
    fingerprint_sha256: str | None = None

    @field_validator("valid_from", "valid_until", mode="before")
    @classmethod
    def ensure_utc(cls, val: Any) -> datetime:
        """Ensure certificate timestamps are timezone-aware and UTC."""
        if isinstance(val, str):
            dt = datetime.fromisoformat(val)
        elif isinstance(val, datetime):
            dt = val
        else:
            raise ValueError(f"Invalid datetime: {val}")

        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)


class ServiceEndpoint(BaseModel):
    """Exposed network service discovered on an IP and port."""

    model_config = ConfigDict(extra="ignore")

    service_id: str = Field(default_factory=lambda: f"SVC-{uuid4().hex[:8].upper()}")
    ip_address: str
    port: int = Field(ge=1, le=65535)
    protocol: ServiceProtocol = Field(default=ServiceProtocol.TCP)
    service_name: str = Field(default="unknown")
    banner: str | None = None
    is_open: bool = True
    response_time_ms: float = Field(default=0.0, ge=0.0)
    tls_details: TlsCertificateDetails | None = None
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ExposureFinding(BaseModel):
    """Specific vulnerability, exposure, or shadow IT risk identified on an asset."""

    model_config = ConfigDict(extra="ignore")

    finding_id: str = Field(default_factory=lambda: f"EXP-{uuid4().hex[:8].upper()}")
    title: str
    description: str
    severity: ExposureSeverity
    tag: ShadowItTag
    remediation: str = Field(default="Review and restrict external access.")
    evidence: dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class DiscoveredAsset(BaseModel):
    """Canonical representation of an organization asset in the inventory graph."""

    model_config = ConfigDict(extra="ignore")

    asset_id: str = Field(default_factory=lambda: f"AST-{uuid4().hex[:8].upper()}")
    asset_type: AssetType
    identifier: str = Field(description="Primary identifier, e.g. domain name, IP, CIDR, or bucket")
    parent_domain: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    dns_records: list[DnsRecord] = Field(default_factory=list)
    services: list[ServiceEndpoint] = Field(default_factory=list)
    findings: list[ExposureFinding] = Field(default_factory=list)
    cloud_provider: CloudProvider = Field(default=CloudProvider.UNKNOWN)
    tags: list[ShadowItTag] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def calculate_risk_score(self) -> float:
        """Compute composite asset exposure risk score between 0.0 and 100.0."""
        score = 0.0

        # Findings impact
        for finding in self.findings:
            score += finding.severity.score_weight * 0.4

        # Exposed high-risk service ports impact
        high_risk_ports = {22, 3389, 3306, 5432, 6379, 27017, 9200}
        for svc in self.services:
            if svc.is_open and svc.port in high_risk_ports:
                score += 25.0

        # Expired TLS certificate impact
        for svc in self.services:
            if svc.tls_details and svc.tls_details.is_expired:
                score += 30.0

        # Shadow IT tag multipliers
        if ShadowItTag.STAGING_DEV in self.tags:
            score += 15.0
        if ShadowItTag.PUBLIC_BUCKET in self.tags:
            score += 35.0

        self.risk_score = min(max(round(score, 1), 0.0), 100.0)
        return self.risk_score


class DiscoveryScanReport(BaseModel):
    """Comprehensive discovery assessment report covering scanned assets."""

    model_config = ConfigDict(extra="ignore")

    scan_id: str = Field(default_factory=lambda: f"SCN-{uuid4().hex[:8].upper()}")
    target_seed: str = Field(description="Target domain or CIDR root")
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    assets_discovered: list[DiscoveredAsset] = Field(default_factory=list)
    total_assets: int = 0
    total_services: int = 0
    total_findings: int = 0
    max_risk_score: float = 0.0
    summary: str = Field(default="")
