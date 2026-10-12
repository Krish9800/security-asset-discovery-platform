"""Exposure risk and asset criticality scoring engine."""

from asset_discovery.models.enums import ExposureSeverity, ShadowItTag
from asset_discovery.models.schemas import DiscoveredAsset


class ExposureScoringEngine:
    """Calculates multi-factor attack surface risk scores (0.0 to 100.0) for assets and inventories."""

    HIGH_RISK_PORTS: dict[int, tuple[float, str]] = {
        22: (25.0, "SSH administration exposed to public Internet"),
        3389: (40.0, "RDP remote desktop service exposed to public Internet"),
        3306: (35.0, "MySQL database port exposed without firewall boundary"),
        5432: (35.0, "PostgreSQL database port exposed without firewall boundary"),
        6379: (45.0, "Redis cache port exposed to public Internet"),
        27017: (45.0, "MongoDB database port exposed without boundary"),
        9200: (35.0, "Elasticsearch cluster REST API exposed"),
    }

    SEVERITY_WEIGHTS: dict[ExposureSeverity, float] = {
        ExposureSeverity.INFO: 0.0,
        ExposureSeverity.LOW: 5.0,
        ExposureSeverity.MEDIUM: 15.0,
        ExposureSeverity.HIGH: 30.0,
        ExposureSeverity.CRITICAL: 50.0,
    }

    SHADOW_IT_TAG_WEIGHTS: dict[ShadowItTag, float] = {
        ShadowItTag.STAGING_DEV: 15.0,
        ShadowItTag.ADMIN_INTERFACE: 20.0,
        ShadowItTag.PUBLIC_BUCKET: 35.0,
        ShadowItTag.DANGLING_DNS: 40.0,
        ShadowItTag.UNSECURED_DATABASE: 45.0,
        ShadowItTag.EXPIRED_CERT: 25.0,
        ShadowItTag.INTERNAL_NAMING: 10.0,
    }

    def score_asset(self, asset: DiscoveredAsset) -> float:
        """Calculate and update risk score for an individual asset."""
        raw_score = 0.0

        # 1. Findings risk contribution
        for finding in asset.findings:
            raw_score += self.SEVERITY_WEIGHTS.get(finding.severity, 0.0)

        # 2. Exposed ports risk contribution
        for svc in asset.services:
            if svc.is_open and svc.port in self.HIGH_RISK_PORTS:
                raw_score += self.HIGH_RISK_PORTS[svc.port][0]

        # 3. TLS Certificate posture contribution
        for svc in asset.services:
            if svc.tls_details:
                if svc.tls_details.is_expired:
                    raw_score += 25.0
                elif svc.tls_details.days_to_expiration < 14:
                    raw_score += 10.0
                if svc.tls_details.tls_version.is_deprecated:
                    raw_score += 20.0

        # 4. Shadow IT tag contribution
        for tag in set(asset.tags):
            raw_score += self.SHADOW_IT_TAG_WEIGHTS.get(tag, 5.0)

        # Clamp between 0.0 and 100.0 with 1 decimal precision
        final_score = min(max(round(raw_score, 1), 0.0), 100.0)
        asset.risk_score = final_score
        return final_score

    def score_inventory(self, assets: list[DiscoveredAsset]) -> dict[str, float]:
        """Score entire inventory and calculate aggregate metrics."""
        if not assets:
            return {"max_risk": 0.0, "average_risk": 0.0, "high_risk_count": 0.0}

        scores = [self.score_asset(a) for a in assets]
        max_score = max(scores)
        avg_score = round(sum(scores) / len(scores), 1)
        high_risk_assets = sum(1 for s in scores if s >= 50.0)

        return {
            "max_risk": max_score,
            "average_risk": avg_score,
            "high_risk_count": float(high_risk_assets),
        }
