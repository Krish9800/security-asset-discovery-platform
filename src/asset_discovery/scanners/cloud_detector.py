"""Cloud infrastructure and Shadow IT heuristic detector."""

import re

from asset_discovery.models.enums import CloudProvider, ExposureSeverity, ShadowItTag
from asset_discovery.models.schemas import DiscoveredAsset, ExposureFinding


class CloudShadowItDetector:
    """Heuristic detector identifying cloud assets, public storage buckets, and shadow IT."""

    # Patterns indicating staging, development, or internal test assets
    STAGING_PATTERNS = re.compile(
        r"(?:staging|dev|development|test|qa|demo|internal|uat|sandbox|preview|poc)[\.-]",
        re.IGNORECASE,
    )

    # Patterns for public cloud storage / CDN endpoints
    AWS_S3_PATTERN = re.compile(r"s3[\.-].*?\.amazonaws\.com|s3\.amazonaws\.com", re.IGNORECASE)
    AZURE_BLOB_PATTERN = re.compile(r"\.blob\.core\.windows\.net", re.IGNORECASE)
    GCP_STORAGE_PATTERN = re.compile(r"storage\.googleapis\.com", re.IGNORECASE)

    # Administrative naming indicators
    ADMIN_PATTERNS = re.compile(
        r"(?:admin|dashboard|cpanel|webmin|phpmyadmin|kibana|grafana|jenkins|gitlab|bastion)[\.-]",
        re.IGNORECASE,
    )

    def analyze_asset(self, asset: DiscoveredAsset) -> list[ExposureFinding]:
        """Analyze discovered asset and tag shadow IT, staging, or cloud exposures."""
        findings: list[ExposureFinding] = []
        ident = asset.identifier.lower()

        # 1. Staging / Dev Shadow IT detection
        if self.STAGING_PATTERNS.search(ident):
            if ShadowItTag.STAGING_DEV not in asset.tags:
                asset.tags.append(ShadowItTag.STAGING_DEV)

            findings.append(
                ExposureFinding(
                    title="Exposed Staging/Development Environment",
                    description=(
                        f"Asset '{asset.identifier}' appears to be a non-production environment "
                        "exposed externally to the Internet."
                    ),
                    severity=ExposureSeverity.MEDIUM,
                    tag=ShadowItTag.STAGING_DEV,
                    remediation="Restrict access via VPN, IP whitelisting, or SSO gateway.",
                    evidence={"identifier": asset.identifier},
                )
            )

        # 2. Administrative interface naming detection
        if self.ADMIN_PATTERNS.search(ident):
            if ShadowItTag.ADMIN_INTERFACE not in asset.tags:
                asset.tags.append(ShadowItTag.ADMIN_INTERFACE)

            findings.append(
                ExposureFinding(
                    title="Publicly Accessible Administration Endpoint",
                    description=(
                        f"Asset '{asset.identifier}' indicates an exposed administrative portal."
                    ),
                    severity=ExposureSeverity.HIGH,
                    tag=ShadowItTag.ADMIN_INTERFACE,
                    remediation="Place administrative tools behind zero-trust access or VPN.",
                    evidence={"identifier": asset.identifier},
                )
            )

        # 3. Cloud Provider & Storage Bucket Detection
        provider = self.identify_cloud_provider(asset)
        asset.cloud_provider = provider

        if self._is_cloud_bucket(asset):
            if ShadowItTag.PUBLIC_BUCKET not in asset.tags:
                asset.tags.append(ShadowItTag.PUBLIC_BUCKET)

            findings.append(
                ExposureFinding(
                    title="Exposed Cloud Storage Bucket",
                    description=(
                        f"Asset '{asset.identifier}' resolves to a public cloud storage endpoint."
                    ),
                    severity=ExposureSeverity.HIGH,
                    tag=ShadowItTag.PUBLIC_BUCKET,
                    remediation="Verify bucket ACLs and IAM policies to prevent unauthorized access.",
                    evidence={"cloud_provider": provider.value},
                )
            )

        # 4. Check for expired TLS certificates in services
        for svc in asset.services:
            if svc.tls_details and svc.tls_details.is_expired:
                if ShadowItTag.EXPIRED_CERT not in asset.tags:
                    asset.tags.append(ShadowItTag.EXPIRED_CERT)

                findings.append(
                    ExposureFinding(
                        title="Expired SSL/TLS Certificate",
                        description=(
                            f"Port {svc.port} presents an expired TLS certificate "
                            f"(expired {abs(svc.tls_details.days_to_expiration)} days ago)."
                        ),
                        severity=ExposureSeverity.HIGH,
                        tag=ShadowItTag.EXPIRED_CERT,
                        remediation="Renew certificate immediately with a trusted certificate authority.",
                        evidence={
                            "port": svc.port,
                            "valid_until": svc.tls_details.valid_until.isoformat(),
                        },
                    )
                )

        # Update findings on asset and calculate new risk score
        asset.findings.extend(findings)
        asset.calculate_risk_score()
        return findings

    def identify_cloud_provider(self, asset: DiscoveredAsset) -> CloudProvider:
        """Infer cloud provider based on CNAME, DNS records, or domain naming."""
        ident = asset.identifier.lower()
        all_text = [ident] + [r.value.lower() for r in asset.dns_records]
        combined = " ".join(all_text)

        if "amazonaws.com" in combined or "awsglobalaccelerator" in combined:
            return CloudProvider.AWS
        if "azure" in combined or "windows.net" in combined:
            return CloudProvider.AZURE
        if "google" in combined or "1e100.net" in combined or "appspot.com" in combined:
            return CloudProvider.GCP
        if "cloudflare" in combined:
            return CloudProvider.CLOUDFLARE
        if "digitalocean" in combined:
            return CloudProvider.DIGITALOCEAN

        return CloudProvider.UNKNOWN

    def _is_cloud_bucket(self, asset: DiscoveredAsset) -> bool:
        """Check if asset or any of its CNAMEs match public cloud storage buckets."""
        ident = asset.identifier
        cnames = [r.value for r in asset.dns_records if r.record_type.value == "CNAME"]
        candidates = [ident] + cnames

        for c in candidates:
            if (
                self.AWS_S3_PATTERN.search(c)
                or self.AZURE_BLOB_PATTERN.search(c)
                or self.GCP_STORAGE_PATTERN.search(c)
            ):
                return True
        return False
