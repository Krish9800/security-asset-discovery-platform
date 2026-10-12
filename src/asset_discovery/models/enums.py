"""Domain enumerations for Security Asset Discovery Platform."""

from enum import StrEnum


class AssetType(StrEnum):
    """Categorization of discovered infrastructure assets."""

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    CIDR = "cidr"
    SERVICE = "service"
    CLOUD_BUCKET = "cloud_bucket"


class DnsRecordType(StrEnum):
    """Supported DNS resource record types."""

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    TXT = "TXT"
    PTR = "PTR"
    NS = "NS"
    SOA = "SOA"


class ServiceProtocol(StrEnum):
    """Transport and application layer protocols."""

    TCP = "tcp"
    UDP = "udp"
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    RDP = "rdp"
    REDIS = "redis"
    MONGODB = "mongodb"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"


class ExposureSeverity(StrEnum):
    """Severity ratings for exposed services and security findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score_weight(self) -> float:
        """Numerical weighting for risk calculations."""
        weights = {
            ExposureSeverity.INFO: 0.0,
            ExposureSeverity.LOW: 10.0,
            ExposureSeverity.MEDIUM: 25.0,
            ExposureSeverity.HIGH: 50.0,
            ExposureSeverity.CRITICAL: 80.0,
        }
        return weights[self]


class CloudProvider(StrEnum):
    """Public cloud infrastructure and storage providers."""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    CLOUDFLARE = "cloudflare"
    DIGITALOCEAN = "digitalocean"
    UNKNOWN = "unknown"


class TlsVersion(StrEnum):
    """TLS/SSL protocol versions."""

    SSLV3 = "SSLv3"
    TLS1_0 = "TLSv1.0"
    TLS1_1 = "TLSv1.1"
    TLS1_2 = "TLSv1.2"
    TLS1_3 = "TLSv1.3"
    UNKNOWN = "unknown"

    @property
    def is_deprecated(self) -> bool:
        """Flag whether the TLS protocol is considered insecure or deprecated."""
        return self in (TlsVersion.SSLV3, TlsVersion.TLS1_0, TlsVersion.TLS1_1)


class ShadowItTag(StrEnum):
    """Heuristic classification tags for shadow IT and exposure detection."""

    STAGING_DEV = "staging_dev"
    INTERNAL_NAMING = "internal_naming"
    PUBLIC_BUCKET = "public_bucket"
    DANGLING_DNS = "dangling_dns"
    ADMIN_INTERFACE = "admin_interface"
    UNSECURED_DATABASE = "unsecured_database"
    EXPIRED_CERT = "expired_cert"
