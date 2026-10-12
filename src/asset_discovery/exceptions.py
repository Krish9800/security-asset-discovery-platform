"""Root exception hierarchy for Security Asset Discovery Platform."""


class AssetDiscoveryError(Exception):
    """Base exception for all asset discovery platform errors."""


class ConfigurationError(AssetDiscoveryError):
    """Raised when platform configuration or settings are invalid."""


class DnsResolutionError(AssetDiscoveryError):
    """Raised when DNS query resolution fails or times out."""


class ProbeTimeoutError(AssetDiscoveryError):
    """Raised when a service network probe times out."""


class TlsInspectionError(AssetDiscoveryError):
    """Raised when TLS handshake or certificate parsing fails."""


class StorageError(AssetDiscoveryError):
    """Raised when persistence operations fail in the asset database."""
