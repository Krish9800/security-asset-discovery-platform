"""TLS/SSL certificate inspection and cryptography analysis."""

import asyncio
import socket
import ssl
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID

from asset_discovery.models.enums import TlsVersion
from asset_discovery.models.schemas import TlsCertificateDetails


class TlsCertificateInspector:
    """Probes TLS services, retrieves X.509 certs, extracts SANs, and checks expiry."""

    def __init__(self, handshake_timeout_seconds: float = 4.0) -> None:
        self.handshake_timeout_seconds = handshake_timeout_seconds

    async def inspect_certificate(
        self,
        hostname: str,
        port: int = 443,
    ) -> TlsCertificateDetails | None:
        """Perform asynchronous TLS handshake and extract certificate details."""
        target_host = hostname.strip()

        # Run blocking socket/SSL handshake in default asyncio thread executor
        loop = asyncio.get_running_loop()
        try:
            cert_details = await asyncio.wait_for(
                loop.run_in_executor(None, self._sync_inspect_tls, target_host, port),
                timeout=self.handshake_timeout_seconds,
            )
            return cert_details
        except Exception:
            return None

    def _sync_inspect_tls(self, hostname: str, port: int) -> TlsCertificateDetails | None:
        """Synchronous helper for TLS handshake with unverified cert extraction."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with (
            socket.create_connection(
                (hostname, port), timeout=self.handshake_timeout_seconds
            ) as sock,
            ctx.wrap_socket(sock, server_hostname=hostname) as ssock,
        ):
            der_cert = ssock.getpeercert(binary_form=True)
            if not der_cert:
                return None

            version_str = ssock.version() or "unknown"
            cipher_info = ssock.cipher()
            cipher_name = cipher_info[0] if cipher_info else None

            return self.parse_der_certificate(
                der_bytes=der_cert,
                tls_version_str=version_str,
                cipher_suite=cipher_name,
            )

    def parse_der_certificate(
        self,
        der_bytes: bytes,
        tls_version_str: str = "TLSv1.3",
        cipher_suite: str | None = None,
    ) -> TlsCertificateDetails:
        """Parse raw DER-encoded X.509 certificate using cryptography library."""
        cert = x509.load_der_x509_certificate(der_bytes, default_backend())

        # Extract Subject Common Name
        subject_cn = "unknown"
        for attr in cert.subject:
            if attr.oid == NameOID.COMMON_NAME:
                subject_cn = str(attr.value)
                break

        # Extract Issuer Common Name
        issuer_cn = "unknown"
        for attr in cert.issuer:
            if attr.oid == NameOID.COMMON_NAME:
                issuer_cn = str(attr.value)
                break

        # Extract Subject Alternative Names (SANs)
        sans: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_value = san_ext.value
            if isinstance(san_value, x509.SubjectAlternativeName):
                sans = [str(name) for name in san_value.get_values_for_type(x509.DNSName)]
        except x509.ExtensionNotFound:
            sans = []

        valid_from = cert.not_valid_before_utc
        valid_until = cert.not_valid_after_utc
        now = datetime.now(UTC)

        is_expired = now > valid_until
        delta_days = (valid_until - now).days

        # Protocol mapping
        proto_map = {
            "TLSv1.3": TlsVersion.TLS1_3,
            "TLSv1.2": TlsVersion.TLS1_2,
            "TLSv1.1": TlsVersion.TLS1_1,
            "TLSv1": TlsVersion.TLS1_0,
            "SSLv3": TlsVersion.SSLV3,
        }
        tls_ver = proto_map.get(tls_version_str, TlsVersion.UNKNOWN)

        fingerprint = (
            cert.fingerprint(cert.signature_hash_algorithm).hex()
            if cert.signature_hash_algorithm
            else None
        )

        return TlsCertificateDetails(
            subject_cn=subject_cn,
            issuer_cn=issuer_cn,
            subject_alt_names=sans,
            valid_from=valid_from,
            valid_until=valid_until,
            is_expired=is_expired,
            days_to_expiration=delta_days,
            tls_version=tls_ver,
            cipher_suite=cipher_suite,
            serial_number=str(cert.serial_number),
            fingerprint_sha256=fingerprint,
        )
