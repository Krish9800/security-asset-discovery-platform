"""Multi-source DNS resolution and subdomain enumeration engine."""

import ipaddress
from collections.abc import Iterable
from datetime import UTC, datetime
from uuid import uuid4

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

from asset_discovery.models.enums import AssetType, DnsRecordType
from asset_discovery.models.schemas import DiscoveredAsset, DnsRecord


class DnsDiscoveryEngine:
    """Asynchronous DNS resolver and subdomain enumeration engine."""

    DEFAULT_SUBDOMAINS: list[str] = [
        "www",
        "mail",
        "remote",
        "blog",
        "webmail",
        "server",
        "ns1",
        "ns2",
        "smtp",
        "secure",
        "vpn",
        "api",
        "dev",
        "staging",
        "test",
        "admin",
        "portal",
        "app",
        "cloud",
        "auth",
        "corp",
        "internal",
        "db",
        "git",
        "jenkins",
        "s3",
        "assets",
        "static",
    ]

    RECORD_TYPES: list[DnsRecordType] = [
        DnsRecordType.A,
        DnsRecordType.AAAA,
        DnsRecordType.CNAME,
        DnsRecordType.MX,
        DnsRecordType.TXT,
    ]

    def __init__(
        self,
        nameservers: list[str] | None = None,
        timeout_seconds: float = 3.0,
    ) -> None:
        self.nameservers = nameservers or ["1.1.1.1", "8.8.8.8"]
        self.timeout_seconds = timeout_seconds
        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.nameservers = self.nameservers
        self._resolver.timeout = self.timeout_seconds
        self._resolver.lifetime = self.timeout_seconds

    async def resolve_record(
        self,
        domain: str,
        record_type: DnsRecordType,
    ) -> list[DnsRecord]:
        """Resolve specific DNS record type for a domain."""
        sanitized_domain = domain.strip().lower()
        records: list[DnsRecord] = []

        try:
            rdtype = dns.rdatatype.from_text(record_type.value)
            answers = await self._resolver.resolve(sanitized_domain, rdtype)
            now = datetime.now(UTC)

            for rdata in answers:
                val_str = str(rdata).strip('"').rstrip(".")
                records.append(
                    DnsRecord(
                        record_type=record_type,
                        domain=sanitized_domain,
                        value=val_str,
                        ttl=answers.rrset.ttl if answers.rrset else 300,
                        discovered_at=now,
                    )
                )
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            # Normal non-existence or timeout for negative records
            return []
        except Exception:
            # Catch other unexpected resolver errors gracefully
            return []

        return records

    async def resolve_all_records(self, domain: str) -> list[DnsRecord]:
        """Resolve all standard DNS record types for a domain."""
        all_records: list[DnsRecord] = []
        for rtype in self.RECORD_TYPES:
            recs = await self.resolve_record(domain, rtype)
            all_records.extend(recs)
        return all_records

    async def reverse_dns_ptr(self, ip_address_str: str) -> str | None:
        """Perform reverse DNS PTR lookup on an IPv4 or IPv6 address."""
        try:
            ip_obj = ipaddress.ip_address(ip_address_str.strip())
            reverse_name = ip_obj.reverse_pointer
            answers = await self._resolver.resolve(reverse_name, "PTR")
            for rdata in answers:
                return str(rdata).rstrip(".")
        except Exception:
            return None
        return None

    async def check_wildcard_dns(self, base_domain: str) -> bool:
        """Detect if domain has wildcard DNS enabled (*.example.com resolving to an IP)."""
        random_subdomain = f"wildcard-check-{uuid4().hex[:12]}.{base_domain}"
        a_records = await self.resolve_record(random_subdomain, DnsRecordType.A)
        return len(a_records) > 0

    async def enumerate_subdomains(
        self,
        base_domain: str,
        wordlist: Iterable[str] | None = None,
    ) -> list[DiscoveredAsset]:
        """Enumerate active subdomains under a base domain."""
        sanitized_base = base_domain.strip().lower()
        subdomains_to_probe = list(wordlist or self.DEFAULT_SUBDOMAINS)
        discovered_assets: list[DiscoveredAsset] = []

        # Check for wildcard DNS to prevent false positives
        has_wildcard = await self.check_wildcard_dns(sanitized_base)

        for sub in subdomains_to_probe:
            candidate_fqdn = f"{sub}.{sanitized_base}"
            records = await self.resolve_all_records(candidate_fqdn)

            if not records:
                continue

            ips = [
                r.value for r in records if r.record_type in (DnsRecordType.A, DnsRecordType.AAAA)
            ]

            # If wildcard DNS is enabled, verify IPs differ or mark note
            if has_wildcard and not ips:
                continue

            asset = DiscoveredAsset(
                asset_type=AssetType.SUBDOMAIN,
                identifier=candidate_fqdn,
                parent_domain=sanitized_base,
                ip_addresses=ips,
                dns_records=records,
            )
            discovered_assets.append(asset)

        return discovered_assets
