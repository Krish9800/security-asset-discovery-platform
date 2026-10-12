# Changelog

All notable changes to the Security Asset Discovery Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-12

### Added
- **Phase 1: Project Foundation & Architecture**
  - Project configuration in `pyproject.toml` with strict ruff, mypy, bandit, and pytest settings.
  - Environment-aware Pydantic v2 configuration settings (`PlatformSettings`).
  - Core exception taxonomy hierarchy (`AssetDiscoveryError`, `DnsResolutionError`, `ProbeTimeoutError`, etc.).
- **Phase 2: Domain Models & Taxonomy**
  - Typed enumerations for `AssetType`, `DnsRecordType`, `ServiceProtocol`, `ExposureSeverity`, `CloudProvider`, `TlsVersion`, `ShadowItTag`.
  - Normalized asset models: `DiscoveredAsset`, `DnsRecord`, `ServiceEndpoint`, `TlsCertificateDetails`, `ExposureFinding`, `DiscoveryScanReport`.
- **Phase 3: Multi-Source DNS & Discovery Engine**
  - Asynchronous DNS resolver for A, AAAA, CNAME, MX, TXT records.
  - Reverse DNS (PTR) lookups for host IP correlation.
  - Subdomain wordlist enumeration engine with automated wildcard DNS detection.
- **Phase 4: Port & Service Exposure Scanner**
  - Asynchronous non-intrusive TCP socket prober for admin ports (22, 3389), databases (3306, 5432, 6379, 27017), and web interfaces (80, 443, 8080, 8443).
  - Banner extraction and socket latency benchmarking.
- **Phase 5: SSL/TLS Certificate & Cloud Heuristics Inspector**
  - TLS handshake engine with raw X.509 DER certificate parsing via `cryptography`.
  - Subject Alternative Names (SANs) extraction and certificate expiry checking.
  - Heuristic detector for staging/dev subdomains, administrative endpoints, and public cloud storage buckets (S3, Azure Blob, GCP).
- **Phase 6: Exposure & Criticality Scoring Engine**
  - Multi-factor risk scoring engine calculating composite scores (0.0 to 100.0) based on exposed services, expired certs, and shadow IT tags.
  - Inventory-wide aggregation metrics (`max_risk`, `average_risk`, `high_risk_count`).
- **Phase 7: SQLite WAL Persistence Layer & Graph Store**
  - Transactional SQLite schema in Write-Ahead Logging (WAL) mode with busy timeout handling.
  - Parameterized table storage for assets, dns_records, service_endpoints, exposure_findings, and scan_reports.
- **Phase 8: FastAPI Control Plane**
  - Endpoints: `POST /api/v1/scans`, `GET /api/v1/assets`, `GET /api/v1/assets/{id}`, `GET /api/v1/exposures`, `GET /health`.
- **Phase 9: Typer & Rich CLI Tool**
  - CLI commands: `scan`, `assets`, `exposures`, `report`.
  - Interactive Rich terminal tables for attack surface summaries.
- **Phase 10: Production Hardening & Adversarial Testbed**
  - Rootless Dockerfile with multi-stage build and non-root user `appsec` (UID 10001).
  - Docker Compose service configuration with dropped capabilities.
  - GitHub Actions CI workflow covering ruff, mypy strict, bandit, and pytest.
  - STRIDE threat model documentation (`docs/threat_model.md`).
  - Adversarial test suite validating malformed inputs, SQL injection resistance, and edge cases.
