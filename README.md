# Security Asset Discovery Platform (EASM)

A high-performance External Attack Surface Management (EASM) and Asset Discovery Platform for identifying unknown, forgotten, or exposed assets across multi-cloud and on-premise perimeters.

---

## Key Features

- **Multi-Source DNS Discovery**: Asynchronous resolution of A, AAAA, CNAME, MX, TXT records with reverse DNS (PTR) lookups and wildcard DNS detection.
- **Subdomain Enumeration**: High-speed, wordlist-driven asynchronous subdomain discovery.
- **Service & Port Exposure Prober**: Non-intrusive TCP socket prober for administrative ports (SSH 22, RDP 3389), databases (MySQL, Postgres, Redis, Mongo), and web services.
- **SSL/TLS Certificate Inspector**: Deep X.509 inspection extracting Subject Alternative Names (SANs), tracking certificate expiration, and flagging obsolete TLS versions.
- **Cloud & Shadow IT Heuristic Detector**: Automated detection of staging/dev subdomains, administrative interfaces, and public cloud storage buckets (AWS S3, Azure Blob, GCP Storage).
- **Composite Risk Scoring Engine**: Calculates multi-factor Exposure Risk Scores (0.0 to 100.0) reflecting open databases, expired certs, and shadow IT tags.
- **SQLite WAL Asset Graph Persistence**: Zero-overhead relational inventory storage running in write-ahead log (WAL) mode with foreign key integrity.
- **FastAPI Control Plane**: Asynchronous REST API for launching scans, monitoring inventory, and querying security findings.
- **Typer & Rich CLI Tool**: Command-line interface with interactive table visualizations for inventory and exposure audits.
- **Production Hardened**: Rootless Docker container (UID 10001), STRIDE threat model, 100% strict type hints (`mypy --strict`), PEP 8 compliance (`ruff`), and adversarial testbed.

---

## Architecture Overview

```
                      ┌─────────────────────────────────────────┐
                      │              Seed Targets               │
                      │         Domain (example.com)            │
                      └────────────────────┬────────────────────┘
                                           │
                                           ▼
                      ┌─────────────────────────────────────────┐
                      │       Multi-Source Discovery Engine     │
                      │       DNS, Subdomains, Reverse PTR      │
                      └────────────────────┬────────────────────┘
                                           │
                                           ▼
                      ┌─────────────────────────────────────────┐
                      │        Service & Exposure Scanner       │
                      │       TCP Socket Probing & Banners      │
                      └────────────────────┬────────────────────┘
                                           │
                                           ▼
                      ┌─────────────────────────────────────────┐
                      │       TLS & Cloud Inspect Engine        │
                      │      SANs, Expiry, Shadow IT Tags       │
                      └────────────────────┬────────────────────┘
                                           │
                                           ▼
                      ┌─────────────────────────────────────────┐
                      │      Exposure Risk Scoring Engine       │
                      │       0.0 - 100.0 Risk Calculation      │
                      └──────────────┬───────────────────┬──────┘
                                     │                   │
                                     ▼                   ▼
                      ┌──────────────────────┐   ┌──────────────────────┐
                      │  SQLite WAL Storage  │   │ Interfaces:          │
                      │  Assets & Exposures  │   │ - FastAPI REST API   │
                      │                      │   │ - Typer CLI & Rich   │
                      └──────────────────────┘   └──────────────────────┘
```

---

## Installation & Quick Start

### 1. Local Setup with Virtual Environment

```bash
# Clone repository
git clone https://github.com/example/security-asset-discovery-platform.git
cd security-asset-discovery-platform

# Create virtual environment and install
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

### 2. Using the CLI

```bash
# Run an attack surface scan
asset-discovery scan corp.internal

# List discovered assets in the repository
asset-discovery assets --min-risk 25.0

# Query detected security exposures and shadow IT
asset-discovery exposures --severity high
```

### 3. Running the FastAPI Server

```bash
# Start API server locally
uvicorn asset_discovery.api.app:app --host 0.0.0.0 --port 8000 --reload
```

Interactive OpenAPI docs will be available at `http://127.0.0.1:8000/docs`.

### 4. Running via Docker / Docker Compose

```bash
# Build and run the rootless container
docker compose up -d

# Check service health
curl -f http://localhost:8000/health
```

---

## Quality Gates & Verification

```bash
# Code formatting and style
ruff format --check src tests
ruff check src tests

# Strict static type checking
mypy --strict src tests

# Security AST vulnerability audit
bandit -r src/

# Full test suite with coverage
pytest --cov=asset_discovery --cov-fail-under=90 tests/
```

---

## Documentation

- [Threat Model (STRIDE)](docs/threat_model.md)
- [Architecture Blueprint](https://github.com/example/security-asset-discovery-platform)
- [Changelog](CHANGELOG.md)

---

## License

Apache License 2.0
