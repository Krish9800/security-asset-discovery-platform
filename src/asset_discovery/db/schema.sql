-- Relational Schema for Security Asset Discovery Platform (SQLite WAL Mode)

CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    asset_type TEXT NOT NULL,
    identifier TEXT NOT NULL UNIQUE,
    parent_domain TEXT,
    cloud_provider TEXT NOT NULL,
    risk_score REAL NOT NULL,
    discovered_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    tags_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dns_records (
    record_id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id TEXT NOT NULL,
    record_type TEXT NOT NULL,
    domain TEXT NOT NULL,
    value TEXT NOT NULL,
    ttl INTEGER NOT NULL,
    discovered_at TEXT NOT NULL,
    FOREIGN KEY(asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS service_endpoints (
    service_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    service_name TEXT NOT NULL,
    banner TEXT,
    is_open INTEGER NOT NULL,
    response_time_ms REAL NOT NULL,
    discovered_at TEXT NOT NULL,
    tls_details_json TEXT,
    FOREIGN KEY(asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS exposure_findings (
    finding_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    tag TEXT NOT NULL,
    remediation TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    FOREIGN KEY(asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scan_reports (
    scan_id TEXT PRIMARY KEY,
    target_seed TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    total_assets INTEGER NOT NULL,
    total_services INTEGER NOT NULL,
    total_findings INTEGER NOT NULL,
    max_risk_score REAL NOT NULL,
    summary TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assets_identifier ON assets(identifier);
CREATE INDEX IF NOT EXISTS idx_assets_risk ON assets(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_records(domain);
CREATE INDEX IF NOT EXISTS idx_services_ip_port ON service_endpoints(ip_address, port);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON exposure_findings(severity);
