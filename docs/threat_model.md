# STRIDE Threat Model: Security Asset Discovery Platform

## 1. System Overview & Scope
The **Security Asset Discovery Platform (EASM)** performs automated, external perimeter discovery, DNS reconnaissance, port probing, TLS certificate evaluation, and shadow IT heuristics against organization infrastructure.

### Assets at Risk
1. **Target Systems & Network Infrastructure**: Network sockets, DNS nameservers, and external hosts must not be overwhelmed or destabilized.
2. **Scanner Execution Runtime**: Scanner node must not be compromised via malicious DNS responses, malformed TLS payloads, or banner exploits.
3. **Asset Repository & Inventory**: SQLite inventory database storing discovered subdomains, IP maps, and vulnerability findings must remain tamper-resistant and ACID-consistent.

---

## 2. Threat Analysis (STRIDE Matrix)

| STRIDE Threat Category | Potential Attack Vector | Impact | Mitigation in Architecture & Implementation |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Adversary injects spoofed DNS responses or wildcard DNS records to poison the scanner's asset graph or misattribute infrastructure. | High (Misattributed assets, polluted inventory) | Automated wildcard DNS detection (`check_wildcard_dns`), validation of IP formats, and querying configured recursive resolvers (`1.1.1.1`, `8.8.8.8`). |
| **Tampering** | Injected hostnames/IPs attempting SQL injection in repository or parser corruption. | Critical (Database manipulation, scanner crash) | Strict parameterized SQL queries (`?` binding) across SQLite repository; zero string concatenation. Pydantic schema validation rejects illegal datatypes. |
| **Repudiation** | Target or operator claims an external asset discovery scan was unauthorized or falsified. | Medium (Lack of audit trail) | Persistent, immutable scan reports (`DiscoveryScanReport`) with nanosecond timestamps, scan UUIDs, and detailed summary evidence. |
| **Information Disclosure** | Leakage of proprietary internal IPs or internal hostnames via error messages or public API endpoints. | High (Reconnaissance disclosure to unauthorized users) | Sanitized API error handlers; configurable network bind interfaces; no credentials stored in source code or Docker images. |
| **Denial of Service (DoS)** | Exhaustion of local network sockets, file descriptors, or target bandwidth due to unbound concurrency or massive CIDR sweeps. | High (Scanner node crash, network disruption) | Concurrency control via `asyncio.Semaphore`, aggressive socket timeouts (1-3s), and bounded connection teardown. |
| **Elevation of Privilege** | Container breakout or host takeover via socket or library exploits. | Critical (Host takeover) | Rootless Docker multi-stage build running as non-root UID 10001 (`appsec`) with dropped Linux capabilities (`cap_drop: ALL`). |

---

## 3. Defensive Controls & Safe Operating Procedures
1. **Non-Intrusive Probing**: Port scanner performs TCP connect probes without sending intrusive vulnerability exploits or heavy fuzzing payloads.
2. **Resource Boundaries**: Strict concurrency limits (`max_concurrency: 50`) and timeouts (2s socket, 4s TLS) prevent resource exhaustion.
3. **Input Sanitization**: Identifiers and domains are stripped, lowercased, and validated before DNS resolution or DB storage.
