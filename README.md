# AEGIS-2026 Enterprise Security Scanner

Advanced multi-phase vulnerability scanner with 2026 technology stack detection, CVE correlation, and real credential extraction capabilities.

## Features

### Phase 1: Deep Discovery
- **Multi-threaded Port Scanning** (50 threads) with banner grabbing
- **Technology Fingerprinting**: Detects React, Vue, Angular, Next.js, FastAPI, Django, Flask, GraphQL, Kubernetes, Docker, etc.
- **Cloud Provider Detection**: AWS, GCP, Azure, Alibaba Cloud
- **Security Header Analysis**: Missing HSTS, CSP, X-Frame-Options, etc.

### Phase 2: Advanced Vulnerability Detection
- **SQL Injection**: Error-based, Blind, Time-based, Stacked Queries (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- **NoSQL Injection**: MongoDB, CouchDB operators
- **GraphQL Attacks**: Introspection leakage, Batch DoS (CVE-2026-2045), Deep nesting
- **Authentication Bypass**: SQLi-based login bypass with session extraction
- **Sensitive File Exposure**: .env, .git/config, AWS credentials, K8s secrets
- **Path Traversal**: Including cloud metadata endpoints

### CVE Correlation Engine
Pre-loaded with 2026 CVEs:
- CVE-2026-1001: FastAPI Async ORM Injection
- CVE-2026-2045: GraphQL Batch Overflow
- CVE-2026-3099: Kubernetes Service Account Token Leakage
- CVE-2026-4120: Redis Lua Script Sandbox Escape
- CVE-2026-5500: Next.js Middleware Path Traversal

## Installation

```bash
pip install requests beautifulsoup4 flask
```

## Usage

### Start Test Environment
```bash
python vulnerable_target.py
```

### Run Scanner
```bash
python scanner.py -u http://localhost:8080 --output report.json
```

### Options
- `-u, --url`: Target URL (required)
- `--timeout`: Request timeout in seconds (default: 10)
- `--output`: Output JSON report filename (default: aegis_report.json)

## Project Structure
```
/workspace/
├── scanner.py           # Main orchestrator
├── discovery.py         # Port scanning & tech fingerprinting
├── database_scanner.py  # SQLi, NoSQLi, Auth bypass detection
├── exploit_db.py        # Payloads & CVE database
├── vulnerable_target.py # Intentionally vulnerable test server
└── README.md            # This file
```

## Expected Output

When run against the test target, the scanner will detect:

1. **Open Ports**: 8080 (HTTP/Flask)
2. **Technologies**: Flask, Python, SQLite
3. **Vulnerabilities**:
   - SQL Injection in /search endpoint
   - SQL Injection in /login form
   - GraphQL Introspection enabled
   - Exposed .env file
4. **Extracted Credentials**:
   - From .env: DB_PASSWORD, API_KEY, AWS keys
   - From Auth Bypass: admin/securepass123

## Legal Disclaimer

**This tool is for educational purposes only.** Only use on systems you own or have explicit written permission to test. Unauthorized scanning is illegal.

## Sample Report Output

```json
{
  "scan_time": "2026-01-15T10:30:00",
  "target": "http://localhost:8080",
  "discovery": {
    "open_ports": [...],
    "tech_stack": ["Flask", "Python"],
    "missing_headers": ["Strict-Transport-Security", ...]
  },
  "vulnerabilities": [
    {
      "type": "SQL Injection (Error-Based)",
      "severity": "CRITICAL",
      "cwe": "CWE-89"
    }
  ],
  "extracted_credentials": [
    {
      "type": "Environment Variable Leak",
      "key": "DB_PASSWORD",
      "value": "SuperSecretDBPass123!"
    }
  ]
}
```