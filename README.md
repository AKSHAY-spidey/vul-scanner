# Advanced Web Vulnerability Scanner (2026 Edition)

A comprehensive, multi-phase web vulnerability scanner built in Python. This tool performs deep reconnaissance, technology fingerprinting, and advanced database vulnerability detection including SQL Injection, Authentication Bypass, and CVE correlation.

## ⚠️ LEGAL DISCLAIMER

**This tool is for EDUCATIONAL PURPOSES and AUTHORIZED SECURITY TESTING ONLY.**

- Only use this scanner on websites you own or have explicit written permission to test.
- Unauthorized scanning of networks or websites is illegal in most jurisdictions.
- The authors are not responsible for any misuse of this software.

## Features

### Phase 1: Deep Discovery
- **Multi-threaded Port Scanning**: Detects open ports (FTP, SSH, HTTP, MySQL, PostgreSQL, MongoDB, Redis, etc.)
- **Banner Grabbing**: Retrieves service banners from open ports
- **Technology Fingerprinting**: Identifies CMS (WordPress, Joomla, Drupal), Web Servers (Apache, Nginx, IIS), and Frameworks (Django, Flask)
- **Sensitive File Detection**: Checks for exposed `.env`, `.git/config`, `database.sql`, `phpMyAdmin`, backup files, etc.
- **Robots.txt Analysis**: Extracts hidden paths from robots.txt

### Phase 2: Website Understanding
- **Web Crawler**: Crawls up to N pages (configurable) to map site structure
- **Form Detection**: Identifies all forms (login, search, contact) for injection testing
- **Security Header Analysis**: Checks for missing HSTS, CSP, X-Frame-Options, etc.

### Phase 3: Database Vulnerability Analysis
- **SQL Injection Detection**:
  - Error-based SQLi (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
  - Time-based Blind SQLi (SLEEP, WAITFOR DELAY)
  - Boolean-based Blind SQLi
  - Union-based SQLi
- **NoSQL Injection**: MongoDB-style injection tests
- **Authentication Bypass**: Detects login circumvention via SQLi
- **CVE Correlation**: Maps detected technologies to known CVEs (Log4Shell, HTTP/2 Rapid Reset, etc.)
- **Credential Extraction Simulation**: Confirms if bypasses lead to credential exposure

## Project Structure

```
/workspace
├── scanner.py            # Main entry point and orchestrator
├── discovery.py          # Phase 1: Port scanning, tech detection, sensitive files
├── database_scanner.py   # Phase 3: SQLi, NoSQLi, CVE mapping, auth bypass
├── payloads.py           # Payloads, CVE database, error patterns, fingerprints
├── vulnerable_target.py  # Intentionally vulnerable test server (for practice)
└── README.md             # This file
```

## Requirements

- Python 3.8+
- `requests`
- `beautifulsoup4`

Install dependencies:
```bash
pip install requests beautifulsoup4
```

## Usage

### Basic Scan
```bash
python scanner.py -u https://target.com
```

### Advanced Options
```bash
python scanner.py -u https://target.com --timeout 15 --max-pages 50
```

### Testing Locally (Recommended)

1. **Start the vulnerable test server:**
   ```bash
   python vulnerable_target.py
   ```
   This starts a server on `http://localhost:8080` with intentional vulnerabilities.

2. **Run the scanner against it:**
   In a NEW terminal window:
   ```bash
   python scanner.py -u http://localhost:8080
   ```

3. **Observe Results:**
   - The scanner will detect open ports (if running locally)
   - It will find the exposed `/.env` and `/.git/config`
   - It will detect SQL Injection in `/search` and `/user` endpoints
   - It will detect Authentication Bypass in the login form
   - **It will extract simulated credentials** (`admin:securepass123`) to prove the vulnerability

## Output

The scanner generates a detailed JSON report (`scan_report.json`) containing:
- Discovered open ports and services
- Detected technologies and versions
- List of exposed sensitive files
- All identified vulnerabilities with evidence
- CVE correlations
- Confirmed authentication bypasses and extracted credentials

### Example Report Snippet
```json
{
  "phase3_vulnerabilities": [
    {
      "type": "SQL Injection (Error Based)",
      "url": "http://localhost:8080/search?q=' OR '1'='1",
      "param": "q",
      "db_type": "MySQL",
      "evidence": "MySQL Error: You have an error in your SQL syntax"
    },
    {
      "type": "Authentication Bypass (Likely SQLi)",
      "url": "http://localhost:8080/login",
      "field": "username",
      "simulated_creds": {"username": "admin", "status": "Bypassed"}
    }
  ],
  "summary": {
    "total_vulnerabilities": 5,
    "critical_findings": 2
  }
}
```

## How It Confirms Credentials

When the scanner detects an **Authentication Bypass**:
1. It sends SQL injection payloads (e.g., `' OR '1'='1`) to login forms
2. If the response contains success indicators ("Welcome", "Dashboard", "Logged in")
3. AND the response contains user data ("admin", "administrator")
4. It flags this as a **Confirmed Bypass** and reports the simulated credentials

In the `vulnerable_target.py` simulation, the server explicitly returns the credentials in the HTML when a bypass is detected, allowing you to verify the scanner works correctly.

## Advanced Attack Vectors Included

| Category | Techniques |
|----------|-----------|
| **SQLi** | Error-based, Union-based, Blind (Boolean & Time-based), Stacked Queries |
| **NoSQLi** | MongoDB `$ne`, `$gt`, `$where` injections |
| **Info Disclosure** | Verbose errors, Stack traces, Database fingerprints |
| **File Exposure** | Backups, Git configs, Environment files, Database dumps |
| **CVE Mapping** | Log4Shell, TeamCity, HTTP/2 Rapid Reset |

## Customization

### Adding New Payloads
Edit `payloads.py`:
```python
SQL_INJECTION_PAYLOADS = [
    # Add your custom payloads here
    "' AND 1=1 -- ",
]
```

### Adding New CVEs
Edit `payloads.py`:
```python
CVE_DATABASE = {
    "CVE-2024-XXXXX": {"name": "New Vuln", "tech": "TechName", "severity": "CRITICAL"},
}
```

### Adding Sensitive Files
Edit `payloads.py`:
```python
SENSITIVE_FILES = [
    "new-secret-file.txt",
    "backup.tar.gz",
]
```

## Ethical Use Guidelines

1. **Written Permission**: Always obtain written authorization before scanning.
2. **Scope Definition**: Clearly define the scope (domains, IPs, time windows).
3. **Data Handling**: Do not store or share discovered credentials unnecessarily.
4. **Responsible Disclosure**: If testing third-party systems, follow responsible disclosure practices.

## Contributing

Contributions are welcome! Areas for improvement:
- Integration with real-time CVE APIs (NVD, GitHub Advisory)
- XSS and CSRF detection modules
- API endpoint fuzzing
- GraphQL injection testing
- Docker containerization

## License

MIT License - For educational purposes only.

---

**Remember**: With great power comes great responsibility. Use this tool ethically.
