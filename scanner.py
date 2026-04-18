#!/usr/bin/env python3
"""
ADVANCED VULNERABILITY SCANNER (2026 EDITION)
============================================
A multi-phase security scanner for web applications.

PHASE 1: Deep Discovery (Ports, Tech Stack, Configs)
PHASE 2: Website Understanding (Crawling, Forms, Structure)
PHASE 3: Database Vulnerability Analysis (SQLi, NoSQLi, CVEs, Auth Bypass)

DISCLAIMER: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY.
"""

import argparse
import json
import sys
import time
from datetime import datetime
from discovery import DiscoveryEngine
from database_scanner import DatabaseScanner
from payloads import HEADERS_TO_ANALYZE
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

class AdvancedScanner:
    def __init__(self, target_url, timeout=10, max_pages=20):
        self.target_url = target_url
        self.timeout = timeout
        self.max_pages = max_pages
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        })
        
        self.report = {
            "target": target_url,
            "scan_date": datetime.now().isoformat(),
            "phase1_discovery": {},
            "phase2_analysis": {},
            "phase3_vulnerabilities": [],
            "summary": {}
        }

    def analyze_headers(self, headers):
        """Analyze security headers."""
        print("[*] Analyzing Security Headers...")
        issues = []
        for header in HEADERS_TO_ANALYZE:
            if header not in headers:
                issues.append(f"Missing Header: {header}")
                print(f"    [-] Missing: {header}")
            else:
                print(f"    [+] Found: {header}")
        return issues

    def crawl_site(self):
        """Simple crawler to understand site structure."""
        print(f"[*] Crawling site (max {self.max_pages} pages)...")
        visited = set()
        to_visit = [self.target_url]
        forms_found = []
        
        while to_visit and len(visited) < self.max_pages:
            current_url = to_visit.pop(0)
            if current_url in visited:
                continue
            
            try:
                resp = self.session.get(current_url, timeout=self.timeout)
                visited.add(current_url)
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                # Extract Forms
                forms = soup.find_all('form')
                if forms:
                    forms_found.append({"url": current_url, "count": len(forms)})
                    print(f"    [i] Found {len(forms)} forms on {current_url}")
                
                # Extract Links
                links = soup.find_all('a', href=True)
                for link in links:
                    href = link['href']
                    if href.startswith('#') or href.startswith('mailto:') or href.startswith('javascript:'):
                        continue
                    
                    full_url = href if href.startswith('http') else f"{urlparse(self.target_url).scheme}://{urlparse(self.target_url).netloc}{href}"
                    
                    if full_url not in visited and urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                        to_visit.append(full_url)
                        
            except Exception as e:
                continue
                
        return {"pages_visited": len(visited), "forms_locations": forms_found}

    def run_scan(self):
        """Execute the full scanning pipeline."""
        print("\n" + "="*60)
        print("   ADVANCED WEB VULNERABILITY SCANNER (2026)")
        print("="*60)
        print(f"Target: {self.target_url}")
        print(f"Started: {self.report['scan_date']}")
        print("="*60 + "\n")
        
        # PHASE 1: DISCOVERY
        print("\n>>> INITIATING PHASE 1: DEEP DISCOVERY")
        discovery_engine = DiscoveryEngine(self.target_url, self.timeout)
        discovery_data = discovery_engine.run_full_discovery()
        self.report['phase1_discovery'] = discovery_data
        
        # Analyze Headers
        try:
            resp = self.session.get(self.target_url, timeout=self.timeout)
            header_issues = self.analyze_headers(resp.headers)
            self.report['phase2_analysis']['header_issues'] = header_issues
        except:
            pass

        # PHASE 2: WEBSITE UNDERSTANDING
        print("\n>>> INITIATING PHASE 2: WEBSITE STRUCTURE ANALYSIS")
        crawl_data = self.crawl_site()
        self.report['phase2_analysis'].update(crawl_data)
        
        # Fetch main page content for form analysis later
        try:
            main_resp = self.session.get(self.target_url, timeout=self.timeout)
            main_html = main_resp.text
        except:
            main_html = None

        # PHASE 3: DATABASE VULNERABILITIES
        print("\n>>> INITIATING PHASE 3: DATABASE & INJECTION ANALYSIS")
        db_scanner = DatabaseScanner(self.target_url, self.session, self.timeout)
        
        # Pass technologies detected in Phase 1
        techs = discovery_data.get('technologies', [])
        
        vulns = db_scanner.run_database_scan(forms_html=main_html, technologies=techs)
        self.report['phase3_vulnerabilities'] = vulns
        
        # GENERATE SUMMARY
        total_vulns = len(vulns)
        critical_count = len([v for v in vulns if "Critical" in str(v) or "Bypass" in str(v)])
        
        self.report['summary'] = {
            "total_vulnerabilities": total_vulns,
            "critical_findings": critical_count,
            "open_ports_count": len(discovery_data.get('open_ports', [])),
            "technologies_detected": len(techs),
            "status": "COMPLETED"
        }
        
        self.print_summary()
        return self.report

    def print_summary(self):
        """Print final summary."""
        print("\n" + "="*60)
        print("   SCAN COMPLETE - FINAL REPORT")
        print("="*60)
        
        s = self.report['summary']
        print(f"Total Vulnerabilities: {s['total_vulnerabilities']}")
        print(f"Critical Findings:     {s['critical_findings']}")
        print(f"Open Ports:            {s['open_ports_count']}")
        print(f"Technologies Detected: {s['technologies_detected']}")
        
        if s['critical_findings'] > 0:
            print("\n[!!!] CRITICAL ISSUES DETECTED - IMMEDIATE ACTION REQUIRED")
            print("Check the JSON report for specific details on bypasses or injections.")
            
        print("\nReport saved to: scan_report.json")
        with open("scan_report.json", "w") as f:
            json.dump(self.report, f, indent=4, default=str)

def main():
    parser = argparse.ArgumentParser(description="Advanced Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--max-pages", type=int, default=20, help="Max pages to crawl")
    
    args = parser.parse_args()
    
    if not args.url.startswith("http"):
        print("Error: URL must start with http:// or https://")
        sys.exit(1)
    
    print("\n[!] LEGAL DISCLAIMER:")
    print("    This tool is for educational purposes and authorized security testing ONLY.")
    print("    Unauthorized scanning of networks/websites is illegal.")
    print("    By continuing, you confirm you have explicit permission to scan the target.")
    
    confirm = input("\nDo you have permission to scan this target? (yes/no): ")
    if confirm.lower() != "yes":
        print("Scan aborted.")
        sys.exit(0)
        
    scanner = AdvancedScanner(args.url, args.timeout, args.max_pages)
    scanner.run_scan()

if __name__ == "__main__":
    main()
