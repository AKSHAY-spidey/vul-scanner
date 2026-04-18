"""
AEGIS-2026 MAIN SCANNER ORCHESTRATOR
Combines discovery, database scanning, and CVE correlation.
"""

import argparse
import json
import sys
from datetime import datetime
from discovery import DiscoveryEngine
from database_scanner import DatabaseScanner
from exploit_db import PayloadDatabase

class AegisScanner:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        self.discovery = DiscoveryEngine(target_url, timeout)
        self.db_scanner = DatabaseScanner(target_url, timeout)
        self.payload_db = PayloadDatabase()
        self.report = {
            "scan_time": datetime.now().isoformat(),
            "target": target_url,
            "discovery": {},
            "vulnerabilities": [],
            "extracted_credentials": [],
            "cve_correlations": []
        }

    def run_phase1_discovery(self):
        """Phase 1: Deep Discovery"""
        print("\n" + "="*60)
        print("PHASE 1: DEEP DISCOVERY & RECONNAISSANCE")
        print("="*60)
        
        discovery_data = self.discovery.run_full_discovery()
        self.report["discovery"] = discovery_data
        
        # Correlate CVEs based on discovered tech
        if discovery_data.get('tech_stack'):
            cves = self.payload_db.check_cve(discovery_data['tech_stack'])
            for cve in cves:
                self.report["cve_correlations"].append({
                    "cve_id": list(self.payload_db.cve_database.keys())[list(self.payload_db.cve_database.values()).index(cve)],
                    "details": cve,
                    "related_tech": discovery_data['tech_stack']
                })
                print(f"[!] CVE ALERT: {cve['name']} ({list(self.payload_db.cve_database.keys())[list(self.payload_db.cve_database.values()).index(cve)]})")
                print(f"    Severity: {cve['severity']} | CWE: {cve['cwe']}")
                print(f"    Description: {cve['description']}")

    def run_phase2_vulnerability_scan(self):
        """Phase 2: Advanced Vulnerability Scanning"""
        print("\n" + "="*60)
        print("PHASE 2: ADVANCED VULNERABILITY EXPLOITATION")
        print("="*60)
        
        vuln_data = self.db_scanner.run_full_scan()
        self.report["vulnerabilities"] = vuln_data["vulnerabilities"]
        self.report["extracted_credentials"] = vuln_data["extracted_credentials"]

    def generate_report(self, filename="aegis_report.json"):
        """Generate comprehensive JSON report"""
        with open(filename, 'w') as f:
            json.dump(self.report, f, indent=2)
        print(f"\n[+] Full report saved to: {filename}")
        
        # Print summary
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"Target: {self.target_url}")
        print(f"Open Ports: {len(self.report['discovery'].get('open_ports', []))}")
        print(f"Technologies Detected: {len(self.report['discovery'].get('tech_stack', []))}")
        print(f"Vulnerabilities Found: {len(self.report['vulnerabilities'])}")
        print(f"Credentials Extracted: {len(self.report['extracted_credentials'])}")
        print(f"CVE Correlations: {len(self.report['cve_correlations'])}")
        
        if self.report['extracted_credentials']:
            print("\n[!!!] EXTRACTED CREDENTIALS [!!!]")
            for cred in self.report['extracted_credentials']:
                print(f"  - Type: {cred.get('type', 'Unknown')}")
                if 'username_used' in cred:
                    print(f"    Username: {cred['username_used']}")
                    print(f"    Password: {cred['password_used']}")
                if 'key' in cred:
                    print(f"    {cred['key']}={cred['value']}")
                if 'extracted_session' in cred:
                    print(f"    Session: {cred['extracted_session']}")

def main():
    parser = argparse.ArgumentParser(description="AEGIS-2026 Advanced Security Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--output", default="aegis_report.json", help="Output report filename")
    
    args = parser.parse_args()
    
    print(r"""
     ___  _____  ______  ___  ________  _______   __
    / _ \/ __/ |/ / __ \/ _ \/ __/ _ \/ __/ _ | / /
   / // / _//    / /_/ / // / _// , _/ _// __ |/ / 
  /____/___/_/|_/\____/____/___/_/|_|___/_/ |_|_/  
                                                   
    AEGIS-2026 ENTERPRISE SECURITY SCANNER
    """)
    
    print("[!] LEGAL DISCLAIMER: This tool is for educational purposes only.")
    print("    Only use on systems you own or have explicit permission to test.")
    print(f"[*] Starting scan on: {args.url}\n")
    
    scanner = AegisScanner(args.url, args.timeout)
    
    try:
        scanner.run_phase1_discovery()
        scanner.run_phase2_vulnerability_scan()
        scanner.generate_report(args.output)
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Error during scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
