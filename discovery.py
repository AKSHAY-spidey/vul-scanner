"""
discovery.py - Advanced Discovery, Port Scanning, and Tech Fingerprinting
"""

import socket
import ssl
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import re
from payloads import TECH_FINGERPRINTS, PORT_SERVICES, SENSITIVE_FILES
from concurrent.futures import ThreadPoolExecutor, as_completed

class DiscoveryEngine:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        self.parsed_url = urlparse(target_url)
        self.hostname = self.parsed_url.hostname
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close"
        })
        self.technologies = []
        self.open_ports = []
        self.sensitive_files_found = []
        self.subdomains = []
        
    def scan_port(self, port):
        """Scan a single port using raw sockets."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.hostname, port))
            sock.close()
            if result == 0:
                service = PORT_SERVICES.get(port, "Unknown")
                # Try to grab banner
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2)
                    s.connect((self.hostname, port))
                    if port in [80, 8080]:
                        s.send(f"GET / HTTP/1.1\r\nHost: {self.hostname}\r\n\r\n".encode())
                    elif port == 443:
                        context = ssl.create_default_context()
                        s = context.wrap_socket(s, server_hostname=self.hostname)
                        s.send(f"GET / HTTP/1.1\r\nHost: {self.hostname}\r\n\r\n".encode())
                    else:
                        # Generic banner grab
                        pass
                    
                    banner = s.recv(1024).decode('utf-8', errors='ignore')
                    s.close()
                    return {"port": port, "service": service, "status": "open", "banner": banner.strip()}
                except:
                    return {"port": port, "service": service, "status": "open", "banner": ""}
            return None
        except Exception:
            return None

    def port_scan(self, common_ports_only=True):
        """Perform multi-threaded port scanning."""
        print(f"[*] Starting Port Scan on {self.hostname}...")
        ports_to_scan = list(PORT_SERVICES.keys()) if common_ports_only else range(1, 1025)
        
        open_ports = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports_to_scan}
            for future in as_completed(future_to_port):
                data = future.result()
                if data:
                    open_ports.append(data)
                    print(f"[+] Open Port: {data['port']} ({data['service']})")
                    if data['banner']:
                        print(f"    Banner: {data['banner'][:100]}...")
        
        self.open_ports = open_ports
        return open_ports

    def detect_technologies(self, response_text, headers):
        """Fingerprint technologies based on content and headers."""
        detected = []
        full_text = response_text + " " + str(headers)
        
        for tech, signatures in TECH_FINGERPRINTS.items():
            for sig in signatures:
                if sig.lower() in full_text.lower():
                    if tech not in detected:
                        detected.append(tech)
                        print(f"[+] Technology Detected: {tech}")
        
        # Check Server Header
        server = headers.get("Server", "")
        if server:
            version_match = re.search(r'([\w\s]+)/?([0-9.\]+)', server)
            if version_match:
                detected.append(f"{version_match.group(1)} (Version: {version_match.group(2)})")
        
        self.technologies = detected
        return detected

    def check_sensitive_files(self):
        """Check for exposed sensitive files and directories."""
        print("[*] Checking for sensitive files...")
        found = []
        
        for file_path in SENSITIVE_FILES:
            url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}/{file_path}"
            try:
                resp = self.session.get(url, timeout=5, allow_redirects=False)
                if resp.status_code == 200:
                    # Verify it's not a custom 404 page
                    if len(resp.content) > 50: 
                        found.append({"url": url, "status": resp.status_code, "size": len(resp.content)})
                        print(f"[!] Sensitive File Found: {url} (Size: {len(resp.content)} bytes)")
                elif resp.status_code in [401, 403]:
                    # Protected but exists
                    found.append({"url": url, "status": resp.status_code, "note": "Protected"})
                    print(f"[!] Protected Resource Found: {url} (Status: {resp.status_code})")
            except:
                continue
        
        self.sensitive_files_found = found
        return found

    def get_robots_txt(self):
        """Parse robots.txt for hidden paths."""
        url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}/robots.txt"
        hidden_paths = []
        try:
            resp = self.session.get(url, timeout=5)
            if resp.status_code == 200:
                lines = resp.text.split('\n')
                for line in lines:
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '*':
                            hidden_paths.append(path)
                            print(f"[i] Hidden path from robots.txt: {path}")
        except:
            pass
        return hidden_paths

    def run_full_discovery(self):
        """Execute the full discovery phase."""
        print("\n=== PHASE 1: DEEP DISCOVERY ===")
        
        # 1. Port Scan
        self.port_scan(common_ports_only=True)
        
        # 2. Initial Request for Tech Detection
        try:
            resp = self.session.get(self.target_url, timeout=self.timeout)
            techs = self.detect_technologies(resp.text, resp.headers)
            
            # 3. Sensitive Files
            self.check_sensitive_files()
            
            # 4. Robots.txt
            self.get_robots_txt()
            
            return {
                "hostname": self.hostname,
                "open_ports": self.open_ports,
                "technologies": techs,
                "sensitive_files": self.sensitive_files_found,
                "response_code": resp.status_code,
                "server_header": resp.headers.get("Server", "Unknown")
            }
        except Exception as e:
            print(f"[-] Error during discovery: {e}")
            return {"error": str(e)}
