"""
ADVANCED DISCOVERY ENGINE
Handles port scanning, tech fingerprinting, cloud detection, and service analysis.
"""

import socket
import threading
import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

class DiscoveryEngine:
    def __init__(self, target_url, timeout=5):
        self.target_url = target_url
        self.timeout = timeout
        self.parsed_url = urlparse(target_url)
        self.hostname = self.parsed_url.hostname
        self.open_ports = []
        self.tech_stack = []
        self.services = {}
        self.cloud_provider = None
        
    def scan_port(self, port):
        """Scan a single port with banner grabbing"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.hostname, port))
            
            if result == 0:
                # Banner grabbing
                try:
                    sock.send(b"GET / HTTP/1.1\r\nHost: " + self.hostname.encode() + b"\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    sock.close()
                    
                    service_info = {
                        "port": port,
                        "state": "open",
                        "banner": banner[:200] if banner else "No banner",
                        "service": self._identify_service(port, banner)
                    }
                    return service_info
                except:
                    sock.close()
                    return {"port": port, "state": "open", "banner": "Closed during banner grab", "service": "unknown"}
            else:
                sock.close()
                return None
        except Exception as e:
            return None

    def _identify_service(self, port, banner):
        """Identify service based on port and banner"""
        common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
            53: "DNS", 80: "HTTP", 443: "HTTPS", 3306: "MySQL",
            5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
            8080: "HTTP-Proxy", 9200: "Elasticsearch", 11211: "Memcached"
        }
        
        service = common_services.get(port, "Unknown")
        
        # Banner analysis
        if banner:
            if "nginx" in banner.lower(): service = "Nginx"
            elif "apache" in banner.lower(): service = "Apache"
            elif "iis" in banner.lower(): service = "IIS"
            elif "mysql" in banner.lower(): service = "MySQL"
            elif "postgres" in banner.lower(): service = "PostgreSQL"
            elif "redis" in banner.lower(): service = "Redis"
            elif "mongo" in banner.lower(): service = "MongoDB"
            elif "elasticsearch" in banner.lower(): service = "Elasticsearch"
            
        return service

    def run_port_scan(self, ports=None, threads=50):
        """Multi-threaded port scanner"""
        if ports is None:
            # Common ports + database ports + cloud ports
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 
                     3306, 5432, 6379, 27017, 9200, 11211, 8080, 8443, 
                     9000, 9090, 15672, 5672, 4369, 2181, 9092] # Kafka, RabbitMQ, Zookeeper
        
        print(f"[*] Starting port scan on {len(ports)} ports for {self.hostname}...")
        results = []
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    results.append(result)
                    self.open_ports.append(result['port'])
                    self.services[result['port']] = result['service']
                    print(f"[+] Port {result['port']} open: {result['service']}")
                    
        return results

    def fingerprint_technologies(self):
        """Advanced technology fingerprinting"""
        print("[*] Fingerprinting technologies...")
        headers = {}
        tech_stack = []
        
        try:
            response = requests.get(self.target_url, timeout=self.timeout, allow_redirects=True)
            headers = response.headers
            
            # Header analysis
            server = headers.get('Server', '')
            x_powered_by = headers.get('X-Powered-By', '')
            x_generator = headers.get('X-Generator', '')
            
            if 'nginx' in server.lower(): tech_stack.append("Nginx")
            if 'apache' in server.lower(): tech_stack.append("Apache")
            if 'iis' in server.lower(): tech_stack.append("IIS")
            if 'express' in x_powered_by.lower(): tech_stack.append("Express.js")
            if 'asp.net' in x_powered_by.lower(): tech_stack.append("ASP.NET")
            if 'php' in x_powered_by.lower(): tech_stack.append("PHP")
            if 'wordpress' in x_generator.lower(): tech_stack.append("WordPress")
            
            # Cookie analysis
            cookies = headers.get('Set-Cookie', '')
            if 'JSESSIONID' in cookies: tech_stack.append("Java/JSP")
            if 'csrftoken' in cookies: tech_stack.append("Django")
            if 'connect.sid' in cookies: tech_stack.append("Node.js/Express")
            
            # HTML Content Analysis
            content = response.text.lower()
            if 'react' in content or 'react-dom' in content: tech_stack.append("React")
            if 'vue' in content: tech_stack.append("Vue.js")
            if 'angular' in content: tech_stack.append("Angular")
            if 'next.js' in content or '__next' in content: tech_stack.append("Next.js")
            if 'graphql' in content: tech_stack.append("GraphQL")
            if 'apollo' in content: tech_stack.append("Apollo GraphQL")
            if 'fastapi' in content: tech_stack.append("FastAPI")
            if 'django' in content: tech_stack.append("Django")
            if 'flask' in content: tech_stack.append("Flask")
            if 'laravel' in content: tech_stack.append("Laravel")
            if 'rails' in content: tech_stack.append("Ruby on Rails")
            
            # K8s / Cloud Detection
            if 'kubernetes' in content or 'k8s' in content: tech_stack.append("Kubernetes")
            if 'docker' in content: tech_stack.append("Docker")
            
            self.tech_stack = list(set(tech_stack))
            print(f"[+] Detected Technologies: {', '.join(self.tech_stack)}")
            
            return self.tech_stack, headers
            
        except Exception as e:
            print(f"[-] Error fingerprinting: {e}")
            return [], {}

    def detect_cloud_provider(self):
        """Detect cloud provider via metadata endpoints (Simulated for safety)"""
        print("[*] Checking for cloud environment...")
        # In a real scenario, this would attempt to reach metadata IPs
        # Here we simulate based on DNS patterns
        if 'amazonaws' in self.hostname:
            self.cloud_provider = "AWS"
        elif 'googlecloud' in self.hostname or 'gcp' in self.hostname:
            self.cloud_provider = "GCP"
        elif 'azure' in self.hostname:
            self.cloud_provider = "Azure"
        elif 'alibaba' in self.hostname:
            self.cloud_provider = "Alibaba Cloud"
        else:
            self.cloud_provider = "Unknown/On-Premise"
            
        print(f"[+] Cloud Environment: {self.cloud_provider}")
        return self.cloud_provider

    def check_security_headers(self, headers):
        """Analyze missing security headers"""
        missing = []
        required_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Referrer-Policy"
        ]
        
        for header in required_headers:
            if header not in headers:
                missing.append(header)
                
        return missing

    def run_full_discovery(self):
        """Execute full discovery phase"""
        port_results = self.run_port_scan()
        tech_stack, headers = self.fingerprint_technologies()
        cloud = self.detect_cloud_provider()
        missing_headers = self.check_security_headers(headers)
        
        if missing_headers:
            print(f"[!] Missing Security Headers: {', '.join(missing_headers)}")
            
        return {
            "open_ports": port_results,
            "tech_stack": tech_stack,
            "cloud_provider": cloud,
            "missing_headers": missing_headers,
            "raw_headers": dict(headers)
        }
