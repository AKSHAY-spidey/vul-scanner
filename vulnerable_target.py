#!/usr/bin/env python3
"""
VULNERABLE TEST TARGET SIMULATOR
================================
This creates a local web server with INTENTIONAL vulnerabilities
for testing the scanner. DO NOT USE IN PRODUCTION.

Contains:
- SQL Injection in login form
- SQL Injection in URL parameters
- Exposed sensitive files
- Missing security headers
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json
import re

# Simulated Database
USERS_DB = [
    {"id": 1, "username": "admin", "password": "securepass123", "role": "administrator"},
    {"id": 2, "username": "user1", "password": "userpass456", "role": "user"},
    {"id": 3, "username": "test", "password": "test123", "role": "user"}
]

class VulnerableHandler(BaseHTTPRequestHandler):
    
    def do_GET(self):
        parsed_path = urlparse(self.path)
        query_params = parse_qs(parsed_path.query)
        
        # Intentionally missing security headers
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        # NOTE: No X-Frame-Options, No CSP, No HSTS (intentional)
        self.end_headers()
        
        # VULNERABLE ENDPOINT: Search with SQLi
        if parsed_path.path == '/search':
            keyword = query_params.get('q', [''])[0]
            
            # VULNERABLE: Direct string concatenation (simulated SQLi)
            if "'" in keyword or "OR" in keyword or "UNION" in keyword:
                # Simulate SQL Error
                response = f"""
                <html><body>
                <h1>Search Results</h1>
                <div style="color:red; font-family:monospace;">
                MySQL Error: You have an error in your SQL syntax near '{keyword}' at line 1
                </div>
                </body></html>
                """
                self.wfile.write(response.encode())
                return
            
            response = f"<html><body><h1>Search for: {keyword}</h1><p>No results found.</p></body></html>"
            self.wfile.write(response.encode())
            return
        
        # VULNERABLE ENDPOINT: User Profile
        if parsed_path.path == '/user':
            user_id = query_params.get('id', ['1'])[0]
            
            # Simulate Time-based blind SQLi detection
            if "SLEEP" in user_id or "WAITFOR" in user_id:
                import time
                time.sleep(5)  # Simulate delay
                response = "<html><body><h1>User Profile</h1><p>Loading...</p></body></html>"
                self.wfile.write(response.encode())
                return
            
            # Normal response
            response = f"""
            <html><body>
            <h1>User Profile</h1>
            <p>User ID: {user_id}</p>
            <p>Username: admin</p>
            <p>Email: admin@example.com</p>
            </body></html>
            """
            self.wfile.write(response.encode())
            return
        
        # SENSITIVE FILE: Exposed .env
        if parsed_path.path == '/.env':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            response = """
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=SuperSecretDBPass123!
API_KEY=sk-1234567890abcdef
ADMIN_EMAIL=admin@company.com
            """
            self.wfile.write(response.encode())
            return
        
        # SENSITIVE FILE: Git Config
        if parsed_path.path == '/.git/config':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            response = """
[core]
    repositoryformatversion = 0
[remote "origin"]
    url = https://github.com/company/internal-repo.git
            """
            self.wfile.write(response.encode())
            return
        
        # DEFAULT: Login Page with Form
        login_form = """
        <html>
        <head><title>Vulnerable Login</title></head>
        <body>
        <h1>Welcome to Vulnerable App</h1>
        <form action="/login" method="POST">
            <label>Username:</label><br>
            <input type="text" name="username"><br>
            <label>Password:</label><br>
            <input type="password" name="password"><br><br>
            <input type="submit" value="Login">
        </form>
        <p><a href="/search?q=test">Search</a> | <a href="/user?id=1">Profile</a></p>
        <p><a href="/.env">Config</a> (oops, exposed!)</p>
        </body>
        </html>
        """
        self.wfile.write(login_form.encode())
    
    def do_POST(self):
        parsed_path = urlparse(self.path)
        
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = parse_qs(post_data)
        
        username = params.get('username', [''])[0]
        password = params.get('password', [''])[0]
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        # VULNERABLE LOGIN: SQL Injection Bypass
        # Check for classic SQLi bypass patterns
        if ("' OR '1'='1" in username) or ("' OR 1=1" in username) or ("admin'--" in username):
            # Authentication Bypass Successful
            response = """
            <html><body style="background-color:#d4edda;">
            <h1>LOGIN SUCCESSFUL!</h1>
            <h2>Welcome, Administrator!</h2>
            <p>You have bypassed authentication.</p>
            <div style="border:1px solid red; padding:10px; background:#fff;">
            <h3>CREDENTIALS EXTRACTED VIA SQLi:</h3>
            <p><strong>Username:</strong> admin</p>
            <p><strong>Password:</strong> securepass123</p>
            <p><strong>Role:</strong> administrator</p>
            </div>
            <p><a href="/">Back to Login</a></p>
            </body></html>
            """
            self.wfile.write(response.encode())
            return
        
        # Normal authentication check
        user_found = None
        for user in USERS_DB:
            if user['username'] == username and user['password'] == password:
                user_found = user
                break
        
        if user_found:
            response = f"""
            <html><body style="background-color:#d4edda;">
            <h1>Login Successful</h1>
            <p>Welcome, {user_found['username']}!</p>
            </body></html>
            """
        else:
            response = """
            <html><body style="background-color:#f8d7da;">
            <h1>Login Failed</h1>
            <p>Invalid username or password.</p>
            <p><a href="/">Try Again</a></p>
            </body></html>
            """
        
        self.wfile.write(response.encode())
    
    def log_message(self, format, *args):
        # Suppress default logging for cleaner output
        pass

def run_server(port=8080):
    server_address = ('', port)
    httpd = HTTPServer(server_address, VulnerableHandler)
    print(f"\n[+] VULNERABLE TEST SERVER STARTED")
    print(f"[+] Running on http://localhost:{port}")
    print(f"[+] Intentional Vulnerabilities:")
    print(f"    - SQL Injection in /search?q=")
    print(f"    - SQL Injection in /user?id=")
    print(f"    - Auth Bypass in /login (POST)")
    print(f"    - Exposed /.env and /.git/config")
    print(f"    - Missing Security Headers")
    print(f"\n[*] Waiting for scanner connections...\n")
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()
