"""
INTENTIONALLY VULNERABLE TEST TARGET (Flask)
DO NOT DEPLOY TO PRODUCTION - FOR TESTING ONLY!
Contains multiple vulnerabilities for scanner verification.
"""

from flask import Flask, request, jsonify, render_template_string, make_response
import sqlite3
import os

app = Flask(__name__)

# Initialize vulnerable database
def init_db():
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)''')
    # Insert default admin credentials
    c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES ('admin', 'securepass123', 'admin')")
    c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES ('user', 'password123', 'user')")
    conn.commit()
    conn.close()

# VULNERABLE: SQL Injection in login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # INTENTIONAL VULNERABILITY: String concatenation
        conn = sqlite3.connect('vulnerable.db')
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            c.execute(query)
            user = c.fetchone()
            conn.close()
            
            if user:
                resp = make_response(render_template_string("""
                    <html><body>
                    <h1>Login Successful!</h1>
                    <p>Welcome, {{ username }}!</p>
                    <p>Your role: {{ role }}</p>
                    <p>Dashboard access granted.</p>
                    </body></html>
                """, username=user[1], role=user[3]))
                resp.set_cookie('session', 'authenticated_session_12345')
                return resp
            else:
                return "Invalid credentials", 401
        except Exception as e:
            # VULNERABILITY: Error message disclosure
            return f"Database Error: {str(e)}", 500
    
    # Login form
    return render_template_string("""
        <html><body>
        <h1>Vulnerable Login</h1>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username"><br><br>
            <input type="password" name="password" placeholder="Password"><br><br>
            <input type="submit" value="Login">
        </form>
        </body></html>
    """)

# VULNERABLE: SQL Injection in search
@app.route('/search')
def search():
    query = request.args.get('q', '')
    if not query:
        return "Use ?q=search_term to search users"
    
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    # INTENTIONAL VULNERABILITY
    sql_query = f"SELECT username, role FROM users WHERE username LIKE '%{query}%'"
    try:
        c.execute(sql_query)
        results = c.fetchall()
        conn.close()
        return jsonify({"results": results})
    except Exception as e:
        # VULNERABILITY: Detailed error
        return jsonify({"error": str(e), "query": sql_query}), 500

# VULNERABLE: Exposed .env file
@app.route('/.env')
def env_file():
    return """
DATABASE_URL=sqlite:///vulnerable.db
DB_PASSWORD=SuperSecretDBPass123!
API_KEY=sk-1234567890abcdef
SECRET_KEY=super_secret_key_do_not_share
ADMIN_EMAIL=admin@vulnerable-site.com
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

# VULNERABLE: GraphQL endpoint with introspection
@app.route('/graphql', methods=['POST'])
def graphql():
    data = request.get_json()
    query = data.get('query', '')
    
    # Simple GraphQL-like parser (vulnerable to batch attacks)
    if '__schema' in query:
        return jsonify({
            "data": {
                "__schema": {
                    "types": [
                        {"name": "User", "fields": [{"name": "id"}, {"name": "username"}, {"name": "password"}]},
                        {"name": "Query", "fields": [{"name": "user"}, {"name": "users"}]}
                    ]
                }
            }
        })
    
    if '__typename' in query:
        return jsonify({"data": {"__typename": "Query"}})
    
    return jsonify({"error": "Unsupported query"})

# VULNERABLE: Path traversal
@app.route('/files')
def files():
    filename = request.args.get('name', 'index.html')
    # INTENTIONAL VULNERABILITY: No sanitization
    try:
        with open(filename, 'r') as f:
            return f.read()
    except Exception as e:
        return f"Error: {str(e)}", 500

# Home page with tech fingerprints
@app.route('/')
def home():
    return render_template_string("""
        <html>
        <head><title>Vulnerable Test Site</title></head>
        <body>
        <h1>AEGIS-2026 Test Target</h1>
        <p>This site is intentionally vulnerable for testing purposes.</p>
        <ul>
            <li><a href="/login">Login Page (SQLi)</a></li>
            <li><a href="/search?q=admin">Search Users (SQLi)</a></li>
            <li><a href="/.env">Exposed .env</a></li>
            <li><a href="/graphql">GraphQL Endpoint</a></li>
        </ul>
        <!-- Built with Flask + SQLite -->
        <!-- Technologies: Python, Flask, SQLite, Next.js (fake), React (fake) -->
        </body>
        </html>
    """)

if __name__ == '__main__':
    init_db()
    print("[*] Starting vulnerable test server on http://localhost:8080")
    print("[!] WARNING: This server is intentionally vulnerable!")
    app.run(host='0.0.0.0', port=8080, debug=True)
