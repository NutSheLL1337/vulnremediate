"""
Vulnerable Flask Application - Demo для VulnRemediate PoC
Містить навмисні вразливості для тестування:
- CWE-89: SQL Injection
- CWE-79: Cross-Site Scripting (XSS)
- CWE-22: Path Traversal
- CWE-798: Hardcoded Credentials
- CWE-327: Weak Cryptography (MD5)
- CWE-502: Insecure Deserialization
- CWE-601: Open Redirect
- CWE-78: OS Command Injection
"""

from flask import Flask, request, render_template_string, send_file, redirect
import sqlite3
import hashlib
import pickle
import os
import subprocess

app = Flask(__name__)

# CWE-798: Hardcoded credentials
DATABASE = 'vulnerable_app.db'
ADMIN_PASSWORD = 'admin123'  # Hardcoded password - VULNERABLE!
SECRET_KEY = 'my-secret-key-12345'  # Hardcoded secret - VULNERABLE!

# Initialize database
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author TEXT
        )
    ''')
    # Insert sample data
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@example.com')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'password', 'user@example.com')")
    cursor.execute("INSERT OR IGNORE INTO posts VALUES (1, 'Welcome', 'Welcome to our blog!', 'admin')")
    conn.commit()
    conn.close()

init_db()

# Home page
@app.route('/')
def home():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerable Flask App</title>
        <style>
            body { font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px; }
            .vuln-card { background: #f8d7da; padding: 15px; margin: 10px 0; border-radius: 5px; }
            h1 { color: #dc3545; }
            a { display: inline-block; margin: 5px; padding: 10px; background: #007bff; color: white; text-decoration: none; border-radius: 3px; }
            a:hover { background: #0056b3; }
        </style>
    </head>
    <body>
        <h1>🔥 Vulnerable Flask Application</h1>
        <p>Це демонстраційний додаток з навмисними вразливостями для тестування VulnRemediate PoC</p>
        
        <h2>Доступні endpoints:</h2>
        <a href="/login">Login (SQLi)</a>
        <a href="/search">Search (XSS)</a>
        <a href="/file?name=test.txt">File Read (Path Traversal)</a>
        <a href="/hash">Hash (Weak Crypto)</a>
        <a href="/ping">Ping (Command Injection)</a>
        <a href="/redirect?url=https://google.com">Redirect (Open Redirect)</a>
        
        <div class="vuln-card">
            <h3>⚠️ УВАГА</h3>
            <p>Цей додаток містить <strong>навмисні вразливості</strong> для освітніх цілей!</p>
            <p>Не використовуйте цей код у production!</p>
        </div>
    </body>
    </html>
    """
    return html

# CWE-89: SQL Injection
@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ""
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # VULNERABLE: SQL Injection через string concatenation
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        try:
            cursor.execute(query)  # VULNERABLE!
            user = cursor.fetchone()
            
            if user:
                message = f"<div style='color: green;'>✅ Успішний вхід як {user[1]}!</div>"
            else:
                message = "<div style='color: red;'>❌ Невірні credentials</div>"
        except Exception as e:
            message = f"<div style='color: red;'>❌ Помилка: {e}</div>"
        finally:
            conn.close()
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Login - SQLi Vulnerable</title></head>
    <body style="font-family: Arial; max-width: 600px; margin: 50px auto;">
        <h2>🔐 Login (SQL Injection Vulnerable)</h2>
        {message}
        <form method="POST">
            <p><input type="text" name="username" placeholder="Username" required style="padding: 10px; width: 300px;"></p>
            <p><input type="password" name="password" placeholder="Password" required style="padding: 10px; width: 300px;"></p>
            <p><button type="submit" style="padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 3px;">Login</button></p>
        </form>
        <div style="background: #fff3cd; padding: 15px; margin-top: 20px; border-radius: 5px;">
            <strong>💡 Спробуйте:</strong>
            <p>Username: <code>admin' OR '1'='1</code></p>
            <p>Password: <code>anything</code></p>
        </div>
        <p><a href="/">← Назад</a></p>
    </body>
    </html>
    """
    return html

# CWE-79: Cross-Site Scripting (XSS)
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    
    # VULNERABLE: XSS через пряме вставлення user input
    html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Search - XSS Vulnerable</title></head>
    <body style="font-family: Arial; max-width: 600px; margin: 50px auto;">
        <h2>🔍 Search (XSS Vulnerable)</h2>
        <form method="GET">
            <input type="text" name="q" placeholder="Search..." value="{query}" style="padding: 10px; width: 300px;">
            <button type="submit" style="padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 3px;">Search</button>
        </form>
        <div style="margin-top: 20px;">
            <p>Результати для: {query}</p>
        </div>
        <div style="background: #fff3cd; padding: 15px; margin-top: 20px; border-radius: 5px;">
            <strong>💡 Спробуйте:</strong>
            <p><code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
            <p><code>&lt;img src=x onerror=alert('XSS')&gt;</code></p>
        </div>
        <p><a href="/">← Назад</a></p>
    </body>
    </html>
    """
    return html

# CWE-22: Path Traversal
@app.route('/file', methods=['GET'])
def read_file():
    filename = request.args.get('name', 'test.txt')
    
    # VULNERABLE: Path traversal через direct file access
    try:
        filepath = os.path.join('.', filename)  # VULNERABLE!
        with open(filepath, 'r') as f:
            content = f.read()
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head><title>File Reader - Path Traversal Vulnerable</title></head>
        <body style="font-family: Arial; max-width: 600px; margin: 50px auto;">
            <h2>📄 File Reader (Path Traversal Vulnerable)</h2>
            <p><strong>File:</strong> {filename}</p>
            <pre style="background: #f4f4f4; padding: 15px; border-radius: 5px;">{content}</pre>
            <div style="background: #fff3cd; padding: 15px; margin-top: 20px; border-radius: 5px;">
                <strong>💡 Спробуйте:</strong>
                <p><code>?name=../../../etc/passwd</code> (Linux)</p>
                <p><code>?name=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts</code> (Windows)</p>
            </div>
            <p><a href="/">← Назад</a></p>
        </body>
        </html>
        """
    except Exception as e:
        return f"<p>❌ Помилка: {e}</p><p><a href='/'>← Назад</a></p>"

# CWE-327: Weak Cryptography
@app.route('/hash', methods=['GET', 'POST'])
def hash_password():
    result = ""
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        
        # VULNERABLE: Using MD5 for password hashing
        hashed = hashlib.md5(password.encode()).hexdigest()  # VULNERABLE!
        result = f"<p><strong>MD5 Hash:</strong> <code>{hashed}</code></p>"
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Hash - Weak Crypto</title></head>
    <body style="font-family: Arial; max-width: 600px; margin: 50px auto;">
        <h2>🔐 Password Hasher (Weak Crypto)</h2>
        <form method="POST">
            <p><input type="text" name="password" placeholder="Enter password" style="padding: 10px; width: 300px;"></p>
            <p><button type="submit" style="padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 3px;">Hash with MD5</button></p>
        </form>
        {result}
        <div style="background: #f8d7da; padding: 15px; margin-top: 20px; border-radius: 5px;">
            <strong>⚠️ Vulnerability:</strong>
            <p>Використання MD5 для хешування паролів є небезпечним! MD5 легко зламати.</p>
            <p>Використовуйте bcrypt, scrypt, або Argon2 замість MD5!</p>
        </div>
        <p><a href="/">← Назад</a></p>
    </body>
    </html>
    """

# CWE-78: OS Command Injection
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    result = ""
    
    if request.method == 'POST':
        host = request.form.get('host', '')
        
        # VULNERABLE: Command injection через subprocess
        try:
            cmd = f"ping -c 3 {host}"  # VULNERABLE!
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)  # VULNERABLE!
            result = f"<pre style='background: #f4f4f4; padding: 15px; border-radius: 5px;'>{output.decode()}</pre>"
        except Exception as e:
            result = f"<p style='color: red;'>❌ Помилка: {e}</p>"
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Ping - Command Injection</title></head>
    <body style="font-family: Arial; max-width: 600px; margin: 50px auto;">
        <h2>🌐 Ping Utility (Command Injection Vulnerable)</h2>
        <form method="POST">
            <p><input type="text" name="host" placeholder="Host to ping" style="padding: 10px; width: 300px;"></p>
            <p><button type="submit" style="padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 3px;">Ping</button></p>
        </form>
        {result}
        <div style="background: #fff3cd; padding: 15px; margin-top: 20px; border-radius: 5px;">
            <strong>💡 Спробуйте:</strong>
            <p><code>127.0.0.1; ls -la</code> (Linux)</p>
            <p><code>127.0.0.1 & dir</code> (Windows)</p>
        </div>
        <p><a href="/">← Назад</a></p>
    </body>
    </html>
    """

# CWE-601: Open Redirect
@app.route('/redirect', methods=['GET'])
def open_redirect():
    url = request.args.get('url', '/')
    
    # VULNERABLE: Open redirect без валідації
    return redirect(url)  # VULNERABLE!

# Health check endpoint
@app.route('/health')
def health():
    return {"status": "ok", "vulnerabilities": 8}

if __name__ == '__main__':
    print("🔥 Starting Vulnerable Flask Application...")
    print("⚠️  WARNING: This app contains intentional vulnerabilities!")
    print("📍 Running on http://localhost:5001")
    app.run(host='0.0.0.0', port=5001, debug=True)
