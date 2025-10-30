"""
Vulnerable Web Application

DELIBERATELY VULNERABLE - For educational/testing purposes only.
Contains OWASP Top 10 vulnerabilities for red team training.
"""

import os
import sqlite3
from flask import Flask, request, render_template_string, redirect, url_for, session
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'super_secret_key_123'  # Weak secret key
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'

# Create uploads folder
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database
def init_db():
    conn = sqlite3.connect('/tmp/users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    # Insert default users
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 1)")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'password', 0)")
    conn.commit()
    conn.close()

init_db()


# Home page
@app.route('/')
def index():
    template = '''
    <!DOCTYPE html>
    <html>
    <head><title>VulnApp - Home</title></head>
    <body>
        <h1>Welcome to VulnApp</h1>
        <p>A deliberately vulnerable web application for security training.</p>
        <ul>
            <li><a href="/login">Login</a></li>
            <li><a href="/search">Search</a></li>
            <li><a href="/upload">Upload</a></li>
        </ul>
    </body>
    </html>
    '''
    return render_template_string(template)


# VULNERABILITY: SQL Injection
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # VULNERABLE: Direct string concatenation in SQL
        conn = sqlite3.connect('/tmp/users.db')
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

        try:
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()

            if user:
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['is_admin'] = user[3]
                return redirect(url_for('dashboard'))
            else:
                return "Invalid credentials", 401
        except Exception as e:
            return f"Error: {str(e)}", 500

    template = '''
    <!DOCTYPE html>
    <html>
    <head><title>Login</title></head>
    <body>
        <h1>Login</h1>
        <form method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    </body>
    </html>
    '''
    return render_template_string(template)


# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    template = '''
    <!DOCTYPE html>
    <html>
    <head><title>Dashboard</title></head>
    <body>
        <h1>Dashboard</h1>
        <p>Welcome, {{ username }}!</p>
        <p>Admin: {{ is_admin }}</p>
        <a href="/logout">Logout</a>
    </body>
    </html>
    '''
    return render_template_string(
        template,
        username=session.get('username'),
        is_admin=session.get('is_admin')
    )


# VULNERABILITY: Command Injection
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    if request.method == 'POST':
        host = request.form.get('host', '')

        # VULNERABLE: Direct command execution
        import subprocess
        try:
            result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
            return f"<pre>{result}</pre>"
        except Exception as e:
            return f"Error: {str(e)}"

    template = '''
    <!DOCTYPE html>
    <html>
    <head><title>Ping</title></head>
    <body>
        <h1>Ping Utility</h1>
        <form method="POST">
            Host: <input type="text" name="host"><br>
            <input type="submit" value="Ping">
        </form>
    </body>
    </html>
    '''
    return render_template_string(template)


# VULNERABILITY: File Upload (no validation)
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "No file provided", 400

        file = request.files['file']
        if file.filename == '':
            return "No file selected", 400

        # VULNERABLE: No file type validation, uses original filename
        filename = file.filename  # Should use secure_filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        return f"File uploaded successfully: {filename}"

    template = '''
    <!DOCTYPE html>
    <html>
    <head><title>Upload</title></head>
    <body>
        <h1>File Upload</h1>
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="file"><br>
            <input type="submit" value="Upload">
        </form>
    </body>
    </html>
    '''
    return render_template_string(template)


# VULNERABILITY: Server-Side Template Injection (SSTI)
@app.route('/search')
def search():
    query = request.args.get('q', '')

    # VULNERABLE: Direct template rendering of user input
    template = f'''
    <!DOCTYPE html>
    <html>
    <head><title>Search</title></head>
    <body>
        <h1>Search Results</h1>
        <p>You searched for: {query}</p>
        <form method="GET">
            <input type="text" name="q" value="">
            <input type="submit" value="Search">
        </form>
    </body>
    </html>
    '''
    return render_template_string(template)


# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
