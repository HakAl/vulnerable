# test_vulnerable.py
"""
Comprehensive test file with various security vulnerabilities
for stress-testing SecureFix remediation engine.
"""

# ============================================================================
# Edge Cases & Corner Cases
# ============================================================================

# Obfuscated SQL injection
def get_user_data(table, uid):
    query = "SELECT * FROM " + table + " WHERE id=" + str(uid)
    cursor.execute(query)
    return cursor.fetchall()


# Nested dangerous operations
def execute_user_code(user_input):
    exec(compile(user_input, '<string>', 'exec'))


# Path traversal via Flask route
from flask import Flask, send_file
app = Flask(__name__)

@app.route('/admin/<path:file>')
def serve_file(file):
    return send_file(file)


# Multiple crypto weaknesses
from Crypto.Cipher import AES
import hashlib

def weak_encryption(data):
    key = hashlib.md5(b'weak').digest()  # Weak hash + hardcoded key
    cipher = AES.new(key, AES.MODE_ECB)  # Weak cipher mode
    return cipher.encrypt(data)


# ============================================================================
# Ambiguous/Complex Contexts
# ============================================================================

# Context-dependent vulnerability (could be env var or hardcoded)
def get_password():
    password = get_config('PASSWORD')
    return password


# Multiple vulnerabilities in single line
def check_user_password(pwd, uid):
    cursor.execute(f"SELECT * FROM users WHERE pass='{hashlib.md5(pwd.encode()).hexdigest()}' AND id={uid}")


# Unsafe deserialization with user input
import pickle
import yaml

def load_user_data(data, format_type):
    if format_type == 'pickle':
        return pickle.loads(data)
    elif format_type == 'yaml':
        return yaml.load(data)  # unsafe_load


# ============================================================================
# Python-Specific Quirks
# ============================================================================

# Dynamic imports with user input
def dynamic_import(module_name):
    return __import__(module_name)


# Eval with f-string
def calculate(user_input):
    result = eval(f"print({user_input})")
    return result


# Os.system with user input
import os

def run_command(user_cmd):
    os.system(user_cmd)


# Subprocess with shell=True
import subprocess

def execute_shell_command(cmd):
    subprocess.call(cmd, shell=True)


# ============================================================================
# Complex SQL Injections
# ============================================================================

# Order by injection
def get_sorted_users(sort_column):
    query = f"SELECT * FROM users ORDER BY {sort_column}"
    cursor.execute(query)


# LIKE injection
def search_users(pattern):
    query = f"SELECT * FROM users WHERE name LIKE '%{pattern}%'"
    cursor.execute(query)


# Union-based injection
def get_user_with_union(user_id):
    query = "SELECT name, email FROM users WHERE id=" + user_id + " UNION SELECT password, salt FROM credentials"
    cursor.execute(query)


# ============================================================================
# Hardcoded Secrets Variations
# ============================================================================

# AWS credentials
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


# Database credentials
DB_CONFIG = {
    'host': 'localhost',
    'user': 'admin',
    'password': 'admin123',  # Hardcoded password
    'database': 'prod_db'
}


# API tokens in code
STRIPE_SECRET_KEY = "sk_live_51HqJ8kLKj8..."
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnop"


# JWT secret
JWT_SECRET = "my-secret-key-12345"


# ============================================================================
# Weak Cryptography Variations
# ============================================================================

# MD5 for password hashing
def hash_password_md5(password):
    return hashlib.md5(password.encode()).hexdigest()


# SHA1 for signatures
def sign_data(data):
    return hashlib.sha1(data.encode()).hexdigest()


# Insecure random for tokens
import random

def generate_token():
    return str(random.randint(1000, 9999))


# Weak SSL/TLS configuration
import ssl
import requests

def fetch_data_insecure(url):
    context = ssl._create_unverified_context()
    response = requests.get(url, verify=False)
    return response.text


# ============================================================================
# XSS Vulnerabilities (Framework-specific)
# ============================================================================

from flask import Flask, request, render_template_string

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Direct injection into template
    return render_template_string(f"<h1>Results for: {query}</h1>")


# Django mark_safe misuse
from django.utils.safestring import mark_safe

def render_user_content(user_html):
    return mark_safe(user_html)  # XSS if user_html is unsanitized


# ============================================================================
# Command Injection Variations
# ============================================================================

# Via os.popen
def check_host(hostname):
    result = os.popen(f"ping -c 1 {hostname}").read()
    return result


# Via subprocess with string concatenation
def git_clone(repo_url):
    cmd = f"git clone {repo_url}"
    subprocess.run(cmd, shell=True)


# Wildcard injection in shell commands
def backup_files(pattern):
    os.system(f"tar czf backup.tar.gz {pattern}")


# ============================================================================
# XML/XXE Vulnerabilities
# ============================================================================

import xml.etree.ElementTree as ET

def parse_xml_unsafe(xml_string):
    tree = ET.fromstring(xml_string)  # Vulnerable to XXE
    return tree


# ============================================================================
# Insecure File Operations
# ============================================================================

# Insecure temp file
import tempfile

def create_temp_file():
    filename = "/tmp/myapp_" + str(random.randint(1000, 9999))
    with open(filename, 'w') as f:
        f.write("sensitive data")


# Insecure file permissions
def create_config_file():
    import os
    with open('/etc/myapp.conf', 'w') as f:
        f.write("secret=password123")
    os.chmod('/etc/myapp.conf', 0o777)  # World-writable


# ============================================================================
# SSRF Vulnerabilities
# ============================================================================

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    response = requests.get(url)  # SSRF - can hit internal services
    return response.text


# ============================================================================
# Race Conditions & TOCTOU
# ============================================================================

def check_and_delete_file(filepath):
    if os.path.exists(filepath):  # Check
        # ... time gap ...
        os.remove(filepath)  # Use - TOCTOU vulnerability


# ============================================================================
# Insecure Deserialization Complex Cases
# ============================================================================

# PyYAML unsafe load with nested data
def load_config_yaml(config_file):
    with open(config_file, 'r') as f:
        return yaml.load(f)  # Unsafe


# Pickle with user-provided data
def restore_session(session_data):
    return pickle.loads(session_data)


# ============================================================================
# Authentication/Authorization Issues
# ============================================================================

# Weak password validation
def is_valid_password(password):
    return len(password) >= 6  # Too weak


# No rate limiting on login
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    # No rate limiting - brute force vulnerable
    if check_credentials(username, password):
        return "Success"
    return "Failed"


# Insecure session management
from flask import session

@app.route('/set_admin')
def set_admin():
    session['is_admin'] = True  # No verification
    return "You are now admin"


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')  # Debug mode in production