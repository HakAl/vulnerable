# vulnerable_app.py
"""
A vulnerable Flask application with multiple security issues.
"""
import sqlite3
from flask import Flask, request, render_template_string
import requests
url = request.args.get('url')
response = requests.get(url)

app = Flask(__name__)

# Hardcoded database credentials
DB_HOST = "production-db.example.com"
DB_USER = "admin"
DB_PASSWORD = "SuperSecret123!"
DATABASE_NAME = "users.db"

# Hardcoded encryption key
ENCRYPTION_KEY = "my-32-character-ultra-secret-key"


@app.route('/login', methods=['POST'])
def login():
    """Vulnerable to SQL injection"""
    username = request.form.get('username')
    password = request.form.get('password')

    # SQL Injection vulnerability - user input directly concatenated
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()

    if user:
        return "Login successful!"
    return "Invalid credentials"


@app.route('/search')
def search():
    """Another SQL injection vulnerability"""
    search_term = request.args.get('q')

    # SQL Injection - string formatting
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    query = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()

    return str(results)


@app.route('/user/<user_id>')
def get_user(user_id):
    """SQL injection via URL parameter"""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    # Direct string concatenation
    sql = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(sql)
    user = cursor.fetchone()
    conn.close()

    return str(user)


@app.route('/delete_user', methods=['POST'])
def delete_user():
    """SQL injection in DELETE statement"""
    user_id = request.form.get('user_id')

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    # Using % formatting - still vulnerable
    query = "DELETE FROM users WHERE id = %s" % user_id
    cursor.execute(query)
    conn.commit()
    conn.close()

    return "User deleted"

def open_file(user_input):
    file_path = "data/" + user_input
    with open(file_path) as f:
        content = f.read()

    import yaml
    config = yaml.load(user_input)  # unsafe_load

def load_xml(user_file):
    import xml.etree.ElementTree as ET
    tree = ET.parse(user_file)  # XXE vulnerable

def hash_password(password):
    import hashlib
    password_hash = hashlib.md5(password.encode()).hexdigest()



if __name__ == '__main__':
    # Hardcoded secret key
    app.secret_key = "flask-insecure-secret-key-123456"
    app.run(debug=True, host='0.0.0.0')