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