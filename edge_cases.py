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
from Crypto.Cipher import AES
import hashlib
app = Flask(__name__)

@app.route('/admin/<path:file>')
def serve_file(file):
    return send_file(file)




# Fix: Use a secure random key and fix the mode.
def weak_encryption(data):
    # Fix: Use a secure random key.
    key = hashlib.sha256(os.urandom(16))).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data.encode())


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


app.run(debug=False, host='127.0.0.1'))
