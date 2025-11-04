# admin_panel.py
"""
Admin panel with multiple security vulnerabilities.
"""
import sqlite3
from flask import Flask, request, session

app = Flask(__name__)

# Hardcoded admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Admin123!@#"
SUPER_ADMIN_TOKEN = "sa_1234567890abcdefghijklmnopqrstuvwxyz"

# Hardcoded session secret
app.secret_key = "super-secret-session-key-12345"

# Hardcoded JWT secret
JWT_SECRET = "jwt-secret-key-for-admin-panel"


@app.route('/admin/users')
def list_users():
    """List users with SQL injection vulnerability"""
    role = request.args.get('role', 'user')

    conn = sqlite3.connect('admin.db')
    cursor = conn.cursor()

    # SQL injection vulnerability
    query = "SELECT * FROM users WHERE role = '" + role + "' ORDER BY created_at"
    cursor.execute(query)
    users = cursor.fetchall()

    conn.close()
    return str(users)


@app.route('/admin/execute')
def execute_query():
    """Extremely dangerous - executes arbitrary SQL"""
    sql = request.args.get('sql')

    conn = sqlite3.connect('admin.db')
    cursor = conn.cursor()

    # Direct execution of user input - major vulnerability
    cursor.execute(sql)
    results = cursor.fetchall()
    conn.commit()

    conn.close()
    return str(results)


@app.route('/admin/update_user', methods=['POST'])
def update_user():
    """Update user with SQL injection"""
    user_id = request.form.get('id')
    new_email = request.form.get('email')
    new_role = request.form.get('role')

    conn = sqlite3.connect('admin.db')
    cursor = conn.cursor()

    # Multiple SQL injections
    update_sql = f"""
        UPDATE users 
        SET email = '{new_email}', role = '{new_role}' 
        WHERE id = {user_id}
    """
    cursor.execute(update_sql)
    conn.commit()
    conn.close()

    return "User updated"


def check_admin_access(token):
    """Check admin access with hardcoded token"""
    if token == SUPER_ADMIN_TOKEN:
        return True

    # Also check against hardcoded admin password
    if token == ADMIN_PASSWORD:
        return True

    return False


def get_reports(start_date, end_date, report_type):
    """Generate reports with SQL injection"""
    conn = sqlite3.connect('analytics.db')
    cursor = conn.cursor()

    # SQL injection in date range query
    query = f"""
        SELECT * FROM reports 
        WHERE date >= '{start_date}' 
        AND date <= '{end_date}' 
        AND type = '{report_type}'
    """
    cursor.execute(query)
    reports = cursor.fetchall()

    conn.close()
    return reports


if __name__ == '__main__':
    # Running with hardcoded credentials and debug mode
    app.run(debug=True, host='0.0.0.0', port=5000)