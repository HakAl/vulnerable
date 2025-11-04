# api_client.py
"""
API client with hardcoded secrets and credentials.
"""
import requests
import boto3

# Hardcoded API credentials
SENDGRID_API_KEY = "SG.1234567890abcdefghijklmnopqrstuvwxyz.ABCDEFG"

# Hardcoded AWS credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_REGION = "us-east-1"

# Hardcoded private key
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz
ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnop
-----END RSA PRIVATE KEY-----"""


class APIClient:
    def __init__(self):
        # More hardcoded secrets
        self.jwt_secret = "my-super-secret-jwt-key-that-should-not-be-here"
        self.encryption_salt = "hardcoded-salt-value-123"

    def send_email(self, to_email, subject, body):
        """Send email using hardcoded API key"""
        headers = {
            'Authorization': f'Bearer {SENDGRID_API_KEY}',
            'Content-Type': 'application/json'
        }

        data = {
            'to': to_email,
            'subject': subject,
            'body': body
        }

        response = requests.post(
            'https://api.sendgrid.com/v3/mail/send',
            headers=headers,
            json=data
        )
        return response.json()

    def upload_to_s3(self, file_path, bucket_name):
        """Upload file using hardcoded AWS credentials"""
        s3_client = boto3.client(
            's3',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_REGION
        )

        s3_client.upload_file(file_path, bucket_name, file_path)
        return f"https://{bucket_name}.s3.amazonaws.com/{file_path}"


def get_user_data(username):
    """Fetch user data with SQL injection vulnerability"""
    import sqlite3

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # SQL injection - direct concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    user = cursor.fetchone()

    conn.close()
    return user


def authenticate_user(username, password):
    """Authentication with SQL injection"""
    import sqlite3

    # Hardcoded database password
    conn = sqlite3.connect('auth.db')
    cursor = conn.cursor()

    # SQL injection vulnerability
    sql = f"SELECT * FROM credentials WHERE user='{username}' AND pass='{password}'"
    cursor.execute(sql)
    result = cursor.fetchone()

    conn.close()
    return result is not None