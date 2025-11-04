# # database.py
# """
# Database connection module with hardcoded credentials.
# """
# import mysql.connector
# import psycopg2
# from pymongo import MongoClient
#
# # Hardcoded MySQL credentials
# MYSQL_HOST = "mysql.prod.example.com"
# MYSQL_USER = "root"
# MYSQL_PASSWORD = "RootPass2024!"
# MYSQL_DATABASE = "production_db"
#
# # Hardcoded PostgreSQL credentials
# POSTGRES_URL = "postgresql://admin:AdminPass123@db.example.com:5432/maindb"
#
# # Hardcoded MongoDB credentials
# MONGO_URI = "mongodb://admin:MongoSecret456@mongo.example.com:27017/admin"
#
#
# class DatabaseManager:
#     def __init__(self):
#         # Hardcoded connection string
#         self.api_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret_payload"
#
#     def connect_mysql(self):
#         """Connect to MySQL with hardcoded credentials"""
#         return mysql.connector.connect(
#             host=MYSQL_HOST,
#             user=MYSQL_USER,
#             password=MYSQL_PASSWORD,
#             database=MYSQL_DATABASE
#         )
#
#     def get_user_by_email(self, email):
#         """SQL injection vulnerability"""
#         conn = self.connect_mysql()
#         cursor = conn.cursor()
#
#         # Vulnerable query
#         cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")
#         result = cursor.fetchone()
#
#         cursor.close()
#         conn.close()
#         return result
#
#     def update_user_status(self, user_id, status):
#         """Another SQL injection"""
#         conn = self.connect_mysql()
#         cursor = conn.cursor()
#
#         # Using format() - still vulnerable
#         sql = "UPDATE users SET status = '{}' WHERE id = {}".format(status, user_id)
#         cursor.execute(sql)
#         conn.commit()
#
#         cursor.close()
#         conn.close()
#
#
# def search_products(category, price_range):
#     """SQL injection in search function"""
#     conn = mysql.connector.connect(
#         host="localhost",
#         user="admin",
#         password="password123",  # Hardcoded password
#         database="shop"
#     )
#     cursor = conn.cursor()
#
#     # SQL injection vulnerability
#     query = "SELECT * FROM products WHERE category = '" + category + "' AND price < " + price_range
#     cursor.execute(query)
#     results = cursor.fetchall()
#
#     cursor.close()
#     conn.close()
#     return results