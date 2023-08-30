import mysql.connector
import time
import streamlit as st
import streamlit_authenticator as stauth
import pyotp

# Load RDS information from secrets
RDS_HOST = st.secrets["rds_host"]
RDS_PORT = st.secrets["rds_port"]
RDS_USER = st.secrets["rds_user"]
RDS_PASSWORD = st.secrets["rds_password"]
RDS_DB = st.secrets["rds_db"]

def connect_to_db():
    return mysql.connector.connect(user=RDS_USER, password=RDS_PASSWORD,
                                   host=RDS_HOST, database=RDS_DB,
                                   autocommit=True)
def ensure_table_exists():
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users_db (username VARCHAR(255) PRIMARY KEY, name VARCHAR(255), password VARCHAR(255), role VARCHAR(50))")
    cursor.execute("CREATE TABLE IF NOT EXISTS student_db (username VARCHAR(255) PRIMARY KEY, name VARCHAR(255), secretKey VARCHAR(255))")
    conn.close()

def insert_user(username, name, password, role):
    ensure_table_exists()
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users_db WHERE username = %s", (username,))
    if cursor.fetchone():
        conn.close()
        return "User Already Exists!!"

    hashed_passwords = stauth.Hasher([password]).generate()
    cursor.execute("INSERT INTO users_db (username, name, password, role) VALUES (%s, %s, %s, %s)", (username, name, hashed_passwords[0], role))
    conn.close()
    return f"Successfully Added User {username}"

def fetch_all_users():
    ensure_table_exists()
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users_db")
    column_names = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()
    result = [dict(zip(column_names, row)) for row in rows]
    conn.close()
    return result

def get_user_role(username):
    user_details = fetch_user_by_email(username)
    return user_details.get("role") if user_details else None
    # ensure_table_exists()
    # conn = connect_to_db()
    # cursor = conn.cursor()
    # cursor.execute("SELECT role FROM users_db WHERE username = %s", (username,))
    # result = cursor.fetchone()
    # conn.close()
    # return result[0] if result else None

def delete_user(username):
    ensure_table_exists()
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users_db WHERE username = %s", (username,))
    conn.close()
    return "User deleted successfully"

def update_user(username, name, password, role):
    ensure_table_exists()
    conn = connect_to_db()
    cursor = conn.cursor()
    updates = []
    params = []
    if name:
        updates.append("name = %s")
        params.append(name)
    if password:
        hashed_password = stauth.Hasher([password]).generate()[0]
        updates.append("password = %s")
        params.append(hashed_password)
    if role:
        updates.append("role = %s")
        params.append(role)
    
    params.append(username)
    query = f"UPDATE users_db SET {', '.join(updates)} WHERE username = %s"
    cursor.execute(query, params)
    conn.close()

def fetch_user_by_email(email):
    ensure_table_exists()
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users_db WHERE username = %s", (email,))
    column_names = [desc[0] for desc in cursor.description]
    row = cursor.fetchone()
    result = dict(zip(column_names, row)) if row else None
    conn.close()
    return result

def get_specific_details(db, username):
    ensure_table_exists()
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {db} WHERE username = %s", (username,))
    result = cursor.fetchone()
    conn.close()
    return result

def fetch_student_by_email(email):
    ensure_table_exists()
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM student_db WHERE username = %s", (email,))
    column_names = [desc[0] for desc in cursor.description]
    row = cursor.fetchone()
    result = dict(zip(column_names, row)) if row else None
    conn.close()
    return result

def get_otp(email):
    student = get_specific_details("student_db", email)
    if not student:
        return None
    secret_key = student[2]  # Assuming secretKey is the third field
    totp = pyotp.TOTP(secret_key)
    return totp.now()

def insert_secretKey(email, studentName, secretKey):
    ensure_table_exists()
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM student_db WHERE username = %s", (email,))
    if cursor.fetchone():
        conn.close()
        return f"SecretKey already registered for {email}"

    cursor.execute("INSERT INTO student_db (username, name, secretKey) VALUES (%s, %s, %s)", (email, studentName, secretKey))
    conn.close()
    return f"Successfully registered for user {email}"

def fetch_all_students():
    ensure_table_exists()
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM student_db")
    column_names = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()
    result = [dict(zip(column_names, row)) for row in rows]
    conn.close()
    return result

def delete_student(username):
    ensure_table_exists()
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM student_db WHERE username = %s", (username,))
    conn.close()
    return "Student deleted successfully"

def update_student(username, name, secretKey):
    ensure_table_exists()
    conn = connect_to_db()
    cursor = conn.cursor()
    updates = []
    params = []
    if name:
        updates.append("name = %s")
        params.append(name)
    if secretKey:
        updates.append("secretKey = %s")
        params.append(secretKey)
    
    params.append(username)
    query = f"UPDATE student_db SET {', '.join(updates)} WHERE username = %s"
    cursor.execute(query, params)
    conn.close()