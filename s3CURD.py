import pandas as pd
import boto3
from io import StringIO
import streamlit as st
import streamlit_authenticator as stauth
import pyotp

AWS_ACCESS_KEY_ID = st.secrets["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = st.secrets["AWS_SECRET_ACCESS_KEY"]

# Initialize boto3 client with credentials
s3 = boto3.client('s3', region_name='ap-south-1',aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

# AWS S3 Bucket and file details
BUCKET_NAME = 'otpbucket'
USER_FILE_NAME = 'users.csv'
STUDENT_FILE_NAME = 'students.csv'

# Utility functions to read and write CSV from/to S3
def read_csv_from_s3(bucket, file_name):
    csv_obj = s3.get_object(Bucket=bucket, Key=file_name)
    body = csv_obj['Body'].read().decode('utf-8')
    return pd.read_csv(StringIO(body))

def write_csv_to_s3(df, bucket, file_name):
    csv_buffer = StringIO()
    df.to_csv(csv_buffer, index=False)
    s3.put_object(Body=csv_buffer.getvalue(), Bucket=bucket, Key=file_name)

# User functions
def insert_user(username, name, password, role):
    df = read_csv_from_s3(BUCKET_NAME, USER_FILE_NAME)
    if df[df['key'] == username].shape[0] > 0:
        return "User Already Exists!!"
    passwords = stauth.Hasher([password]).generate()
    new_row = {'key': username, 'name': name, 'password': passwords[0], 'role': role}
    df = df.append(new_row, ignore_index=True)
    write_csv_to_s3(df, BUCKET_NAME, USER_FILE_NAME)
    return "Successfully Added User " + username

def fetch_all_users():
    df = read_csv_from_s3(BUCKET_NAME, USER_FILE_NAME)
    return df.to_dict(orient='records')

def get_user_role(username):
    df = read_csv_from_s3(BUCKET_NAME, USER_FILE_NAME)
    user_row = df[df['key'] == username]
    if user_row.empty:
        return None
    return user_row.iloc[0]['role']

def delete_user(username):
    df = read_csv_from_s3(BUCKET_NAME, USER_FILE_NAME)
    if df[df['key'] == username].empty:
        return "User with given email does not exist"
    df = df[df['key'] != username]
    write_csv_to_s3(df, BUCKET_NAME, USER_FILE_NAME)
    return "User deleted successfully"

def update_user(username, name, password, role):
    df = read_csv_from_s3(BUCKET_NAME, USER_FILE_NAME)
    index = df[df['key'] == username].index
    if not index.empty:
        if name:
            df.loc[index, 'name'] = name
        if password:
            passwords = stauth.Hasher([password]).generate()
            df.loc[index, 'password'] = passwords[0]
        if role:
            df.loc[index, 'role'] = role
        write_csv_to_s3(df, BUCKET_NAME, USER_FILE_NAME)

# Student functions
def fetch_student_by_email(email):
    df = read_csv_from_s3(BUCKET_NAME, STUDENT_FILE_NAME)
    student_row = df[df['key'] == email]
    if student_row.empty:
        return None
    return student_row.iloc[0].to_dict()

def get_otp(email):
    df = read_csv_from_s3(BUCKET_NAME, STUDENT_FILE_NAME)
    student_row = df[df['key'] == email]
    if student_row.empty:
        return None
    secretKey = student_row.iloc[0]['secretKey']
    totp = pyotp.TOTP(secretKey)
    return totp.now()

def insert_secretKey(email, studentName, secretKey):
    df = read_csv_from_s3(BUCKET_NAME, STUDENT_FILE_NAME)
    if not df[df['key'] == email].empty:
        return "SecretKey already registered for " + email
    new_row = {'key': email, 'name': studentName, 'secretKey': secretKey}
    df = df.append(new_row, ignore_index=True)
    write_csv_to_s3(df, BUCKET_NAME, STUDENT_FILE_NAME)
    return "Successfully registered for user " + email

def fetch_all_students():
    df = read_csv_from_s3(BUCKET_NAME, STUDENT_FILE_NAME)
    return df.to_dict(orient='records')

def delete_student(username):
    df = read_csv_from_s3(BUCKET_NAME, STUDENT_FILE_NAME)
    if df[df['key'] == username].empty:
        return "Student with given email does not exist"
    df = df[df['key'] != username]
    write_csv_to_s3(df, BUCKET_NAME, STUDENT_FILE_NAME)
    return "Student deleted successfully"

def update_student(username, name, secretKey):
    df = read_csv_from_s3(BUCKET_NAME, STUDENT_FILE_NAME)
    index = df[df['key'] == username].index
    if not index.empty:
        if name:
            df.loc[index, 'name'] = name
        if secretKey:
            df.loc[index, 'secretKey'] = secretKey
        write_csv_to_s3(df, BUCKET_NAME, STUDENT_FILE_NAME)