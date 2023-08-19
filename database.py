from deta import Deta
import time
import streamlit as st
import streamlit_authenticator as stauth
import pyotp

#load deta key from secrets
DETA_KEY = st.secrets["db_key"]

deta = Deta(DETA_KEY)
user_db = deta.Base('users_db')
student_db = deta.Base('student_db')

def insert_user(username, name, password,role):
    if get_specific_details(user_db,username):
        return "User Already Exists!!"
    passwords = stauth.Hasher([password]).generate()
    user_db.put({
        "key": username,
        "name": name,
        "password": passwords[0],
        "role": role
    })
    return "Successfully Added User "+username

def fetch_all_users():
    return fetch_all_details(user_db)

def get_user_role(username):
    details = get_specific_details(user_db,username)
    if details is None:
        return None
    return details.get("role")

def delete_user(username):
    if fetch_user_by_email(username) is None:
        return "User with given email does not exist"
    return user_db.delete(username)

def update_user(username, name, password, role):
    """ Updates the user with the given username with the given updates."""
    update_data = dict()
    if(name):
        update_data['name'] = name
    if(password):
        passwords = stauth.Hasher([password]).generate()
        update_data['password'] = passwords[0]
    if(role):
        update_data['role'] = role
    user_db.update(update_data, username)

def fetch_user_by_email(email):
    return get_specific_details(user_db,email)

def get_specific_details(db,username):
    res = db.get(username)
    return res

def fetch_all_details(db):
    max_retries = 5
    delay = 1  # seconds
    for i in range(max_retries):
        try:
            res = db.fetch()
            return res.items
        except Exception as e:
            print(f"Error fetching users: {e}")
            if i < max_retries - 1:
                print(f"Retrying in {delay} seconds...")
                time.sleep(delay)
    print("Failed to fetch details after multiple attempts")
    return []   

def fetch_student_by_email(email):
    return get_specific_details(student_db,email)

def get_otp(email):
     details = get_specific_details(student_db,email)
     if details is None:
          return None
     totp = pyotp.TOTP(details.get("secretKey"))
     otp = totp.now()
     return otp

def insert_secretKey(email,studentName,secretKey):
     if fetch_student_by_email(email) is not None:
          return "SecretKey already registered for "+email
     else:
        student_db.put({
        "key": email,
        "name": studentName,
        "secretKey": secretKey
        })
        return "Successfully registered for user "+email

def fetch_all_students():
    return fetch_all_details(student_db)

def delete_student(username):
    if fetch_student_by_email(username) is None:
        return "Student with given email does not exist"
    return student_db.delete(username)


def update_student(username, name, secretKey):
    """ Updates the user with the given username with the given updates."""
    update_data = dict()
    if(name):
        update_data['name'] = name
    if(secretKey):
        update_data['secretKey'] = secretKey
    student_db.update(update_data, username)