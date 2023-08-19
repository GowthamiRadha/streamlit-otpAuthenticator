import streamlit as st
import streamlit_authenticator as stauth
import database as db
import yaml
import pandas as pd
from yaml.loader import SafeLoader
import re,time


st.title("OTP Authenticator")
st.sidebar.header("")
st.sidebar.info(
    '''Web Application For OTP Authentication'''
)

def get_authenticator():
    
    with open('.streamlit/config.yaml') as file:
        config = yaml.load(file, Loader=SafeLoader)

    users = db.fetch_all_users()

    credentials = {}
    credentials['usernames'] = {}

    for user in users:
        credentials['usernames'][user['key']] = {}
        credentials['usernames'][user['key']]['email'] = user['key']
        credentials['usernames'][user['key']]['name'] = user['name']
        credentials['usernames'][user['key']]['password'] = user['password']
        
    authenticator = stauth.Authenticate(
                credentials,
                config['cookie']['name'],
                config['cookie']['key'],
                config['cookie']['expiry_days'],
                config['preauthorized']
            )
    
    return authenticator
    

def login(authenticator):
    name, authentication_status, username = authenticator.login("Login","main")
    return username, authentication_status

def is_valid_email(email):
    # A simple regex pattern for validating an email
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email)
    
def main():
    authenticator = get_authenticator()
    username, authentication_status = login(authenticator)

    if authentication_status == None:
        st.warning("Please enter username and password")
    
    if authentication_status == False:
        st.error("Username/Password is incorrect")

    if authentication_status == True:
        role = db.get_user_role(username)
        if role=='Admin':
            menu = ["GetOTP","RegisterSecretKey","AddUser","GetAllUsers","GetAllStudents","DeleteUser","DeleteStudent","UpdateUser","UpdateStudent"]
            choice = st.sidebar.selectbox("Menu",menu)
            if choice=="AddUser":
                st.subheader("Add New User")
                with st.form("userForm", clear_on_submit=True):
                    email = st.text_input("UserName(Email)")
                    name = st.text_input("Name")
                    password = st.text_input("Password",type='password')
                    role = st.selectbox("Role",('User','Admin'))
                    submitted = st.form_submit_button("Register")
                    if submitted:
                        if(is_valid_email(email) is None):
                            st.error('Invalid Email Address')
                        elif name=="" or name is None:
                            st.error("Name cannot be empty")
                        elif len(password)<6:
                            st.error("Password must have atleast 6 characters.")
                        else:
                            details = db.insert_user(email, name, password, role)
                            success_message = st.empty()
                            success_message.success(details)
                            time.sleep(5)
                            success_message.empty()
            elif choice=="UpdateUser":
                st.subheader("Update User")
                with st.form("updateUserForm", clear_on_submit=True):
                    email = st.text_input("UserName(Email)")
                    name = st.text_input("Name")
                    password = st.text_input("Password",type='password')
                    role = st.selectbox("Role",('User','Admin'))
                    submitted = st.form_submit_button("UpdateUser")
                    if submitted:
                        if email is None or email=="":
                            st.error("Email cannot be empty")
                        elif(db.fetch_user_by_email(email) is None):
                            st.error("User with given email does not exist")
                        else:
                            details = db.update_user(email, name, password, role)
                            if details is not None:
                                st.error("Failed to Update User")
                            else:
                                success_message = st.empty()
                                success_message.success("Updated!!")
                                time.sleep(5)
                                success_message.empty()
            elif choice=="UpdateStudent":
                st.subheader("Update Student")
                with st.form("updateStudentForm", clear_on_submit=True):
                    email = st.text_input("Email")
                    student_name = st.text_input("Name of Student")
                    secret_key = st.text_input("SecretKey",type='password')
                    submitted = st.form_submit_button("UpdateStudent")
                    if submitted:
                        if email is None or email=="":
                            st.error("Email cannot be empty")
                        elif(db.fetch_student_by_email(email) is None):
                            st.error("Student with given email does not exist")
                        else:
                            details = db.update_student(email, student_name, secret_key)
                            if details is not None:
                                st.error("Failed to Update Student")
                            else:
                                success_message = st.empty()
                                success_message.success("Updated!!")
                                time.sleep(5)
                                success_message.empty()
            elif choice == "DeleteUser":
                st.subheader("Delete Existing Users")
                with st.form("DeleteUserForm",clear_on_submit=True):
                    email = st.text_input("Enter Email")
                    submitted = st.form_submit_button("DeleteUser")
                    if submitted:
                        status = db.delete_user(email)
                        success_message = st.empty()
                        success_message.success(status)
                        time.sleep(5)
                        success_message.empty()
            elif choice == "DeleteStudent":
                st.subheader("Delete Existing Student")
                with st.form("DeleteStudentForm",clear_on_submit=True):
                    email = st.text_input("Enter Email")
                    submitted = st.form_submit_button("DeleteUser")
                    if submitted:
                        status = db.delete_student(email)
                        success_message = st.empty()
                        success_message.success(status)
                        time.sleep(5)
                        success_message.empty()           
            elif choice == "GetAllUsers":
                users = db.fetch_all_users()
                for entry in users:
                    entry.pop("password")
                df = pd.DataFrame(users)
                df.rename(columns={"key": "Username"}, inplace=True)
                st.title("User Data")
                st.table(df)
            elif choice == "GetAllStudents":
                students = db.fetch_all_students()
                df = pd.DataFrame(students)
                df.rename(columns={"key": "Username"}, inplace=True)
                st.title("Student Data")
                st.table(df)
            elif choice == "GetOTP":
                st.subheader("Get OTP for LogIn")
                with st.form("GetOTPForm",clear_on_submit=True):
                    email = st.text_input("Enter Email")
                    submitted = st.form_submit_button("GetOTP")
                    if submitted:
                        otp = db.get_otp(email)
                        if otp is None:
                            st.error('Invalid Email')
                        else:
                            st.success(f"Successfully Generated OTP for {email}")
                            st.code(otp)
            elif choice == "RegisterSecretKey":
                st.subheader("Register New LogIn Key")
                with st.form("registerKeyForm", clear_on_submit=True):
                    new_user = st.text_input("Email")
                    student_name = st.text_input("Name of Student")
                    secret_key = st.text_input("SecretKey",type='password')
                    submitted = st.form_submit_button("Register")
                    if submitted:
                        if(not is_valid_email(new_user)):
                            st.error('Invalid Email Address')
                        elif student_name=="" or student_name is None:
                            st.error("Name should not be null")
                        elif secret_key=="" or secret_key is None:
                            st.error("Secret Key must be valid")
                        else:
                            details = db.insert_secretKey(new_user,student_name,secret_key)
                            success_message = st.empty()
                            success_message.success(details)
                            time.sleep(5)
                            success_message.empty() 
        else:
            menu = ["GetOTP","RegisterSecretKey"]
            choice = st.sidebar.selectbox("Menu",menu)

            
            if choice == "GetOTP":
                with st.form("GetOTPForm",clear_on_submit=True):
                    st.subheader("Get OTP for LogIn")
                    email = st.text_input("Enter Email")
                    submitted = st.form_submit_button("GetOTP")
                    if submitted:
                        otp = db.get_otp(email)
                        if otp is None:
                            st.error('Invalid Email')
                        else:
                            st.success(f"Successfully Generated OTP for {email}")
                            st.code(otp)
            elif choice == "RegisterSecretKey":
                st.subheader("Register New LogIn Key")
                with st.form("registerKeyForm", clear_on_submit=True):
                    new_user = st.text_input("Email")
                    student_name = st.text_input("Name of Student")
                    secret_key = st.text_input("SecretKey",type='password')
                    submitted = st.form_submit_button("Register")
                    if submitted:
                        if(not is_valid_email(new_user)):
                            st.error('Invalid Email Address')
                        elif student_name=="" or student_name is None:
                            st.error("Name should not be null")
                        elif secret_key=="" or secret_key is None:
                            st.error("Secret Key must be valid")
                        else:
                            details = db.insert_secretKey(new_user,student_name,secret_key)
                            success_message = st.empty()
                            success_message.success(details)
                            time.sleep(5)
                            success_message.empty()

        authenticator.logout("Logout","sidebar")

if __name__ == "__main__":
    main()