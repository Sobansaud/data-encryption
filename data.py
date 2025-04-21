# import streamlit as st
# import hashlib
# import json
# import os
# import time 
# from cryptography.fernet import Fernet
# from base64 import urlsafe_b64decode
# from hashlib import pbkdf2_hmac

# # DATA IINFORMATION FROM USER

# DATA_FILE = "secure_data.json"
# SALT = b"secure_salt_value"
# LOCKOUT_DURATION = 60  # 1 minute



# # SECTION LOGIN DETAILS

# if "authenticated_user" not in st.session_state:
#     st.session_state.authenticated_user = None

# if "failed_attempt" not in st.session_state:
#     st.session_state.failed_attempt = 0

# if "lockout_time" not in st.session_state:
#     st.session_state.lockout_time = 0

# # IF DATA IS LOAD

# def load_data():
#     if os.path.exists(DATA_FILE):
#         with open(DATA_FILE, "r") as f:
#             return json.load(f)
#         return {}
    
# def save_data(data):
#     with open(DATA_FILE, "w") as f:
#         json.dump(data,f)

# def generate_key(passkey):
#     key = pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000)
#     return urlsafe_b64decode(key)

# def hash_password(password):
#     return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000)

# # CRYPTOGRAPHY FERNET IS USED

# def encrypt_text(text,key):
#     cipher = Fernet(generate_key(key))
#     return cipher.encrypt(text.encode()).decode()


# def decrypt_text(encrypt_text, key):
#     try:
#         cipher = Fernet(generate_key(key))
#         return cipher.decrypt(encrypt_text.encode()).decode()
#     except:
#         return None
    
# stored_data =- load_data()
# # NAVIGATION BAR

# st.title("🔐 SECURE DATA ENCRYPTION SYSTEM ")
# menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
# choice = st.sidebar.selectbox("Navigation", menu)

# if choice == "Home":
#     st.title("Welcome to 🔏 Secure Data Encryption System")
#     st.write("Develop a Streamlit-based secure data storage and retrieval system where:Users store data with a unique passkey.Users decrypt data by providing the correct passkey.Multiple failed attempts result in a forced reauthorization (login page).The system operates entirely in memory without external databases.")

# elif choice == "Register":
#     st.title("🖋 ️ Register")
#     username = st.text_input("Username")
#     password = st.text_input("Password", type="password")
#     confirm_password = st.text_input("Confirm Password", type="password")
#     if st.button("Register"):
#         if username and password:
#             if username in stored_data:
#                 st.warning(" ⚠ ️ Username already exists")
#             else:
#                 stored_data[username] = {
#                     "password": hash_password(password),
#                     "data": {}
#                 }
#                 save_data(stored_data)
#                 st.success("Registration successful")
#         else:
#             st.error("Please fill in all fields")
#     elif choice == "Login":
#         st.title("🔒 Login")

#         if time.time() < st.session_state.lockout_time:
#             remaining = int(st.session_state.lockout_time - time.time())
#             st.write(f" ⏲ Account locked for {remaining} seconds")
#             st.stop()

#             username = st.text_input("Username")
#             password = st.text_input("Password", type="password")
#             if st.button("Login"):
#                 if username in stored_data and stored_data[username]["password"] == hash_password(password):
#                     st.session_state.authenticated_user = username
#                     st.session_state.failed_attempts = 0
#                     st.success("👋 Welcome , " + username)
#                     st.write("You are now logged in")
#                 else:
#                     st.session_state.failed_attempts += 1
#                     remaining = 3 - st.session_state.failed_attempts
#                     st.error(f"❌ Invalid username or password. {remaining} attempts remaining")

#                     if st.session_state.failed_attempts >= 3:
#                         st.session_state.lockout_time = time.time() + 60
#                         st.write("Account locked for 60 seconds")
#                         st.stop()

# elif choice == "Store Data":
#     if not st.session_state.authenticated_user:
#         st.error("You must be logged in to store data")
#     else:
#         st.subheader("🏪 ️ Store Data")
#         data = st.text_area("Enter data to encrypt")
#         passkey = st.text_input("Encryption key {passphrase}", type="password")
#         if st.button("Encrypt and Store"):
#             if data and passkey:
#                 encrypted = encrypt_text(data, passkey)
#                 stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
#                 save_data(stored_data)
#                 st.success( " ✅ Data encrypt and stored successfully")

#             else:
#                 st.error("Please fill in all fields")
    

# elif choice == "Retrieve Data":
#     if not st.session_state.authenticated_user:
#         st.error("You must be logged in to retrieve data")
#     else:
#         st.subheader("📁 ️ Retrieve Data")
#         user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

#         if not user_data:
#             st.info("No data found")
#         else:
#             st.write("Your encrypted data:")
#             for i, item in enumerate(user_data):
#                 st.code(item,language="text")
            
#             encrypted_input = st.text_area("Enter encrypted data to decrypt")
#             passkey = st.text_input("Encryption key {passphrase}", type="password")

#             if st.button("Decrypt and Display"):
#                 result = decrypt_text(encrypted_input, passkey)
#                 if result:
#                     st.success(f" ✅ Decrypted data: {result}")
#                 else:
#                     st.error("❌ Invalid encryption key or encrypted data")


            


import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# === Constants ===
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"  # Keep this secret & consistent across sessions
LOCKOUT_DURATION = 60  # in seconds

# === Session State Initialization ===
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# === Utility Functions ===

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    # Derive a key using PBKDF2
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# === Load stored data from JSON ===
stored_data = load_data()

# === Navigation ===
st.title("🔐 Secure Multi-User Data System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

# === Home ===
if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.markdown("Securely store & retrieve your data with encryption. Each user has their own protected data.")

# === Register ===
elif choice == "Register":
    st.subheader("📝 Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ Username already exists.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ User registered successfully!")
        else:
            st.error("Both fields are required.")

# === Login ===
elif choice == "Login":
    st.subheader("🔑 User Login")
    
    # Lockout check
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Too many failed attempts. Please wait {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials! Attempts left: {remaining}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🔒 Too many failed attempts. Locked for 60 seconds.")
                st.stop()

# === Store Data ===
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login first.")
    else:
        st.subheader("📦 Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption Key (passphrase)", type="password")

        if st.button("Encrypt & Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and saved!")
            else:
                st.error("All fields are required.")

# === Retrieve Data ===
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login first.")
    else:
        st.subheader("🔎 Retrieve Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No data found.")
        else:
            st.write("🔐 Encrypted Data Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

            encrypted_input = st.text_area("Enter Encrypted Text")
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"✅ Decrypted: {result}")
                else:
                    st.error("❌ Incorrect passkey or corrupted data.")
