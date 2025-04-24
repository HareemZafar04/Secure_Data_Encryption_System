import streamlit as st
import hashlib
import time
from cryptography.fernet import Fernet

# --- Encryption Setup ---
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# --- In-Memory Storage ---
stored_data = {}  # { "encrypted_text": { "encrypted_text": ..., "passkey": ... } }
failed_attempts = st.session_state.get("failed_attempts", 0)
authenticated = st.session_state.get("authenticated", False)

# --- Utility Functions ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    for key, value in stored_data.items():
        if key == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# --- Streamlit UI ---
st.set_page_config(page_title="Secure Data Vault", page_icon="🛡️")
st.title("🛡️ Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# --- Pages ---
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("This app securely **stores** and **retrieves** your data using a **passkey** and **encryption**.")
    st.info("🔐 3 failed attempts will require reauthorization via Login.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data encrypted and stored securely!")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ Please fill in all fields.")

elif choice == "Retrieve Data":
    if st.session_state.get("failed_attempts", 0) >= 3 and not st.session_state.get("authenticated", False):
        st.warning("🔒 Too many failed attempts! Please login again.")
        st.stop()

    st.subheader("🔍 Retrieve Encrypted Data")
    encrypted_text = st.text_area("Paste Encrypted Text:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success("✅ Data Decrypted Successfully!")
                st.code(result, language="text")
            else:
                remaining = 3 - st.session_state.get("failed_attempts", 0)
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🚫 Too many failed attempts! Please login again.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required.")

elif choice == "Login":
    st.subheader("🔑 Reauthorize")
    login_pass = st.text_input("Enter Admin Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.authenticated = True
            st.success("✅ Reauthorized! Redirecting...")
            time.sleep(2)
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password.")
