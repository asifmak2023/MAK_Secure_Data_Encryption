# 📦 Step 1: Import the needed tools
import streamlit as st
from cryptography.fernet import Fernet
import hashlib

# 🗝️ Step 2: Load or Create the secret key to lock/unlock data
try:
    with open("fernet.key", "rb") as key_file:
        secret_key = key_file.read()
except FileNotFoundError:
    secret_key = Fernet.generate_key()
    with open("fernet.key", "wb") as key_file:
        key_file.write(secret_key)

# 🔐 Step 3: Make a magic box (cipher) with the secret key
cipher = Fernet(secret_key)

# 🧠 Step 4: Make a memory to keep things while app is running
if 'memory' not in st.session_state:
    st.session_state.memory = {}

memory = st.session_state.memory
  # This is like a toy box to store secrets

# 🧙 Step 5: Make the magic spells (functions)
def lock_data(text):
    return cipher.encrypt(text.encode()).decode()

def unlock_data(secret):
    return cipher.decrypt(secret.encode()).decode()

def make_hash(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# 🎨 Step 6: Make the Streamlit app pretty
st.title("🔐 MAK-Secure Data Encryption System")

menu = ["Lock a Secret", "Unlock a Secret"]
choice = st.sidebar.selectbox("Choose what to do:", menu)

# 🧩 Step 7: Lock a secret
if choice == "Lock a Secret":
    st.header("🔏 Lock Your Secret")
    user = st.text_input("Your Name")
    secret = st.text_area("What is your secret?")
    key = st.text_input("Make a password to protect it", type="password")
    
    if st.button("Lock it!"):
        if user and secret and key:
            locked = lock_data(secret)
            hashed_key = make_hash(key)
            memory[user] = {"locked": locked, "key": hashed_key, "tries": 0}
            st.success("🎉 Your secret is safe!")
        else:
            st.error("Oops! Please fill all the boxes.")

# 🧩 Step 8: Unlock a secret
elif choice == "Unlock a Secret":
    st.header("🔓 Unlock Your Secret")
    user = st.text_input("Your Name")
    key = st.text_input("Type your password", type="password")

    if st.button("Unlock it!"):
        if user in memory:
            saved = memory[user]

            if saved["tries"] >= 3:
                st.error("🚫 Too many wrong tries! Try later.")
            elif make_hash(key) == saved["key"]:
                real_secret = unlock_data(saved["locked"])
                st.success(f"Here is your secret: {real_secret}")
                saved["tries"] = 0
            else:
                saved["tries"] += 1
                st.error("❌ Wrong password!")
        else:
            st.error("We don’t know you yet! Try locking something first.")
