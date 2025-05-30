# MAK_Secure_Data_Encryption
🔐 Secure Data Encryption App (Streamlit + Python)

Welcome to the Secret Keeper App — a simple and fun Streamlit app that lets you lock and unlock secrets using encryption! 🔒✨

This project is based on the assignment from Panaverse.

🚀 Features

🔏 Encrypt (lock) a message with a password.

🔓 Decrypt (unlock) the message using the correct password.

🧠 Smart memory using Streamlit's session state.

🛡️ Passwords are hashed securely — not saved in plain text.

📁 Project Structure

secure_data_encryption_app/
├── app.py           # Main Streamlit application
├── fernet.key       # Secret key file for encryption
├── README.md        # This file

🛠️ How to Run

Install Python Libraries

pip install streamlit cryptography

Run the App

streamlit run app.py

📦 Libraries Used & Their Purpose

1. streamlit

Used to build the interactive web app UI easily.

st.title() – Makes a large title at the top.

st.text_input() – Lets the user type in small text boxes.

st.text_area() – A bigger box for writing secrets.

st.button() – Adds a button for actions like locking/unlocking.

st.sidebar.selectbox() – Adds a dropdown menu in the sidebar.

st.session_state – Remembers things like secrets during your session.

st.success(), st.error() – Show colorful feedback messages.

2. cryptography.fernet

Part of the cryptography library that handles encryption and decryption securely.

Fernet.generate_key() – Creates a new random key for encryption.

Fernet(key).encrypt(data) – Encrypts (locks) a message.

Fernet(key).decrypt(token) – Decrypts (unlocks) the encrypted message.

3. hashlib

Used for turning passwords into safe, one-way hash codes.

hashlib.sha256(passkey.encode()).hexdigest() – Hashes a password using SHA-256.

🧙 Function Definitions (Explained Simply)

lock_data(text)

def lock_data(text):
    return cipher.encrypt(text.encode()).decode()

🔐 Encrypts a plain message so it looks like gibberish. Only someone with the right key can decrypt it.

unlock_data(secret)

def unlock_data(secret):
    return cipher.decrypt(secret.encode()).decode()

🔓 Decrypts the encrypted gibberish and gives you the original message.

make_hash(passkey)

def make_hash(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

🔍 Turns a password into a one-way code that’s safe to store. Even we can’t see the real password!

🧠 How It Works (In Simple Words)

You write a secret and set a password.

The app locks your secret and saves it in memory.

The password is turned into a hash (a one-way secret code).

Later, you can type your name and password to unlock the secret.

If your password is right, the app shows the message!

🧒 For Kids or Beginners

Everything is explained with emojis and friendly names 🎨

You don’t need to know hard words like "encryption" or "hashing"

Just think: You put your secret in a box, lock it, and only you can open it!

🛡️ Security Note

This app is for learning and fun. Don’t use it for real-life secrets or passwords, since it uses in-memory storage only and has no database or long-term saving.

📷 Visual Learning

  

📬 Feedback or Questions?

Feel free to open an issue or suggest improvements! 😊

Happy encrypting! 🔐🎉