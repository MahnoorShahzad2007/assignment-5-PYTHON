import streamlit as st
import hashlib

# Function to hash the password and encrypt the message
def encrypt_message(password, message):
    password_hash = hashlib.sha256(password.encode()).digest()  # Create SHA-256 hash of the password
    encrypted_message = ''.join(chr(ord(c) ^ password_hash[i % len(password_hash)]) for i, c in enumerate(message))  # XOR encryption
    return encrypted_message

# Function to decrypt the message
def decrypt_message(password, encrypted_message):
    password_hash = hashlib.sha256(password.encode()).digest()  # Create SHA-256 hash of the password
    decrypted_message = ''.join(chr(ord(c) ^ password_hash[i % len(password_hash)]) for i, c in enumerate(encrypted_message))  # XOR decryption
    return decrypted_message

# Streamlit UI
st.title("Secure Data Encryption System")

# Input fields for password and message
password = st.text_input("Enter a password for encryption:", type="password")
message = st.text_area("Enter your message to encrypt:")

if password and message:
    try:
        # Encrypt and Decrypt the message
        encrypted_message = encrypt_message(password, message)
        decrypted_message = decrypt_message(password, encrypted_message)

        # Display the results
        st.write(f"Encrypted Message: {encrypted_message}")
        st.write(f"Decrypted Message: {decrypted_message}")
    except Exception as e:
        st.error(f"An error occurred: {e}")
