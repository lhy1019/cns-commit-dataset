import os
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import base64

# Load the secret key from .env file
load_dotenv()
secret_key = os.getenv("SECRET_KEY").encode()  # Ensure the key is bytes

if len(secret_key) != 32:
    raise ValueError("The secret key must be 32 bytes long.")

# Helper function to pad data
def pad(data):
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

# Helper function to unpad data
def unpad(padded_data):
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

# Function to encrypt data using AES CBC mode
def encrypt(data, key):
    iv = os.urandom(16)  # Generate a random 16-byte IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pad(data.encode())
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data).decode()

# Function to decrypt data using AES CBC mode
def decrypt(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data.encode())
    iv = encrypted_data[:16]
    actual_encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(actual_encrypted_data) + decryptor.finalize()
    return unpad(padded_data).decode()

