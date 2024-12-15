import base64
import hashlib
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import os

# Load key from environment or secure location 
SECRET_KEY = "test" 
hashed_key = hashlib.sha256(SECRET_KEY.encode('utf-8')).digest()
cipher = Fernet(base64.urlsafe_b64encode(hashed_key))

def encrypt_password(password: str) -> bytes:
    return cipher.encrypt(password.encode())

def decrypt_password(encrypted_password: bytes) -> str:
    return cipher.decrypt(encrypted_password).decode()

# print(encrypt_password("muah"))
# print(decrypt_password(encrypt_password("muah")))