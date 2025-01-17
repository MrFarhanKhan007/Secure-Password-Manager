import base64
import hashlib
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import os

load_dotenv()
SECRET_KEY = os.getenv('SECRET_KEY')

# Load key from environment or secure location 
hashed_key = hashlib.sha256(SECRET_KEY.encode('utf-8')).digest()
cipher = Fernet(base64.urlsafe_b64encode(hashed_key))

def encrypt_password(password: str) -> bytes:
    return cipher.encrypt(password.encode())

def decrypt_password(encrypted_password: bytes) -> str:
    return cipher.decrypt(encrypted_password).decode()