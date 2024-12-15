from cryptography.fernet import Fernet

# Load key from environment or secure location
key = Fernet.generate_key()
cipher = Fernet(key)

def encrypt_password(password: str) -> bytes:
    return cipher.encrypt(password.encode())

def decrypt_password(encrypted_password: bytes) -> str:
    return cipher.decrypt(encrypted_password).decode()
