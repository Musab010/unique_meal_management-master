# encrypt_decrypt.py

import hashlib
from cryptography.fernet import Fernet

def load_key():
    """Laad de eerder gegenereerde sleutel."""
    key = open("data/secret.key", "rb").read()
    return key

def encrypt_data(data: str) -> str:
    """Versleutel data en retourneer als een string."""
    key = load_key()
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data.decode()

def decrypt_data(encrypted_data: str) -> str:
    """Desleutel data van een string."""
    key = load_key()
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data.encode())
    return decrypted_data.decode()

def hash_username(username: str) -> str:
    """Maak een hash van de gebruikersnaam voor consistente opslag."""
    hashed = hashlib.sha256(username.encode()).hexdigest()
    return hashed

def hash_password(password: str) -> str:
    """Maak een hash van het wachtwoord."""
    return hashlib.sha256(password.encode()).hexdigest()
