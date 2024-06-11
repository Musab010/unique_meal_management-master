# utils.py
import hashlib

def hash_password(password):
    """Maak een hash van het wachtwoord."""
    return hashlib.sha256(password.encode()).hexdigest()
