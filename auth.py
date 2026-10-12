import hashlib
import os
from config import HASH_FILE, BASE_DIR

def hash_string(value):
    """
    Hash a string using SHA-256 and return its hexadecimal digest.
    """
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

def register_gmail(email):
    """
    Hash the Gmail address and store it locally.
    """
    email_hash = hash_string(email)
    hash_path = os.path.join(BASE_DIR, HASH_FILE)
    
    try:
        with open(hash_path, "w", encoding="utf-8") as f:
            f.write(email_hash)
        return True
    except Exception as e:
        print(f"Error saving hash: {e}")
        return False

def is_gmail_registered():
    """
    Check if a Gmail hash exists.
    """
    hash_path = os.path.join(BASE_DIR, HASH_FILE)
    return os.path.exists(hash_path)

def verify_email(email):
    """
    Verify if the provided email matches the registered hash.
    """
    if not is_gmail_registered():
        return False
        
    hash_path = os.path.join(BASE_DIR, HASH_FILE)
    try:
        with open(hash_path, "r", encoding="utf-8") as f:
            stored_hash = f.read().strip()
            
        return hash_string(email) == stored_hash
    except Exception:
        return False
