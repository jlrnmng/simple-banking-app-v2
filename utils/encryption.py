from cryptography.fernet import Fernet
import os

# Load encryption key from environment variable or generate a new one
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')

if not ENCRYPTION_KEY:
    # Generate a new key and print it for the user to set in environment variables
    ENCRYPTION_KEY = Fernet.generate_key().decode()
    print(f"Generated new ENCRYPTION_KEY: {ENCRYPTION_KEY}")
    print("Please set this key in your environment variables for consistent encryption.")

fernet = Fernet(ENCRYPTION_KEY.encode())

def encrypt(data: str) -> str:
    if data is None:
        return None
    return fernet.encrypt(data.encode()).decode()

def decrypt(token: str) -> str:
    if token is None:
        return None
    return fernet.decrypt(token.encode()).decode()
