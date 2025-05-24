from cryptography.fernet import Fernet, InvalidToken
import os
import logging

logger = logging.getLogger(__name__)

# Key Management: Load encryption key from environment variable or generate a new one.
# It is critical to keep this key secret and consistent to ensure data can be decrypted.
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')

if not ENCRYPTION_KEY:
    # Generate a new key and print it for the user to set in environment variables
    ENCRYPTION_KEY = Fernet.generate_key().decode()
    print(f"Generated new ENCRYPTION_KEY: {ENCRYPTION_KEY}")
    print("Please set this key in your environment variables for consistent encryption.")

fernet = Fernet(ENCRYPTION_KEY.encode())

def encrypt(data: str) -> str:
    # Encrypt data using Fernet symmetric encryption.
    if data is None:
        return None
    try:
        return fernet.encrypt(data.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise

def decrypt(token: str) -> str:
    # Decrypt data using Fernet symmetric encryption.
    if token is None:
        return None
    try:
        return fernet.decrypt(token.encode()).decode()
    except InvalidToken:
        logger.error("Decryption failed: Invalid encryption token")
        return None
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return None
