import pyotp
import base64

# Multi-Factor Authentication (MFA) Utilities
# These functions support Time-based One-Time Password (TOTP) generation and verification.

def generate_totp_secret():
    # Generate a random base32 secret for TOTP
    return pyotp.random_base32()

def get_totp_uri(secret, username, issuer_name="SimpleBankingApp"):
    # Generate a provisioning URI for use with authenticator apps (e.g., Google Authenticator)
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer_name)

def verify_totp(token, secret):
    # Verify a TOTP token against the secret
    totp = pyotp.TOTP(secret)
    return totp.verify(token)
