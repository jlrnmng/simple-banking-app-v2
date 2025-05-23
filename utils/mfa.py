import pyotp
import base64

def generate_totp_secret():
    return pyotp.random_base32()

def get_totp_uri(secret, username, issuer_name="SimpleBankingApp"):
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer_name)

def verify_totp(token, secret):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)
