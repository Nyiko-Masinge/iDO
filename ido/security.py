import hashlib
import hmac
import secrets

def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 240_000).hex()
    return f"{salt}${digest}"

def password_ok(password, encoded):
    salt, _ = encoded.split("$", 1)
    return hmac.compare_digest(password_hash(password, salt), encoded)
