import base64
import hashlib
import hmac
import os

ITERATIONS = 600_000


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, encoded: str | None) -> bool:
    if not encoded:
        return False
    try:
        algorithm, iterations, salt, digest = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        expected = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt), int(iterations))
        return hmac.compare_digest(expected, base64.b64decode(digest))
    except (ValueError, TypeError):
        return False
