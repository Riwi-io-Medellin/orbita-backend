import base64
import uuid
from datetime import datetime, timedelta, UTC

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from jose import JWTError, jwt

from app.config.settings import settings

APP_TOKEN_EXPIRE_MINUTES = 30


def create_access_token(
    user_id: str,
    email: str,
    roles: list[str],
) -> str:

    expire = datetime.now(UTC) + timedelta(
        minutes=settings.jwt_expire_minutes
    )

    payload = {
        "sub": user_id,
        "email": email,
        "roles": roles,
        "exp": expire,
    }

    return jwt.encode(
        payload,
        settings.jwt_private_key,
        algorithm=settings.jwt_algorithm,
        headers={"kid": settings.jwt_kid},
    )

def create_app_token(
    user_id: str,
    email: str,
    name: str,
    client_id: str,
    roles: list[str],
) -> tuple[str, str, datetime]:

    jti = str(uuid.uuid4())
    expire = datetime.now(UTC) + timedelta(
        minutes=APP_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": user_id,
        "email": email,
        "name": name,
        "aud": client_id,
        "roles": roles,
        "jti": jti,
        "exp": expire,
    }

    token = jwt.encode(
        payload,
        settings.jwt_private_key,
        algorithm=settings.jwt_algorithm,
        headers={"kid": settings.jwt_kid},
    )

    return token, jti, expire

def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_public_key,
            algorithms=[settings.jwt_algorithm],
        )

        return payload

    except JWTError:
        return {}

def decode_app_token(token: str, audience: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_public_key,
            algorithms=[settings.jwt_algorithm],
            audience=audience,
        )

        return payload

    except JWTError:
        return {}


def _encode_uint_as_base64url(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(length, byteorder="big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def get_jwks() -> dict:
    public_key = load_pem_public_key(settings.jwt_public_key.encode("utf-8"))
    numbers = public_key.public_numbers()

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": settings.jwt_algorithm,
                "kid": settings.jwt_kid,
                "n": _encode_uint_as_base64url(numbers.n),
                "e": _encode_uint_as_base64url(numbers.e),
            }
        ]
    }
