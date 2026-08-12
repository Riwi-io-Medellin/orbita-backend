from datetime import datetime, timedelta, UTC

from jose import JWTError, jwt

from app.config.settings import settings


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
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )

def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )

        return payload

    except JWTError:
        return {}
