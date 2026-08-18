from pydantic import BaseModel, EmailStr, Field


class PasswordLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

    model_config = {
        "json_schema_extra": {
            "example": {"email": "user@example.com", "password": "correct-horse-battery-staple"}
        }
    }


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=1, max_length=255)

    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "user@example.com",
                "password": "correct-horse-battery-staple",
                "full_name": "Jane Doe",
            }
        }
    }


class TokenExchangeRequest(BaseModel):
    code: str
    client_id: str
    client_secret: str
    redirect_uri: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "code": "b3f1c2...",
                "client_id": "riwi-portal",
                "client_secret": "s3cr3t...",
                "redirect_uri": "https://portal.riwi.io/auth/callback",
            }
        }
    }


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int

    model_config = {
        "json_schema_extra": {
            "example": {
                "access_token": "eyJhbGciOiJSUzI1NiIs...",
                "token_type": "Bearer",
                "expires_in": 1800,
            }
        }
    }


class IntrospectRequest(BaseModel):
    token: str
    client_id: str
    client_secret: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "token": "eyJhbGciOiJSUzI1NiIs...",
                "client_id": "riwi-portal",
                "client_secret": "s3cr3t...",
            }
        }
    }


class IntrospectResponse(BaseModel):
    active: bool
    sub: str | None = None
    email: str | None = None
    roles: list[str] | None = None
    exp: int | None = None

    model_config = {
        "json_schema_extra": {
            "example": {
                "active": True,
                "sub": "6a2c18e6-0fc1-49bd-8b0e-d76f42ed4790",
                "email": "user@example.com",
                "roles": ["staff"],
                "exp": 1755043200,
            }
        }
    }
