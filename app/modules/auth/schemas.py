from typing import Literal

from pydantic import BaseModel, EmailStr, Field


class PasswordLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

    model_config = {
        "json_schema_extra": {
            "example": {"email": "user@example.com", "password": "correct-horse-battery-staple"}
        }
    }


class MoodleLoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=256)


class MoodlePasswordResetRequest(BaseModel):
    identifier: str = Field(min_length=1, max_length=255)
    identifier_type: Literal["username", "email"]


class AuthenticationProvidersResponse(BaseModel):
    moodle: bool
    microsoft: bool
    local: bool


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
    code: str = Field(min_length=32, max_length=512)
    client_id: str = Field(min_length=2, max_length=255)
    client_secret: str = Field(min_length=1, max_length=512)
    redirect_uri: str = Field(min_length=8, max_length=2048)

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
    token: str = Field(min_length=32, max_length=8192)
    client_id: str = Field(min_length=2, max_length=255)
    client_secret: str = Field(min_length=1, max_length=512)

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
