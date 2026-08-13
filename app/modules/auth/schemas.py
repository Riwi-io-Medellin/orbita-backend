from pydantic import BaseModel, EmailStr, Field


class PasswordLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=1, max_length=255)


class TokenExchangeRequest(BaseModel):
    code: str
    client_id: str
    client_secret: str
    redirect_uri: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int


class IntrospectRequest(BaseModel):
    token: str
    client_id: str
    client_secret: str


class IntrospectResponse(BaseModel):
    active: bool
    sub: str | None = None
    email: str | None = None
    roles: list[str] | None = None
    exp: int | None = None
