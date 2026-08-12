from pydantic import BaseModel


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
