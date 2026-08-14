from typing import Literal

from pydantic import BaseModel, Field


class SSOExchangeRequest(BaseModel):
    grant_type: Literal["authorization_code"] = "authorization_code"
    code: str = Field(min_length=32, max_length=512)
    client_id: str = Field(min_length=3, max_length=120)
    client_secret: str = Field(min_length=32, max_length=512)
    redirect_uri: str = Field(min_length=1, max_length=2048)


class SSOExchangeResponse(BaseModel):
    user: dict[str, str]
    application: dict[str, str]
    roles: list[str]


class ApplicationCreateRequest(BaseModel):
    slug: str = Field(pattern=r"^[a-z0-9-]+$", min_length=2, max_length=80)
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(min_length=1, max_length=5000)
    url: str = Field(min_length=1, max_length=2048)
    redirect_uri: str = Field(min_length=1, max_length=2048)
    client_id: str = Field(pattern=r"^[a-z0-9-]+$", min_length=3, max_length=120)
    icon: str | None = Field(default=None, max_length=50)


class ApplicationRoleRequest(BaseModel):
    key: str = Field(pattern=r"^[a-z0-9-]+$", min_length=2, max_length=80)
    name: str = Field(min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=5000)


class UserApplicationRoleAssignmentRequest(BaseModel):
    role_keys: list[str] = Field(min_length=1, max_length=20)
