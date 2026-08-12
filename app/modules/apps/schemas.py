import uuid

from pydantic import BaseModel


class AppCreate(BaseModel):
    client_id: str
    name: str


class AppRead(BaseModel):
    id: uuid.UUID
    client_id: str
    name: str
    is_active: bool

    model_config = {"from_attributes": True}


class AppCreated(AppRead):
    client_secret: str


class RedirectURICreate(BaseModel):
    redirect_uri: str


class RedirectURIRead(BaseModel):
    id: uuid.UUID
    redirect_uri: str

    model_config = {"from_attributes": True}


class RoleCreate(BaseModel):
    name: str


class RoleRead(BaseModel):
    id: uuid.UUID
    app_id: uuid.UUID
    name: str

    model_config = {"from_attributes": True}


class RoleAssign(BaseModel):
    user_id: uuid.UUID
