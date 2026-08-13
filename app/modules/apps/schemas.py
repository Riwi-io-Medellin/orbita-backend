import uuid

from pydantic import BaseModel


class AppCreate(BaseModel):
    client_id: str
    name: str

    model_config = {
        "json_schema_extra": {"example": {"client_id": "riwi-portal", "name": "Riwi Portal"}}
    }


class AppRead(BaseModel):
    id: uuid.UUID
    client_id: str
    name: str
    is_active: bool

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": "de3008c1-3d48-48a5-b30a-94f395a45306",
                "client_id": "riwi-portal",
                "name": "Riwi Portal",
                "is_active": True,
            }
        },
    }


class AppCreated(AppRead):
    client_secret: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": "de3008c1-3d48-48a5-b30a-94f395a45306",
                "client_id": "riwi-portal",
                "name": "Riwi Portal",
                "is_active": True,
                "client_secret": "qdSXwvjgp4oNIZ48VuflondERbMr9FheE_i_CagOaUs",
            }
        },
    }


class RedirectURICreate(BaseModel):
    redirect_uri: str

    model_config = {
        "json_schema_extra": {"example": {"redirect_uri": "https://portal.riwi.io/auth/callback"}}
    }


class RedirectURIRead(BaseModel):
    id: uuid.UUID
    redirect_uri: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": "b1e2c3d4-5678-49bd-8b0e-d76f42ed4790",
                "redirect_uri": "https://portal.riwi.io/auth/callback",
            }
        },
    }


class RoleCreate(BaseModel):
    name: str

    model_config = {"json_schema_extra": {"example": {"name": "staff"}}}


class RoleRead(BaseModel):
    id: uuid.UUID
    app_id: uuid.UUID
    name: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": "3d338516-48ff-4a01-a607-0501be303935",
                "app_id": "de3008c1-3d48-48a5-b30a-94f395a45306",
                "name": "staff",
            }
        },
    }


class RoleAssign(BaseModel):
    user_id: uuid.UUID

    model_config = {
        "json_schema_extra": {"example": {"user_id": "6a2c18e6-0fc1-49bd-8b0e-d76f42ed4790"}}
    }


class AppStatusUpdate(BaseModel):
    is_active: bool

    model_config = {"json_schema_extra": {"example": {"is_active": False}}}


class UserAppRoleRead(BaseModel):
    user_id: uuid.UUID
    email: str
    full_name: str
    role_name: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "user_id": "6a2c18e6-0fc1-49bd-8b0e-d76f42ed4790",
                "email": "user@example.com",
                "full_name": "Jane Doe",
                "role_name": "staff",
            }
        }
    }
