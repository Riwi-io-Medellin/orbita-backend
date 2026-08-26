import uuid
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator


class AppCreate(BaseModel):
    client_id: str = Field(min_length=2, max_length=255, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    slug: str = Field(min_length=2, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$")
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=500)
    url: str = Field(min_length=8, max_length=2048)
    icon: str | None = Field(default=None, max_length=50)

    @field_validator("url")
    @classmethod
    def validate_launcher_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("url must be an absolute HTTP(S) URL")
        return value

    model_config = {
        "json_schema_extra": {"example": {
            "client_id": "teamlead",
            "slug": "teamlead",
            "name": "TeamLead",
            "description": "Gestiona clases, líderes, clanes y horarios.",
            "url": "https://teamlead-api.example.com/api/auth/orbita/login",
            "icon": "teamlead",
        }}
    }


class AppRead(BaseModel):
    id: uuid.UUID
    application_id: uuid.UUID | None
    client_id: str
    name: str
    is_active: bool

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": "de3008c1-3d48-48a5-b30a-94f395a45306",
                "application_id": "e1e00085-20f0-4650-b4af-67195057c7ae",
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

    @field_validator("redirect_uri")
    @classmethod
    def validate_redirect_uri(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.fragment:
            raise ValueError("redirect_uri must be an absolute HTTP(S) URL without a fragment")
        return value

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
    name: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9][a-z0-9._-]*$")

    model_config = {"json_schema_extra": {"example": {"name": "staff"}}}


class RoleRead(BaseModel):
    id: uuid.UUID
    app_id: uuid.UUID
    name: str
    display_name: str
    description: str | None
    is_active: bool
    managed_by_app: bool

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": "3d338516-48ff-4a01-a607-0501be303935",
                "app_id": "de3008c1-3d48-48a5-b30a-94f395a45306",
                "name": "staff",
                "display_name": "Staff",
                "description": "Personal interno",
                "is_active": True,
                "managed_by_app": True,
            }
        },
    }


class RoleCatalogEntry(BaseModel):
    """An app-owned role declaration. `key` is the exact JWT value consumed by that app."""

    key: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    display_name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=500)

    model_config = {
        "json_schema_extra": {
            "example": {"key": "team_leader", "display_name": "Team Leader", "description": "Gestiona su equipo."}
        }
    }


class RoleCatalogSyncRequest(BaseModel):
    """Confidential client request; absent previously app-managed roles become inactive, never deleted."""

    client_secret: str = Field(min_length=1, max_length=512)
    roles: list[RoleCatalogEntry] = Field(max_length=100)

    @model_validator(mode="after")
    def unique_role_keys(self):
        keys = [role.key for role in self.roles]
        if len(keys) != len(set(keys)):
            raise ValueError("roles must not contain duplicate keys")
        return self

    model_config = {
        "json_schema_extra": {
            "example": {
                "client_secret": "stored-server-side-only",
                "roles": [RoleCatalogEntry.model_config["json_schema_extra"]["example"]],
            }
        }
    }


class RoleCatalogSyncResult(BaseModel):
    roles: list[RoleRead]
    deactivated_role_keys: list[str]

    model_config = {
        "json_schema_extra": {
            "example": {
                "roles": [RoleRead.model_config["json_schema_extra"]["example"]],
                "deactivated_role_keys": ["legacy_role"],
            }
        }
    }


class RoleAssign(BaseModel):
    user_id: uuid.UUID

    model_config = {
        "json_schema_extra": {"example": {"user_id": "6a2c18e6-0fc1-49bd-8b0e-d76f42ed4790"}}
    }


class AppStatusUpdate(BaseModel):
    is_active: bool

    model_config = {"json_schema_extra": {"example": {"is_active": False}}}


class AppRoleRead(BaseModel):
    app_id: uuid.UUID
    client_id: str
    app_name: str
    role_id: uuid.UUID
    role_name: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "app_id": "de3008c1-3d48-48a5-b30a-94f395a45306",
                "client_id": "riwi-portal",
                "app_name": "Riwi Portal",
                "role_id": "3d338516-48ff-4a01-a607-0501be303935",
                "role_name": "staff",
            }
        }
    }


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
