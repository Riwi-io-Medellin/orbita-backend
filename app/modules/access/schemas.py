import uuid
from datetime import datetime

from pydantic import BaseModel


class ApplicationCreate(BaseModel):
    slug: str
    name: str
    description: str
    url: str
    icon: str | None = None

    model_config = {
        "json_schema_extra": {
            "example": {
                "slug": "riwi-portal",
                "name": "Riwi Portal",
                "description": "Main student/staff portal.",
                "url": "https://portal.riwi.io",
                "icon": "portal",
            }
        }
    }


class ApplicationRead(BaseModel):
    id: uuid.UUID
    slug: str
    name: str
    description: str
    url: str
    icon: str | None
    is_active: bool

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": "e1e00085-20f0-4650-b4af-67195057c7ae",
                "slug": "riwi-portal",
                "name": "Riwi Portal",
                "description": "Main student/staff portal.",
                "url": "https://portal.riwi.io",
                "icon": "portal",
                "is_active": True,
            }
        },
    }


class ApplicationStatusUpdate(BaseModel):
    is_active: bool

    model_config = {"json_schema_extra": {"example": {"is_active": False}}}


class GlobalRoleRead(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": "ad9633ac-9f3f-4a9f-9aeb-6e9dbe225fe1",
                "name": "staff",
                "description": "Personal interno de Riwi",
            }
        },
    }


class AuthorizedApplicationRead(BaseModel):
    """Shape of one entry in the launcher list a user is authorized to see."""

    id: str
    slug: str
    name: str
    description: str
    url: str
    icon: str | None

    model_config = {
        "json_schema_extra": {
            "example": {
                "id": "e1e00085-20f0-4650-b4af-67195057c7ae",
                "slug": "riwi-portal",
                "name": "Riwi Portal",
                "description": "Main student/staff portal.",
                "url": "https://portal.riwi.io",
                "icon": "portal",
            }
        }
    }


class AuditLogRead(BaseModel):
    """Shape of one audit log row, with actor/application already resolved to display names."""

    id: str
    event: str
    user_name: str | None
    user_email: str | None
    application_name: str | None
    ip_address: str | None
    details: dict
    created_at: datetime

    model_config = {
        "json_schema_extra": {
            "example": {
                "id": "1c71ad16-f1d6-4bc3-a4d3-05118a99a829",
                "event": "login",
                "user_name": "Jane Doe",
                "user_email": "user@example.com",
                "application_name": None,
                "ip_address": "127.0.0.1",
                "details": {},
                "created_at": "2026-08-13T01:12:47.995520+00:00",
            }
        }
    }
