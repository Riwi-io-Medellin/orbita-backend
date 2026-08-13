import uuid
from datetime import datetime

from pydantic import BaseModel


class UserAdminRead(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    is_active: bool
    is_platform_admin: bool
    deleted_at: datetime | None
    created_at: datetime

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": "6a2c18e6-0fc1-49bd-8b0e-d76f42ed4790",
                "email": "user@example.com",
                "full_name": "Jane Doe",
                "is_active": True,
                "is_platform_admin": False,
                "deleted_at": None,
                "created_at": "2026-08-13T01:12:34.473413Z",
            }
        },
    }


class UserStatusUpdate(BaseModel):
    is_active: bool

    model_config = {"json_schema_extra": {"example": {"is_active": True}}}


class BulkUserIds(BaseModel):
    user_ids: list[uuid.UUID]

    model_config = {
        "json_schema_extra": {
            "example": {
                "user_ids": [
                    "6a2c18e6-0fc1-49bd-8b0e-d76f42ed4790",
                    "8cd78071-af7a-460b-954b-e58801f13f73",
                ]
            }
        }
    }


class BulkStatusUpdate(BaseModel):
    user_ids: list[uuid.UUID]
    is_active: bool

    model_config = {
        "json_schema_extra": {
            "example": {
                "user_ids": [
                    "6a2c18e6-0fc1-49bd-8b0e-d76f42ed4790",
                    "8cd78071-af7a-460b-954b-e58801f13f73",
                ],
                "is_active": True,
            }
        }
    }
