from pydantic import BaseModel


class ErrorDetail(BaseModel):
    """Shape of every error response raised via HTTPException across the API."""

    detail: str

    model_config = {"json_schema_extra": {"example": {"detail": "App not found"}}}
