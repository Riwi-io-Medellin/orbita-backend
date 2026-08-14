from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str
    environment: str
    port: int = 8000

    frontend_url: str

    database_url: str

    @field_validator("database_url", mode="before")
    @classmethod
    def force_async_driver(cls, value: str) -> str:
        if value.startswith("postgres://"):
            return value.replace("postgres://", "postgresql+asyncpg://", 1)
        if value.startswith("postgresql://"):
            return value.replace("postgresql://", "postgresql+asyncpg://", 1)
        return value

    microsoft_client_id: str
    microsoft_client_secret: str
    microsoft_tenant_id: str
    microsoft_redirect_uri: str

    jwt_secret: str
    jwt_algorithm: str
    jwt_expire_minutes: int

    jwt_private_key: str
    jwt_public_key: str
    jwt_kid: str

    platform_admin_emails: str = ""

    @field_validator("jwt_algorithm")
    @classmethod
    def require_rs256(cls, value: str) -> str:
        if value.upper() != "RS256":
            raise ValueError("JWT_ALGORITHM must be RS256")
        return "RS256"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
