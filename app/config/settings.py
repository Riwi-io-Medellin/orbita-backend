from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str
    environment: str

    frontend_url: str

    database_url: str

    microsoft_client_id: str
    microsoft_client_secret: str
    microsoft_tenant_id: str
    microsoft_redirect_uri: str

    jwt_secret: str
    jwt_algorithm: str
    jwt_expire_minutes: int

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()