from functools import lru_cache

from urllib.parse import urlparse

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str
    environment: str
    port: int = 8000

    frontend_url: str
    frontend_origins: str = ""
    public_base_url: str = ""

    database_url: str

    @field_validator("database_url", mode="before")
    @classmethod
    def force_async_driver(cls, value: str) -> str:
        if value.startswith("postgres://"):
            return value.replace("postgres://", "postgresql+asyncpg://", 1)
        if value.startswith("postgresql://"):
            return value.replace("postgresql://", "postgresql+asyncpg://", 1)
        return value

    # Microsoft remains disabled until Riwi supplies its institutional tenant UUID.
    # Keeping these optional lets Moodle/local login operate safely during that period.
    microsoft_client_id: str = ""
    microsoft_client_secret: str = ""
    microsoft_tenant_id: str = ""
    microsoft_redirect_uri: str = ""
    enable_microsoft_login: bool = False

    moodle_base_url: str = ""
    moodle_service: str = ""
    moodle_timeout_seconds: float = 10.0
    enable_local_login: bool = True
    allowed_identity_email_domains: str = "riwi.io"
    allow_moodle_noninstitutional_email_linking: bool = True
    moodle_login_pair_limit: int = 5
    moodle_login_ip_limit: int = 30
    moodle_login_window_minutes: int = 15

    jwt_secret: str
    jwt_algorithm: str
    jwt_expire_minutes: int

    jwt_private_key: str
    jwt_public_key: str
    jwt_kid: str

    session_secret: str = ""
    csrf_secret: str = ""
    rate_limit_secret: str = ""
    sql_echo: bool = False

    platform_admin_emails: str = ""

    @field_validator("jwt_algorithm")
    @classmethod
    def require_rs256(cls, value: str) -> str:
        if value.upper() != "RS256":
            raise ValueError("JWT_ALGORITHM must be RS256")
        return "RS256"

    @field_validator("moodle_base_url")
    @classmethod
    def normalize_moodle_base_url(cls, value: str) -> str:
        return value.strip().rstrip("/")

    @field_validator("public_base_url")
    @classmethod
    def normalize_public_base_url(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        if not value:
            return value
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"}:
            raise ValueError("PUBLIC_BASE_URL must be an absolute origin without a path")
        return value

    @model_validator(mode="after")
    def require_production_security_settings(self):
        if self.environment == "production":
            if not self.public_base_url.startswith("https://"):
                raise ValueError("PUBLIC_BASE_URL must use HTTPS in production")
            if not self.session_secret or not self.csrf_secret or not self.rate_limit_secret:
                raise ValueError("SESSION_SECRET, CSRF_SECRET and RATE_LIMIT_SECRET are required in production")
        return self

    def identity_email_domains(self) -> set[str]:
        return {
            domain.strip().lower()
            for domain in self.allowed_identity_email_domains.split(",")
            if domain.strip()
        }

    def allowed_frontend_origins(self) -> set[str]:
        configured = self.frontend_origins or self.frontend_url
        origins = {origin.strip().rstrip("/") for origin in configured.split(",") if origin.strip()}
        if self.environment == "development":
            origins.update({"http://localhost:5173", "http://127.0.0.1:5173"})
        return origins

    @property
    def resolved_public_base_url(self) -> str:
        return self.public_base_url or f"http://localhost:{self.port}"

    @property
    def session_signing_secret(self) -> str:
        return self.session_secret or self.jwt_secret

    @property
    def csrf_signing_secret(self) -> str:
        return self.csrf_secret or self.jwt_secret

    @property
    def rate_limit_signing_secret(self) -> str:
        return self.rate_limit_secret or self.jwt_secret

    @property
    def access_cookie_name(self) -> str:
        return "__Host-orbita_access" if self.environment == "production" else "access_token"

    @property
    def pending_session_cookie_name(self) -> str:
        return "__Host-orbita_pending" if self.environment == "production" else "orbita_pending"

    @property
    def access_cookie_samesite(self) -> str:
        return "none" if self.environment == "production" else "lax"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
