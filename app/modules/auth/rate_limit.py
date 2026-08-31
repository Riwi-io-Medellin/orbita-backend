import hashlib
import hmac
from datetime import UTC, datetime, timedelta

from fastapi import Request
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.settings import Settings
from app.modules.identity.models import MoodleLoginFailure


class MoodleRateLimitedError(Exception):
    pass


def _hash_value(value: str, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


class MoodleLoginRateLimiter:
    @staticmethod
    def _keys(settings: Settings, username: str, request: Request) -> tuple[str, str]:
        ip_address = request.client.host if request.client else "unknown"
        return (
            _hash_value(username.strip().lower(), settings.jwt_secret),
            _hash_value(ip_address, settings.jwt_secret),
        )

    @staticmethod
    async def ensure_allowed(db: AsyncSession, settings: Settings, username: str, request: Request) -> None:
        subject_hash, ip_hash = MoodleLoginRateLimiter._keys(settings, username, request)
        cutoff = datetime.now(UTC) - timedelta(minutes=settings.moodle_login_window_minutes)
        await db.execute(delete(MoodleLoginFailure).where(MoodleLoginFailure.failed_at < cutoff))
        pair_failures = await db.scalar(
            select(func.count()).select_from(MoodleLoginFailure).where(
                MoodleLoginFailure.subject_hash == subject_hash,
                MoodleLoginFailure.ip_hash == ip_hash,
                MoodleLoginFailure.failed_at >= cutoff,
            )
        )
        ip_failures = await db.scalar(
            select(func.count()).select_from(MoodleLoginFailure).where(
                MoodleLoginFailure.ip_hash == ip_hash,
                MoodleLoginFailure.failed_at >= cutoff,
            )
        )
        await db.commit()
        if pair_failures >= settings.moodle_login_pair_limit or ip_failures >= settings.moodle_login_ip_limit:
            raise MoodleRateLimitedError()

    @staticmethod
    async def record_failure(db: AsyncSession, settings: Settings, username: str, request: Request) -> None:
        subject_hash, ip_hash = MoodleLoginRateLimiter._keys(settings, username, request)
        db.add(MoodleLoginFailure(subject_hash=subject_hash, ip_hash=ip_hash))
        await db.commit()

    @staticmethod
    async def clear_success(db: AsyncSession, settings: Settings, username: str, request: Request) -> None:
        subject_hash, ip_hash = MoodleLoginRateLimiter._keys(settings, username, request)
        await db.execute(
            delete(MoodleLoginFailure).where(
                MoodleLoginFailure.subject_hash == subject_hash,
                MoodleLoginFailure.ip_hash == ip_hash,
            )
        )
        await db.commit()
