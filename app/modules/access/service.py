from sqlalchemy import select, union
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.access.models import (
    Application,
    AuditLog,
    Role,
    application_roles,
    user_application_access_roles,
    user_roles,
)
from app.modules.users.models import User

DEFAULT_ROLE = "coder"


class AccessService:
    @staticmethod
    async def seed(db: AsyncSession) -> None:
        await db.execute(insert(Role).values([
            {"name": "admin", "description": "Administración de Órbita"},
            {"name": "staff", "description": "Personal interno de Riwi"},
            {"name": DEFAULT_ROLE, "description": "Coders de Riwi"},
        ]).on_conflict_do_nothing(index_elements=["name"]))
        await db.commit()

    @staticmethod
    async def ensure_default_role(db: AsyncSession, user: User) -> None:
        has_role = await db.scalar(select(user_roles.c.user_id).where(user_roles.c.user_id == user.id).limit(1))
        if has_role:
            return
        role_id = await db.scalar(select(Role.id).where(Role.name == DEFAULT_ROLE))
        if role_id is not None:
            await db.execute(insert(user_roles).values(user_id=user.id, role_id=role_id).on_conflict_do_nothing())
            await db.commit()

    @staticmethod
    async def role_names(db: AsyncSession, user_id) -> list[str]:
        result = await db.scalars(select(Role.name).join(user_roles).where(user_roles.c.user_id == user_id).order_by(Role.name))
        return list(result)

    @staticmethod
    async def authorized_applications(db: AsyncSession, user_id) -> list[Application]:
        """Return applications authorized by either the legacy or scoped model.

        Existing catalog entries keep working while they are progressively
        migrated to application-scoped roles for SSO.
        """
        legacy_application_ids = (
            select(application_roles.c.application_id)
            .join(user_roles, user_roles.c.role_id == application_roles.c.role_id)
            .where(user_roles.c.user_id == user_id)
        )
        scoped_application_ids = (
            select(user_application_access_roles.c.application_id)
            .where(user_application_access_roles.c.user_id == user_id)
        )
        authorized_application_ids = union(
            legacy_application_ids,
            scoped_application_ids,
        ).subquery()
        result = await db.scalars(
            select(Application).distinct()
            .join(authorized_application_ids, authorized_application_ids.c.application_id == Application.id)
            .where(Application.is_active.is_(True))
            .order_by(Application.name)
        )
        return list(result)

    @staticmethod
    async def audit(db: AsyncSession, *, event: str, user_id=None, request=None, application_id=None, details: dict | None = None) -> None:
        db.add(AuditLog(
            event=event, user_id=user_id, application_id=application_id,
            ip_address=request.client.host if request and request.client else None,
            user_agent=request.headers.get("user-agent") if request else None,
            details=details or {},
        ))
        await db.commit()
