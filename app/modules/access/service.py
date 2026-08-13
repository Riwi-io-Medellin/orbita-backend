from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.access.models import Application, AuditLog, GlobalRole, application_global_roles, user_global_roles
from app.modules.users.models import User

DEFAULT_ROLE = "coder"


class AccessService:
    @staticmethod
    async def seed(db: AsyncSession) -> None:
        await db.execute(insert(GlobalRole).values([
            {"name": "admin", "description": "Administración de Órbita"},
            {"name": "staff", "description": "Personal interno de Riwi"},
            {"name": DEFAULT_ROLE, "description": "Coders de Riwi"},
        ]).on_conflict_do_nothing(index_elements=["name"]))
        await db.commit()

    @staticmethod
    async def ensure_default_role(db: AsyncSession, user: User) -> None:
        has_role = await db.scalar(select(user_global_roles.c.user_id).where(user_global_roles.c.user_id == user.id).limit(1))
        if has_role:
            return
        role_id = await db.scalar(select(GlobalRole.id).where(GlobalRole.name == DEFAULT_ROLE))
        if role_id is not None:
            await db.execute(insert(user_global_roles).values(user_id=user.id, global_role_id=role_id).on_conflict_do_nothing())
            await db.commit()

    @staticmethod
    async def role_names(db: AsyncSession, user_id) -> list[str]:
        result = await db.scalars(select(GlobalRole.name).join(user_global_roles).where(user_global_roles.c.user_id == user_id).order_by(GlobalRole.name))
        return list(result)

    @staticmethod
    async def authorized_applications(db: AsyncSession, user_id) -> list[Application]:
        result = await db.scalars(
            select(Application).distinct()
            .join(application_global_roles, application_global_roles.c.application_id == Application.id)
            .join(user_global_roles, user_global_roles.c.global_role_id == application_global_roles.c.global_role_id)
            .where(user_global_roles.c.user_id == user_id, Application.is_active.is_(True))
            .order_by(Application.name)
        )
        return list(result)

    @staticmethod
    async def list_global_roles(db: AsyncSession) -> list[GlobalRole]:
        result = await db.scalars(select(GlobalRole).order_by(GlobalRole.name))
        return list(result)

    @staticmethod
    async def create_application(
        db: AsyncSession,
        slug: str,
        name: str,
        description: str,
        url: str,
        icon: str | None,
    ) -> Application:

        application = Application(slug=slug, name=name, description=description, url=url, icon=icon)

        db.add(application)

        await db.commit()
        await db.refresh(application)

        return application

    @staticmethod
    async def set_application_status(db: AsyncSession, application: Application, is_active: bool) -> Application:
        application.is_active = is_active

        await db.commit()
        await db.refresh(application)

        return application

    @staticmethod
    async def grant_application_role(db: AsyncSession, application_id: UUID, global_role_id: UUID) -> None:
        await db.execute(
            insert(application_global_roles)
            .values(application_id=application_id, global_role_id=global_role_id)
            .on_conflict_do_nothing()
        )
        await db.commit()

    @staticmethod
    async def revoke_application_role(db: AsyncSession, application_id: UUID, global_role_id: UUID) -> None:
        await db.execute(
            delete(application_global_roles).where(
                application_global_roles.c.application_id == application_id,
                application_global_roles.c.global_role_id == global_role_id,
            )
        )
        await db.commit()

    @staticmethod
    async def assign_global_role(db: AsyncSession, user_id: UUID, global_role_id: UUID) -> None:
        await db.execute(
            insert(user_global_roles)
            .values(user_id=user_id, global_role_id=global_role_id)
            .on_conflict_do_nothing()
        )
        await db.commit()

    @staticmethod
    async def revoke_global_role(db: AsyncSession, user_id: UUID, global_role_id: UUID) -> None:
        await db.execute(
            delete(user_global_roles).where(
                user_global_roles.c.user_id == user_id,
                user_global_roles.c.global_role_id == global_role_id,
            )
        )
        await db.commit()

    @staticmethod
    async def bulk_assign_global_role(db: AsyncSession, user_ids: list[UUID], global_role_id: UUID) -> None:
        if not user_ids:
            return

        await db.execute(
            insert(user_global_roles)
            .values([{"user_id": user_id, "global_role_id": global_role_id} for user_id in user_ids])
            .on_conflict_do_nothing()
        )
        await db.commit()

    @staticmethod
    async def bulk_revoke_global_role(db: AsyncSession, user_ids: list[UUID], global_role_id: UUID) -> None:
        await db.execute(
            delete(user_global_roles).where(
                user_global_roles.c.user_id.in_(user_ids),
                user_global_roles.c.global_role_id == global_role_id,
            )
        )
        await db.commit()

    @staticmethod
    async def audit(db: AsyncSession, *, event: str, user_id=None, request=None, application_id=None, details: dict | None = None) -> None:
        db.add(AuditLog(
            event=event, user_id=user_id, application_id=application_id,
            ip_address=request.client.host if request and request.client else None,
            user_agent=request.headers.get("user-agent") if request else None,
            details=details or {},
        ))
        await db.commit()
