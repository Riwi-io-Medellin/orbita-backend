from uuid import UUID

from sqlalchemy import delete, func, select, union
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.access.models import (
    Application,
    ApplicationAccessPolicy,
    AuditLog,
    GlobalRole,
    application_global_roles,
    user_applications,
    user_global_roles,
)
from app.modules.users.models import User
from app.modules.apps.models import App, UserAppRole

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
    async def bootstrap_platform_admins(db: AsyncSession, emails: list[str]) -> None:
        normalized = sorted({email.strip().lower() for email in emails if email.strip()})
        if not normalized:
            return

        users = list(await db.scalars(select(User).where(func.lower(User.email).in_(normalized))))
        if not users:
            return

        admin_role_id = await db.scalar(select(GlobalRole.id).where(GlobalRole.name == "admin"))
        for user in users:
            user.is_platform_admin = True
            user.is_active = True

        if admin_role_id is not None:
            await db.execute(
                insert(user_global_roles)
                .values([
                    {"user_id": user.id, "global_role_id": admin_role_id}
                    for user in users
                ])
                .on_conflict_do_nothing()
            )
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
        legacy_ids = (
            select(Application.id)
            .join(application_global_roles, application_global_roles.c.application_id == Application.id)
            .join(user_global_roles, user_global_roles.c.global_role_id == application_global_roles.c.global_role_id)
            .where(
                user_global_roles.c.user_id == user_id,
                Application.is_active.is_(True),
                Application.access_policy == ApplicationAccessPolicy.CATALOG.value,
            )
        )
        app_role_ids = (
            select(Application.id)
            .join(App, App.application_id == Application.id)
            .join(UserAppRole, UserAppRole.app_id == App.id)
            .where(
                UserAppRole.user_id == user_id,
                Application.is_active.is_(True),
                App.is_active.is_(True),
            )
        )
        direct_ids = (
            select(Application.id)
            .join(user_applications, user_applications.c.application_id == Application.id)
            .where(
                user_applications.c.user_id == user_id,
                Application.is_active.is_(True),
                Application.access_policy == ApplicationAccessPolicy.CATALOG.value,
            )
        )
        authorized_ids = union(legacy_ids, app_role_ids, direct_ids).subquery()
        result = await db.scalars(
            select(Application)
            .join(authorized_ids, authorized_ids.c.id == Application.id)
            .order_by(Application.name)
        )
        return list(result)

    @staticmethod
    async def list_global_roles(db: AsyncSession) -> list[GlobalRole]:
        result = await db.scalars(select(GlobalRole).order_by(GlobalRole.name))
        return list(result)

    @staticmethod
    async def list_global_roles_for_user(db: AsyncSession, user_id: UUID) -> list[GlobalRole]:
        result = await db.scalars(
            select(GlobalRole)
            .join(user_global_roles, user_global_roles.c.global_role_id == GlobalRole.id)
            .where(user_global_roles.c.user_id == user_id)
            .order_by(GlobalRole.name)
        )
        return list(result)

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
    async def grant_application_access(db: AsyncSession, user_id: UUID, application_id: UUID) -> None:
        await db.execute(
            insert(user_applications)
            .values(user_id=user_id, application_id=application_id)
            .on_conflict_do_nothing()
        )
        await db.commit()

    @staticmethod
    async def revoke_application_access(db: AsyncSession, user_id: UUID, application_id: UUID) -> None:
        await db.execute(
            delete(user_applications).where(
                user_applications.c.user_id == user_id,
                user_applications.c.application_id == application_id,
            )
        )
        await db.commit()

    # Ids that don't match any user are reported back rather than silently dropped
    # (and, since this is a single multi-row INSERT, pre-filtering to ids that
    # actually exist is what keeps one bad id from failing the whole batch with
    # a ForeignKeyViolation - on_conflict_do_nothing() only covers the PK, not the FK).
    @staticmethod
    async def bulk_assign_global_role(db: AsyncSession, user_ids: list[UUID], global_role_id: UUID) -> tuple[list[UUID], list[UUID]]:
        if not user_ids:
            return [], []

        existing_ids = set(await db.scalars(select(User.id).where(User.id.in_(user_ids))))
        not_found_ids = [user_id for user_id in user_ids if user_id not in existing_ids]

        if existing_ids:
            await db.execute(
                insert(user_global_roles)
                .values([{"user_id": user_id, "global_role_id": global_role_id} for user_id in existing_ids])
                .on_conflict_do_nothing()
            )
            await db.commit()

        return list(existing_ids), not_found_ids

    # Ids that don't match any user are reported back rather than silently dropped
    @staticmethod
    async def bulk_revoke_global_role(db: AsyncSession, user_ids: list[UUID], global_role_id: UUID) -> tuple[list[UUID], list[UUID]]:
        existing_ids = set(await db.scalars(select(User.id).where(User.id.in_(user_ids))))
        not_found_ids = [user_id for user_id in user_ids if user_id not in existing_ids]

        if existing_ids:
            await db.execute(
                delete(user_global_roles).where(
                    user_global_roles.c.user_id.in_(existing_ids),
                    user_global_roles.c.global_role_id == global_role_id,
                )
            )
            await db.commit()

        return list(existing_ids), not_found_ids

    @staticmethod
    async def bulk_grant_application_access(db: AsyncSession, user_ids: list[UUID], application_id: UUID) -> tuple[list[UUID], list[UUID]]:
        if not user_ids:
            return [], []

        existing_ids = set(await db.scalars(select(User.id).where(User.id.in_(user_ids))))
        not_found_ids = [user_id for user_id in user_ids if user_id not in existing_ids]

        if existing_ids:
            await db.execute(
                insert(user_applications)
                .values([{"user_id": user_id, "application_id": application_id} for user_id in existing_ids])
                .on_conflict_do_nothing()
            )
            await db.commit()

        return list(existing_ids), not_found_ids

    @staticmethod
    async def bulk_revoke_application_access(db: AsyncSession, user_ids: list[UUID], application_id: UUID) -> tuple[list[UUID], list[UUID]]:
        existing_ids = set(await db.scalars(select(User.id).where(User.id.in_(user_ids))))
        not_found_ids = [user_id for user_id in user_ids if user_id not in existing_ids]

        if existing_ids:
            await db.execute(
                delete(user_applications).where(
                    user_applications.c.user_id.in_(existing_ids),
                    user_applications.c.application_id == application_id,
                )
            )
            await db.commit()

        return list(existing_ids), not_found_ids

    @staticmethod
    async def audit(db: AsyncSession, *, event: str, user_id=None, request=None, application_id=None, details: dict | None = None) -> None:
        db.add(AuditLog(
            event=event, user_id=user_id, application_id=application_id,
            ip_address=request.client.host if request and request.client else None,
            user_agent=request.headers.get("user-agent") if request else None,
            details=details or {},
        ))
        await db.commit()
