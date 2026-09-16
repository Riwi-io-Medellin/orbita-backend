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
    user_global_role_sources,
)
from app.modules.users.models import User, UserFederatedAttribute
from app.modules.apps.models import App, UserAppRole

DEFAULT_ROLE = "guest"
PLATFORM_ADMIN_ROLE = "admin"
MOODLE_ROLE_SOURCE = "moodle"
MANUAL_ROLE_SOURCE = "manual"
BOOTSTRAP_ROLE_SOURCE = "bootstrap"
FALLBACK_ROLE_SOURCE = "fallback"
ROLE_PRIORITY = (PLATFORM_ADMIN_ROLE, "teamleader", "coder", DEFAULT_ROLE)


def resolve_effective_role(names_by_source: dict[str, str]) -> str:
    """Resolve the one role used for authorization from its independent sources."""
    return (
        PLATFORM_ADMIN_ROLE if PLATFORM_ADMIN_ROLE in names_by_source.values()
        else names_by_source.get(MOODLE_ROLE_SOURCE)
        or names_by_source.get(MANUAL_ROLE_SOURCE)
        or DEFAULT_ROLE
    )


class AccessService:
    @staticmethod
    async def seed(db: AsyncSession) -> None:
        await db.execute(insert(GlobalRole).values([
            {"name": PLATFORM_ADMIN_ROLE, "description": "Administración de Órbita"},
            {"name": "teamleader", "description": "Liderazgo académico de Riwi"},
            {"name": "coder", "description": "Coders de Riwi"},
            {"name": DEFAULT_ROLE, "description": "Cuenta sin rol ni acceso por catálogo"},
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

        admin_role_id = await db.scalar(
            select(GlobalRole.id).where(GlobalRole.name == PLATFORM_ADMIN_ROLE)
        )

        if admin_role_id is not None:
            await db.execute(
                insert(user_global_role_sources)
                .values([
                    {"user_id": user.id, "global_role_id": admin_role_id, "source": BOOTSTRAP_ROLE_SOURCE}
                    for user in users
                ])
                .on_conflict_do_nothing()
            )
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
        has_source = await db.scalar(select(user_global_role_sources.c.user_id).where(user_global_role_sources.c.user_id == user.id).limit(1))
        if has_source:
            return
        role_id = await db.scalar(select(GlobalRole.id).where(GlobalRole.name == DEFAULT_ROLE))
        if role_id is not None:
            await db.execute(insert(user_global_role_sources).values(user_id=user.id, global_role_id=role_id, source=FALLBACK_ROLE_SOURCE).on_conflict_do_nothing())
            await AccessService.reconcile_effective_role(db, user.id, commit=False)
            await db.commit()

    @staticmethod
    async def reconcile_effective_role(db: AsyncSession, user_id: UUID, *, commit: bool = True) -> str:
        rows = (await db.execute(
            select(GlobalRole.name, user_global_role_sources.c.source)
            .join(user_global_role_sources, user_global_role_sources.c.global_role_id == GlobalRole.id)
            .where(user_global_role_sources.c.user_id == user_id)
        )).all()
        names_by_source = {source: name for name, source in rows}
        effective = resolve_effective_role(names_by_source)
        role_id = await db.scalar(select(GlobalRole.id).where(GlobalRole.name == effective))
        await db.execute(delete(user_global_roles).where(user_global_roles.c.user_id == user_id))
        if role_id is not None:
            await db.execute(insert(user_global_roles).values(user_id=user_id, global_role_id=role_id))
        if commit:
            await db.commit()
        return effective

    @staticmethod
    async def sync_moodle_role(db: AsyncSession, user_id: UUID, role_name: str | None) -> str:
        await db.execute(delete(user_global_role_sources).where(
            user_global_role_sources.c.user_id == user_id,
            user_global_role_sources.c.source == MOODLE_ROLE_SOURCE,
        ))
        if role_name is not None:
            role_id = await db.scalar(select(GlobalRole.id).where(GlobalRole.name == role_name))
            if role_id is not None:
                await db.execute(insert(user_global_role_sources).values(
                    user_id=user_id, global_role_id=role_id, source=MOODLE_ROLE_SOURCE,
                ))
        return await AccessService.reconcile_effective_role(db, user_id)

    @staticmethod
    async def sync_moodle_clan(db: AsyncSession, user_id: UUID, *, role_name: str | None, clan: str | None, status: str) -> None:
        if role_name != "coder":
            await db.execute(delete(UserFederatedAttribute).where(
                UserFederatedAttribute.user_id == user_id,
                UserFederatedAttribute.name == "clan",
            ))
            await db.commit()
            return
        existing = await db.scalar(select(UserFederatedAttribute).where(
            UserFederatedAttribute.user_id == user_id,
            UserFederatedAttribute.name == "clan",
        ))
        if existing is None:
            db.add(UserFederatedAttribute(
                user_id=user_id,
                name="clan",
                value=clan if status == "synced" else None,
                source="moodle",
                sync_status=status,
            ))
        else:
            existing.value = clan if status == "synced" else None
            existing.source = "moodle"
            existing.sync_status = status
            existing.observed_at = func.now()
        await db.commit()

    @staticmethod
    async def set_manual_global_role(db: AsyncSession, user_id: UUID, role_id: UUID) -> str:
        role = await db.get(GlobalRole, role_id)
        if role is None or role.name == DEFAULT_ROLE:
            raise ValueError("This role cannot be assigned manually")
        has_moodle_role = await db.scalar(select(user_global_role_sources.c.user_id).where(
            user_global_role_sources.c.user_id == user_id,
            user_global_role_sources.c.source == MOODLE_ROLE_SOURCE,
        ).limit(1))
        if has_moodle_role and role.name != PLATFORM_ADMIN_ROLE:
            raise PermissionError("This user's role is synchronized from Moodle")
        await db.execute(delete(user_global_role_sources).where(
            user_global_role_sources.c.user_id == user_id,
            user_global_role_sources.c.source == MANUAL_ROLE_SOURCE,
        ))
        await db.execute(insert(user_global_role_sources).values(
            user_id=user_id, global_role_id=role_id, source=MANUAL_ROLE_SOURCE,
        ))
        return await AccessService.reconcile_effective_role(db, user_id)

    @staticmethod
    async def revoke_manual_global_role(db: AsyncSession, user_id: UUID, role_id: UUID) -> str:
        await db.execute(delete(user_global_role_sources).where(
            user_global_role_sources.c.user_id == user_id,
            user_global_role_sources.c.global_role_id == role_id,
            user_global_role_sources.c.source == MANUAL_ROLE_SOURCE,
        ))
        return await AccessService.reconcile_effective_role(db, user_id)

    @staticmethod
    async def role_names(db: AsyncSession, user_id) -> list[str]:
        result = await db.scalars(select(GlobalRole.name).join(user_global_roles).where(user_global_roles.c.user_id == user_id).order_by(GlobalRole.name))
        return list(result)

    @staticmethod
    async def has_global_role(db: AsyncSession, user_id, role_name: str) -> bool:
        role_id = await db.scalar(
            select(GlobalRole.id)
            .join(user_global_roles)
            .where(
                user_global_roles.c.user_id == user_id,
                GlobalRole.name == role_name,
            )
            .limit(1)
        )
        return role_id is not None

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
        direct_ids = (
            select(Application.id)
            .join(user_applications, user_applications.c.application_id == Application.id)
            .where(
                user_applications.c.user_id == user_id,
                Application.is_active.is_(True),
                Application.access_policy == ApplicationAccessPolicy.CATALOG.value,
            )
        )
        authorized_ids = union(legacy_ids, direct_ids).subquery()
        catalog = list(await db.scalars(
            select(Application)
            .join(authorized_ids, authorized_ids.c.id == Application.id)
        ))

        # SSO apps use the same resolver as authorize/token so launcher visibility
        # cannot bypass guest suppression, role cardinality or migration policy.
        from app.modules.apps.service import RoleService
        sso_rows = (await db.execute(
            select(Application, App)
            .join(App, App.application_id == Application.id)
            .where(Application.is_active.is_(True), App.is_active.is_(True))
        )).all()
        authorized = {application.id: application for application in catalog}
        for application, app in sso_rows:
            access = await RoleService.resolve_access(db, user_id, app)
            if access.roles or access.migration:
                authorized[application.id] = application
        return sorted(authorized.values(), key=lambda application: application.name.lower())

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
        role = await db.get(GlobalRole, global_role_id)
        if role is not None and role.name == DEFAULT_ROLE:
            raise ValueError("Guest cannot be granted catalog access by role")
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
        await AccessService.set_manual_global_role(db, user_id, global_role_id)

    @staticmethod
    async def revoke_global_role(db: AsyncSession, user_id: UUID, global_role_id: UUID) -> None:
        await AccessService.revoke_manual_global_role(db, user_id, global_role_id)

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
