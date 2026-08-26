import hashlib
import hmac
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.apps.models import App, AppRedirectURI, Role, UserAppRole
from app.modules.apps.schemas import RoleCatalogEntry
from app.modules.access.models import Application
from app.modules.users.models import User
from app.modules.apps.application_lifecycle import _PBKDF2_ITERATIONS

def _verify_secret(raw_secret: str, stored_hash: str) -> bool:
    salt, _, digest = stored_hash.partition("$")
    if not salt or not digest:
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256",
        raw_secret.encode("utf-8"),
        bytes.fromhex(salt),
        _PBKDF2_ITERATIONS,
    ).hex()
    return hmac.compare_digest(candidate, digest)


class AppService:

    @staticmethod
    async def get_by_client_id(
        db: AsyncSession,
        client_id: str,
    ) -> App | None:

        query = select(App).where(App.client_id == client_id)
        result = await db.execute(query)

        return result.scalar_one_or_none()

    @staticmethod
    async def list_apps(
        db: AsyncSession,
        is_active: bool | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[App]:
        query = select(App)

        if is_active is not None:
            query = query.where(App.is_active == is_active)

        query = query.order_by(App.name).limit(limit).offset(offset)

        result = await db.execute(query)

        return list(result.scalars().all())

    @staticmethod
    async def get_catalog_application_by_slug(
        db: AsyncSession,
        slug: str,
    ) -> Application | None:
        return await db.scalar(select(Application).where(Application.slug == slug))

    @staticmethod
    def verify_client_secret(app: App, raw_secret: str) -> bool:
        return _verify_secret(raw_secret, app.client_secret_hash)

    @staticmethod
    async def add_redirect_uri(
        db: AsyncSession,
        app: App,
        redirect_uri: str,
    ) -> AppRedirectURI:

        entry = AppRedirectURI(
            app_id=app.id,
            redirect_uri=redirect_uri,
        )

        db.add(entry)

        await db.commit()
        await db.refresh(entry)

        return entry

    @staticmethod
    async def validate_redirect_uri(
        db: AsyncSession,
        app: App,
        redirect_uri: str,
    ) -> bool:

        query = select(AppRedirectURI).where(
            AppRedirectURI.app_id == app.id,
            AppRedirectURI.redirect_uri == redirect_uri,
        )

        result = await db.execute(query)

        return result.scalar_one_or_none() is not None


class RoleService:

    @staticmethod
    async def create_role(
        db: AsyncSession,
        app: App,
        name: str,
    ) -> Role:

        role = Role(app_id=app.id, name=name, display_name=name)

        db.add(role)

        await db.commit()
        await db.refresh(role)

        return role

    @staticmethod
    async def get_by_app_and_name(
        db: AsyncSession,
        app: App,
        name: str,
    ) -> Role | None:

        query = select(Role).where(
            Role.app_id == app.id,
            Role.name == name,
        )

        result = await db.execute(query)

        return result.scalar_one_or_none()

    @staticmethod
    async def get_role_by_id(
        db: AsyncSession,
        app: App,
        role_id: UUID,
    ) -> Role | None:

        query = select(Role).where(
            Role.app_id == app.id,
            Role.id == role_id,
            Role.is_active.is_(True),
        )

        result = await db.execute(query)

        return result.scalar_one_or_none()

    @staticmethod
    async def list_for_app(db: AsyncSession, app: App, include_inactive: bool = False) -> list[Role]:
        query = select(Role).where(Role.app_id == app.id)
        if not include_inactive:
            query = query.where(Role.is_active.is_(True))
        query = query.order_by(Role.display_name)
        result = await db.execute(query)

        return list(result.scalars().all())

    @staticmethod
    async def assign_role_to_user(
        db: AsyncSession,
        user_id: UUID,
        app: App,
        role: Role,
    ) -> UserAppRole:

        existing_query = select(UserAppRole).where(
            UserAppRole.user_id == user_id,
            UserAppRole.app_id == app.id,
            UserAppRole.role_id == role.id,
        )
        existing = (await db.execute(existing_query)).scalar_one_or_none()

        if existing is not None:
            return existing

        assignment = UserAppRole(
            user_id=user_id,
            app_id=app.id,
            role_id=role.id,
        )

        db.add(assignment)

        await db.commit()
        await db.refresh(assignment)

        return assignment

    @staticmethod
    async def list_roles_for_user_in_app(
        db: AsyncSession,
        user_id: UUID,
        app: App,
    ) -> list[str]:

        query = (
            select(Role.name)
            .join(UserAppRole, UserAppRole.role_id == Role.id)
            .where(
                UserAppRole.user_id == user_id,
                UserAppRole.app_id == app.id,
                Role.is_active.is_(True),
            )
        )

        result = await db.execute(query)

        return list(result.scalars().all())

    @staticmethod
    async def sync_catalog(
        db: AsyncSession,
        app: App,
        entries: list[RoleCatalogEntry],
    ) -> tuple[list[Role], list[str]]:
        """Upsert the app's declared roles and safely retire missing managed roles."""
        existing_roles = list(await db.scalars(select(Role).where(Role.app_id == app.id)))
        by_key = {role.name: role for role in existing_roles}
        declared_keys = {entry.key for entry in entries}

        for entry in entries:
            role = by_key.get(entry.key)
            if role is None:
                db.add(Role(
                    app_id=app.id,
                    name=entry.key,
                    display_name=entry.display_name,
                    description=entry.description,
                    is_active=True,
                    managed_by_app=True,
                ))
            else:
                role.display_name = entry.display_name
                role.description = entry.description
                role.is_active = True
                role.managed_by_app = True

        deactivated = []
        for role in existing_roles:
            if role.managed_by_app and role.name not in declared_keys and role.is_active:
                role.is_active = False
                deactivated.append(role.name)

        await db.commit()
        roles = await RoleService.list_for_app(db, app, include_inactive=True)
        return roles, deactivated

    @staticmethod
    async def delete_role(db: AsyncSession, role: Role) -> None:
        await db.execute(delete(UserAppRole).where(UserAppRole.role_id == role.id))
        await db.delete(role)
        await db.commit()

    @staticmethod
    async def unassign_role_from_user(
        db: AsyncSession,
        user_id: UUID,
        app: App,
        role: Role,
    ) -> None:

        await db.execute(
            delete(UserAppRole).where(
                UserAppRole.user_id == user_id,
                UserAppRole.app_id == app.id,
                UserAppRole.role_id == role.id,
            )
        )
        await db.commit()

    @staticmethod
    async def bulk_assign_role_to_users(
        db: AsyncSession,
        user_ids: list[UUID],
        app: App,
        role: Role,
    ) -> tuple[list[UUID], list[UUID]]:

        if not user_ids:
            return [], []

        existing_ids = set(await db.scalars(select(User.id).where(User.id.in_(user_ids))))
        not_found_ids = [user_id for user_id in user_ids if user_id not in existing_ids]

        if existing_ids:
            await db.execute(
                insert(UserAppRole)
                .values([{"user_id": uid, "app_id": app.id, "role_id": role.id} for uid in existing_ids])
                .on_conflict_do_nothing()
            )
            await db.commit()

        return list(existing_ids), not_found_ids

    @staticmethod
    async def bulk_unassign_role_from_users(
        db: AsyncSession,
        user_ids: list[UUID],
        app: App,
        role: Role,
    ) -> tuple[list[UUID], list[UUID]]:

        existing_ids = set(await db.scalars(select(User.id).where(User.id.in_(user_ids))))
        not_found_ids = [user_id for user_id in user_ids if user_id not in existing_ids]

        if existing_ids:
            await db.execute(
                delete(UserAppRole).where(
                    UserAppRole.user_id.in_(existing_ids),
                    UserAppRole.app_id == app.id,
                    UserAppRole.role_id == role.id,
                )
            )
            await db.commit()

        return list(existing_ids), not_found_ids

    @staticmethod
    async def list_user_roles_for_app(
        db: AsyncSession,
        app: App,
        limit: int = 100,
        offset: int = 0,
    ) -> list[tuple[UUID, str, str, str]]:

        query = (
            select(User.id, User.email, User.full_name, Role.name)
            .join(UserAppRole, UserAppRole.user_id == User.id)
            .join(Role, Role.id == UserAppRole.role_id)
            .where(UserAppRole.app_id == app.id)
            .order_by(User.email, Role.name)
            .limit(limit)
            .offset(offset)
        )

        result = await db.execute(query)

        return list(result.all())

    @staticmethod
    async def list_app_roles_for_user(
        db: AsyncSession,
        user_id: UUID,
        limit: int = 100,
        offset: int = 0,
    ) -> list[tuple[UUID, str, str, UUID, str]]:

        query = (
            select(App.id, App.client_id, App.name, Role.id, Role.name)
            .join(UserAppRole, UserAppRole.app_id == App.id)
            .join(Role, Role.id == UserAppRole.role_id)
            .where(UserAppRole.user_id == user_id)
            .order_by(App.name, Role.name)
            .limit(limit)
            .offset(offset)
        )

        result = await db.execute(query)

        return list(result.all())
