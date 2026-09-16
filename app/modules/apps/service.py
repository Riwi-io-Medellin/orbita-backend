import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.apps.models import App, AppGlobalRoleMapping, AppPostLogoutURI, AppRedirectURI, Role, UserAppRole
from app.modules.apps.schemas import RoleCatalogEntry
from app.modules.access.models import Application, GlobalRole, user_global_roles
from app.modules.users.models import User
from app.modules.apps.application_lifecycle import _PBKDF2_ITERATIONS, hash_client_secret
from app.modules.auth.models import AppSession

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
        if _verify_secret(raw_secret, app.client_secret_hash):
            return True
        return bool(
            app.previous_client_secret_hash
            and app.previous_secret_expires_at
            and app.previous_secret_expires_at > datetime.now(UTC)
            and _verify_secret(raw_secret, app.previous_client_secret_hash)
        )

    @staticmethod
    async def rotate_client_secret(db: AsyncSession, app: App, *, grace_minutes: int = 15) -> tuple[str, datetime]:
        raw_secret = secrets.token_urlsafe(32)
        expires_at = datetime.now(UTC) + timedelta(minutes=grace_minutes)
        app.previous_client_secret_hash = app.client_secret_hash
        app.previous_secret_expires_at = expires_at
        app.client_secret_hash = hash_client_secret(raw_secret)
        await db.commit()
        await db.refresh(app)
        return raw_secret, expires_at

    @staticmethod
    async def is_available_for_sso(db: AsyncSession, app: App) -> bool:
        if not app.is_active or app.application_id is None:
            return False
        application = await db.get(Application, app.application_id)
        return bool(application and application.is_active)

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

    @staticmethod
    async def add_post_logout_uri(db: AsyncSession, app: App, uri: str) -> AppPostLogoutURI:
        entry = AppPostLogoutURI(app_id=app.id, post_logout_uri=uri)
        db.add(entry)
        await db.commit()
        await db.refresh(entry)
        return entry

    @staticmethod
    async def validate_post_logout_uri(db: AsyncSession, app: App, uri: str) -> bool:
        return await db.scalar(select(AppPostLogoutURI.id).where(
            AppPostLogoutURI.app_id == app.id, AppPostLogoutURI.post_logout_uri == uri,
        )) is not None

    @staticmethod
    async def update_policy(
        db: AsyncSession,
        app: App,
        *,
        role_cardinality: str,
        migration_access_enabled: bool,
        jit_role_adoption_enabled: bool,
        released_claims: list[str],
    ) -> App:
        app.role_cardinality = role_cardinality
        app.migration_access_enabled = migration_access_enabled
        app.jit_role_adoption_enabled = jit_role_adoption_enabled
        app.released_claims = released_claims
        await db.commit()
        await db.refresh(app)
        return app

    @staticmethod
    async def upsert_global_role_mapping(db: AsyncSession, app: App, global_role_name: str, app_role_name: str) -> None:
        global_role = await db.scalar(select(GlobalRole).where(GlobalRole.name == global_role_name))
        app_role = await db.scalar(select(Role).where(
            Role.app_id == app.id, Role.name == app_role_name, Role.is_active.is_(True),
        ))
        if global_role is None or app_role is None:
            raise ValueError("Global role or app role not found")
        existing = await db.scalar(select(AppGlobalRoleMapping).where(
            AppGlobalRoleMapping.app_id == app.id,
            AppGlobalRoleMapping.global_role_id == global_role.id,
        ))
        if existing:
            existing.app_role_id = app_role.id
        else:
            db.add(AppGlobalRoleMapping(
                app_id=app.id, global_role_id=global_role.id, app_role_id=app_role.id,
            ))
        await db.commit()


@dataclass(frozen=True)
class AppAccessResolution:
    roles: list[str]
    migration: bool = False


def resolve_app_access_policy(
    *,
    global_roles: list[str],
    explicit_roles: list[str],
    mapped_roles: list[str],
    role_cardinality: str,
    migration_access_enabled: bool,
) -> AppAccessResolution:
    if not global_roles or "guest" in global_roles:
        return AppAccessResolution([])
    explicit = sorted(set(explicit_roles))
    if explicit:
        return AppAccessResolution(explicit) if role_cardinality != "single" or len(explicit) == 1 else AppAccessResolution([])
    mapped = sorted(set(mapped_roles))
    if mapped:
        return AppAccessResolution(mapped) if role_cardinality != "single" or len(mapped) == 1 else AppAccessResolution([])
    return AppAccessResolution([], migration=migration_access_enabled)


class RoleService:

    @staticmethod
    async def resolve_access(db: AsyncSession, user_id: UUID, app: App) -> AppAccessResolution:
        global_roles = list(await db.scalars(
            select(GlobalRole.name)
            .join(user_global_roles, user_global_roles.c.global_role_id == GlobalRole.id)
            .where(user_global_roles.c.user_id == user_id)
        ))
        explicit = await RoleService.list_roles_for_user_in_app(db, user_id, app)

        mapped = list(await db.scalars(
            select(Role.name)
            .join(AppGlobalRoleMapping, AppGlobalRoleMapping.app_role_id == Role.id)
            .join(GlobalRole, GlobalRole.id == AppGlobalRoleMapping.global_role_id)
            .join(user_global_roles, user_global_roles.c.global_role_id == GlobalRole.id)
            .where(
                AppGlobalRoleMapping.app_id == app.id,
                user_global_roles.c.user_id == user_id,
                Role.is_active.is_(True),
            )
        ))
        return resolve_app_access_policy(
            global_roles=global_roles,
            explicit_roles=explicit,
            mapped_roles=mapped,
            role_cardinality=app.role_cardinality,
            migration_access_enabled=app.migration_access_enabled,
        )

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
        *,
        source: str = "manual",
    ) -> UserAppRole:

        existing_query = select(UserAppRole).where(
            UserAppRole.user_id == user_id,
            UserAppRole.app_id == app.id,
            UserAppRole.role_id == role.id,
        )
        existing = (await db.execute(existing_query)).scalar_one_or_none()

        if existing is not None:
            return existing

        if app.role_cardinality == "single":
            conflicting = await db.scalar(select(UserAppRole.id).where(
                UserAppRole.user_id == user_id,
                UserAppRole.app_id == app.id,
                UserAppRole.role_id != role.id,
            ).limit(1))
            if conflicting is not None:
                raise ValueError("This app allows only one role per user")

        assignment = UserAppRole(
            user_id=user_id,
            app_id=app.id,
            role_id=role.id,
            source=source,
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

        if deactivated:
            await db.execute(
                update(AppSession)
                .where(AppSession.app_id == app.id, AppSession.revoked_at.is_(None))
                .values(revoked_at=datetime.now(UTC))
            )

        await db.commit()
        roles = await RoleService.list_for_app(db, app, include_inactive=True)
        return roles, deactivated

    @staticmethod
    async def delete_role(db: AsyncSession, role: Role) -> None:
        user_ids = list(await db.scalars(select(UserAppRole.user_id).where(UserAppRole.role_id == role.id)))
        await db.execute(delete(UserAppRole).where(UserAppRole.role_id == role.id))
        if user_ids:
            await db.execute(
                update(AppSession)
                .where(
                    AppSession.app_id == role.app_id,
                    AppSession.user_id.in_(user_ids),
                    AppSession.revoked_at.is_(None),
                )
                .values(revoked_at=datetime.now(UTC))
            )
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
        await db.execute(
            update(AppSession)
            .where(
                AppSession.user_id == user_id,
                AppSession.app_id == app.id,
                AppSession.revoked_at.is_(None),
            )
            .values(revoked_at=datetime.now(UTC))
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

        if app.role_cardinality == "single" and existing_ids:
            conflicting = await db.scalar(select(UserAppRole.id).where(
                UserAppRole.user_id.in_(existing_ids),
                UserAppRole.app_id == app.id,
                UserAppRole.role_id != role.id,
            ).limit(1))
            if conflicting is not None:
                raise ValueError("This app allows only one role per user")

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
            await db.execute(
                update(AppSession)
                .where(
                    AppSession.user_id.in_(existing_ids),
                    AppSession.app_id == app.id,
                    AppSession.revoked_at.is_(None),
                )
                .values(revoked_at=datetime.now(UTC))
            )
            await db.commit()

        return list(existing_ids), not_found_ids

    @staticmethod
    async def list_user_roles_for_app(
        db: AsyncSession,
        app: App,
        limit: int = 100,
        offset: int = 0,
    ) -> list[tuple[UUID, str, str, UUID, str]]:

        query = (
            select(User.id, User.email, User.full_name, Role.id, Role.name)
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
