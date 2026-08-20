import hashlib
import hmac
import secrets
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.apps.models import App, AppRedirectURI, Role, UserAppRole
from app.modules.access.models import Application
from app.modules.users.models import User

_PBKDF2_ITERATIONS = 260_000


def _hash_secret(raw_secret: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        raw_secret.encode("utf-8"),
        bytes.fromhex(salt),
        _PBKDF2_ITERATIONS,
    ).hex()
    return f"{salt}${digest}"


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
    async def create_app(
        db: AsyncSession,
        client_id: str,
        slug: str,
        name: str,
        description: str,
        url: str,
        icon: str | None,
    ) -> tuple[App, str]:

        raw_secret = secrets.token_urlsafe(32)

        application = Application(
            slug=slug,
            name=name,
            description=description,
            url=url,
            icon=icon,
        )
        db.add(application)
        await db.flush()

        app = App(
            application_id=application.id,
            client_id=client_id,
            name=name,
            client_secret_hash=_hash_secret(raw_secret),
        )

        db.add(app)

        await db.commit()
        await db.refresh(app)

        return app, raw_secret

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
    async def set_active_status(
        db: AsyncSession,
        app: App,
        is_active: bool,
    ) -> App:

        app.is_active = is_active

        if app.application_id is not None:
            application = await db.get(Application, app.application_id)
            if application is not None:
                application.is_active = is_active

        await db.commit()
        await db.refresh(app)

        return app

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

        role = Role(app_id=app.id, name=name)

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
        )

        result = await db.execute(query)

        return result.scalar_one_or_none()

    @staticmethod
    async def list_for_app(db: AsyncSession, app: App) -> list[Role]:
        query = select(Role).where(Role.app_id == app.id)
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
            )
        )

        result = await db.execute(query)

        return list(result.scalars().all())

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
