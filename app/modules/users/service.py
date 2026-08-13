from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

from app.modules.users.models import User


class UserService:

    # Search for an user by microsoft_id
    @staticmethod
    async def get_by_microsoft_id(
        db: AsyncSession,
        microsoft_id: str,
    ) -> User | None:

        query = select(User).where(
            User.microsoft_id == microsoft_id
        )

        result = await db.execute(query)

        return result.scalar_one_or_none()

    # Creates an user if not exits
    @staticmethod
    async def create_user(
        db: AsyncSession,
        microsoft_id: str,
        email: str,
        full_name: str,
    ) -> User:

        user = User(
            microsoft_id=microsoft_id,
            email=email,
            full_name=full_name,
        )

        db.add(user)

        await db.commit()

        await db.refresh(user)

        return user

    # Lists users for the admin view
    @staticmethod
    async def list_users(
        db: AsyncSession,
        include_deleted: bool = False,
    ) -> list[User]:

        query = select(User)

        if not include_deleted:
            query = query.where(User.deleted_at.is_(None))

        result = await db.execute(query.order_by(User.email))

        return list(result.scalars().all())

    # Enables/disables login for a user
    @staticmethod
    async def set_active_status(
        db: AsyncSession,
        user: User,
        is_active: bool,
    ) -> User:

        user.is_active = is_active

        await db.commit()
        await db.refresh(user)

        return user

    # Soft-deletes a user: marks deleted_at and disables login
    @staticmethod
    async def soft_delete_user(
        db: AsyncSession,
        user: User,
    ) -> User:

        user.deleted_at = datetime.now(timezone.utc)
        user.is_active = False

        await db.commit()
        await db.refresh(user)

        return user

    # Bulk enables/disables login for a set of users
    @staticmethod
    async def bulk_set_active_status(
        db: AsyncSession,
        user_ids: list[UUID],
        is_active: bool,
    ) -> list[User]:

        await db.execute(
            update(User).where(User.id.in_(user_ids)).values(is_active=is_active)
        )
        await db.commit()

        result = await db.execute(select(User).where(User.id.in_(user_ids)))

        return list(result.scalars().all())

    # Bulk soft-deletes a set of users: marks deleted_at and disables login
    @staticmethod
    async def bulk_soft_delete(
        db: AsyncSession,
        user_ids: list[UUID],
    ) -> list[User]:

        await db.execute(
            update(User)
            .where(User.id.in_(user_ids))
            .values(is_active=False, deleted_at=datetime.now(timezone.utc))
        )
        await db.commit()

        result = await db.execute(select(User).where(User.id.in_(user_ids)))

        return list(result.scalars().all())

    @staticmethod
    async def update_user(
        db: AsyncSession,
        user: User,
        email: str,
        full_name: str,
    ) -> User:

        user.email = email
        user.full_name = full_name

        await db.commit()
        await db.refresh(user)

        return user

    # Search for an user, if exits, then it updates the user, if not, its created
    @staticmethod
    async def upsert_user(
        db: AsyncSession,
        microsoft_id: str,
        email: str,
        full_name: str,
    ) -> User:

        user = await UserService.get_by_microsoft_id(
            db,
            microsoft_id,
        )

        if user is None:
            return await UserService.create_user(
                db,
                microsoft_id,
                email,
                full_name,
            )

        return await UserService.update_user(
            db,
            user,
            email,
            full_name,
        )

    @staticmethod
    async def get_user_by_id(
        db: AsyncSession,
        user_id: UUID,
    ) -> User | None:

        query = select(User).where(
            User.id == user_id
        )

        result = await db.execute(query)

        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_email(
        db: AsyncSession,
        email: str,
    ) -> User | None:

        query = select(User).where(
            User.email == email.lower()
        )

        result = await db.execute(query)

        return result.scalar_one_or_none()

    # Creates a local (password-based) user, no Microsoft identity
    @staticmethod
    async def create_local_user(
        db: AsyncSession,
        email: str,
        full_name: str,
        password_hash: str,
    ) -> User:

        user = User(
            microsoft_id=None,
            email=email,
            full_name=full_name,
            password_hash=password_hash,
        )

        db.add(user)

        await db.commit()

        await db.refresh(user)

        return user