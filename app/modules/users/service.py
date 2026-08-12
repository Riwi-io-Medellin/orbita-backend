from sqlalchemy import select
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
    async def create(
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

    @staticmethod
    async def update(
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
    async def upsert(
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
            return await UserService.create(
                db,
                microsoft_id,
                email,
                full_name,
            )

        return await UserService.update(
            db,
            user,
            email,
            full_name,
        )

    @staticmethod
    async def get_by_id(
        db: AsyncSession,
        user_id: UUID,
    ) -> User | None:

        query = select(User).where(
            User.id == user_id
        )

        result = await db.execute(query)

        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_email(db: AsyncSession, email: str) -> User | None:
        result = await db.execute(select(User).where(User.email == email.lower()))
        return result.scalar_one_or_none()
