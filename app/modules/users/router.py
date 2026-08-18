from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.modules.access.models import GlobalRole
from app.modules.access.service import AccessService
from app.modules.auth.dependencies import get_current_platform_admin
from app.modules.users.schemas import BulkStatusUpdate, BulkUserIds, UserAdminRead, UserStatusUpdate
from app.modules.users.service import UserService
from app.schemas import ErrorDetail

router = APIRouter(
    prefix="/users",
    tags=["Users"],
    dependencies=[Depends(get_current_platform_admin)],
    responses={
        401: {"model": ErrorDetail, "description": "No/invalid session cookie."},
        403: {"model": ErrorDetail, "description": "Caller is not a platform admin."},
    },
)


@router.get("/", response_model=list[UserAdminRead], summary="List users")
async def list_users(
    db: AsyncSession = Depends(get_db),
):
    """Returns every user that isn't soft-deleted (active or not)."""
    return await UserService.list_users(db)


# Bulk routes are declared before the "/{user_id}/..." routes below: they share
# the same path shape (e.g. "/bulk/status" vs "/{user_id}/status"), and FastAPI/
# Starlette matches in declaration order without backtracking on a UUID parse
# failure, so the dynamic routes would otherwise swallow these requests first.
@router.patch(
    "/bulk/status",
    response_model=list[UserAdminRead],
    summary="Bulk enable or disable users",
)
async def bulk_update_user_status(
    payload: BulkStatusUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Sets `is_active` for every listed user id in one call. Unknown ids are silently skipped (not an error) — only matched rows are updated and returned."""
    return await UserService.bulk_set_active_status(db, payload.user_ids, payload.is_active)


@router.post(
    "/bulk/delete",
    response_model=list[UserAdminRead],
    summary="Bulk soft-delete users",
)
async def bulk_delete_users(
    payload: BulkUserIds,
    db: AsyncSession = Depends(get_db),
):
    """Sets `deleted_at` and `is_active=false` for every listed user id. Unknown ids are silently skipped."""
    return await UserService.bulk_soft_delete(db, payload.user_ids)


@router.post(
    "/bulk/global-roles/{role_id}/grant",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Bulk grant a global role to users",
    responses={404: {"model": ErrorDetail, "description": "Global role not found."}},
)
async def bulk_grant_global_role(
    role_id: UUID,
    payload: BulkUserIds,
    db: AsyncSession = Depends(get_db),
):
    """Grants the role to every listed user id in one call — unlocks any app that requires this role for all of them at once. Idempotent per user."""
    role = await db.get(GlobalRole, role_id)

    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Global role not found")

    await AccessService.bulk_assign_global_role(db, payload.user_ids, role_id)


@router.post(
    "/bulk/global-roles/{role_id}/revoke",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Bulk revoke a global role from users",
)
async def bulk_revoke_global_role(
    role_id: UUID,
    payload: BulkUserIds,
    db: AsyncSession = Depends(get_db),
):
    """Revokes the role from every listed user id in one call."""
    await AccessService.bulk_revoke_global_role(db, payload.user_ids, role_id)


@router.patch(
    "/{user_id}/status",
    response_model=UserAdminRead,
    summary="Enable or disable a single user",
    responses={404: {"model": ErrorDetail, "description": "User not found."}},
)
async def update_user_status(
    user_id: UUID,
    payload: UserStatusUpdate,
    db: AsyncSession = Depends(get_db),
):
    """
    Sets `is_active`. New users (self-registered or via Microsoft) start inactive by default — this is
    how a platform admin turns on access. Setting it false blocks login and every authenticated call.
    """
    user = await UserService.get_user_by_id(db, user_id)

    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return await UserService.set_active_status(db, user, payload.is_active)


@router.delete(
    "/{user_id}",
    response_model=UserAdminRead,
    summary="Soft-delete a single user",
    responses={404: {"model": ErrorDetail, "description": "User not found."}},
)
async def delete_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Sets `deleted_at` and `is_active=false`. The row is kept (not hard-deleted) but excluded from the default `GET /users` listing and can no longer authenticate."""
    user = await UserService.get_user_by_id(db, user_id)

    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return await UserService.soft_delete_user(db, user)


@router.post(
    "/{user_id}/global-roles/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Grant a global role to a single user",
    responses={404: {"model": ErrorDetail, "description": "User not found, or global role not found."}},
)
async def assign_global_role(
    user_id: UUID,
    role_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Grants the user this global role, unlocking any launcher app that requires it. Idempotent."""
    user = await UserService.get_user_by_id(db, user_id)

    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    role = await db.get(GlobalRole, role_id)

    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Global role not found")

    await AccessService.assign_global_role(db, user_id, role_id)


@router.delete(
    "/{user_id}/global-roles/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a global role from a single user",
)
async def revoke_global_role(
    user_id: UUID,
    role_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Revokes the role. If it was the user's only path to an app's required role, that app disappears from their launcher. No-op if the link doesn't exist."""
    await AccessService.revoke_global_role(db, user_id, role_id)
