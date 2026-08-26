from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.modules.access.models import Application, ApplicationAccessPolicy, GlobalRole
from app.modules.access.schemas import AuthorizedApplicationRead, GlobalRoleRead
from app.modules.access.service import AccessService
from app.modules.apps.schemas import AppRoleRead
from app.modules.apps.service import RoleService
from app.modules.auth.dependencies import get_current_platform_admin
from app.modules.users.models import User
from app.modules.users.schemas import (
    BulkRoleAssignmentResult,
    BulkStatusUpdate,
    BulkUserIds,
    BulkUserStatusResult,
    UserAdminRead,
    UserStatusUpdate,
)
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
    limit: int = Query(default=100, ge=1, le=250),
    offset: int = Query(default=0, ge=0),
    is_active: bool | None = Query(default=None),
    search: str | None = Query(default=None, description="Case-insensitive substring match against email or full name."),
    include_deleted: bool = Query(default=False, description="Include soft-deleted users (excluded by default)."),
    db: AsyncSession = Depends(get_db),
):
    """Returns users, ordered by email. Excludes soft-deleted users unless `include_deleted=true`."""
    return await UserService.list_users(
        db,
        include_deleted=include_deleted,
        is_active=is_active,
        search=search,
        limit=limit,
        offset=offset,
    )


# Bulk routes are declared before the "/{user_id}/..." routes below: they share
# the same path shape (e.g. "/bulk/status" vs "/{user_id}/status"), and FastAPI/
# Starlette matches in declaration order without backtracking on a UUID parse
# failure, so the dynamic routes would otherwise swallow these requests first.
@router.patch(
    "/bulk/status",
    response_model=BulkUserStatusResult,
    summary="Bulk enable or disable users",
    responses={400: {"model": ErrorDetail, "description": "Your own account was included in a bulk deactivation."}},
)
async def bulk_update_user_status(
    payload: BulkStatusUpdate,
    current_admin: User = Depends(get_current_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """Sets `is_active` for every listed user id in one call (1-500 ids per request). Ids that don't match any user are reported in `not_found_ids`, not silently dropped. Your own account can't be included when deactivating (whole batch rejected) — only a direct SQL change can do that."""
    if not payload.is_active and current_admin.id in payload.user_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Your own account cannot be included in a bulk deactivation",
        )

    updated, not_found_ids = await UserService.bulk_set_active_status(db, payload.user_ids, payload.is_active)
    return BulkUserStatusResult(updated=updated, not_found_ids=not_found_ids)


@router.post(
    "/bulk/delete",
    response_model=BulkUserStatusResult,
    summary="Bulk soft-delete users",
    responses={400: {"model": ErrorDetail, "description": "Your own account was included in the bulk delete."}},
)
async def bulk_delete_users(
    payload: BulkUserIds,
    current_admin: User = Depends(get_current_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """Sets `deleted_at` and `is_active=false` for every listed user id (1-500 ids per request). Ids that don't match any user are reported in `not_found_ids`, not silently dropped. Your own account can't be included (whole batch rejected)."""
    if current_admin.id in payload.user_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Your own account cannot be included in a bulk delete",
        )

    updated, not_found_ids = await UserService.bulk_soft_delete(db, payload.user_ids)
    return BulkUserStatusResult(updated=updated, not_found_ids=not_found_ids)


@router.post(
    "/bulk/global-roles/{role_id}/grant",
    response_model=BulkRoleAssignmentResult,
    summary="Bulk grant a global role to users",
    responses={404: {"model": ErrorDetail, "description": "Global role not found."}},
)
async def bulk_grant_global_role(
    role_id: UUID,
    payload: BulkUserIds,
    db: AsyncSession = Depends(get_db),
):
    """Grants the role to every listed user id in one call (1-500 ids per request) — unlocks any app that requires this role for all of them at once. Idempotent per user. Ids that don't match any user are reported in `not_found_ids`, not silently dropped (and no longer fail the whole batch)."""
    role = await db.get(GlobalRole, role_id)

    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Global role not found")

    updated_user_ids, not_found_ids = await AccessService.bulk_assign_global_role(db, payload.user_ids, role_id)
    return BulkRoleAssignmentResult(updated_user_ids=updated_user_ids, not_found_ids=not_found_ids)


@router.post(
    "/bulk/global-roles/{role_id}/revoke",
    response_model=BulkRoleAssignmentResult,
    summary="Bulk revoke a global role from users",
)
async def bulk_revoke_global_role(
    role_id: UUID,
    payload: BulkUserIds,
    db: AsyncSession = Depends(get_db),
):
    """Revokes the role from every listed user id in one call (1-500 ids per request). Ids that don't match any user are reported in `not_found_ids`, not silently dropped."""
    updated_user_ids, not_found_ids = await AccessService.bulk_revoke_global_role(db, payload.user_ids, role_id)
    return BulkRoleAssignmentResult(updated_user_ids=updated_user_ids, not_found_ids=not_found_ids)


@router.post(
    "/bulk/applications/{application_id}/grant",
    response_model=BulkRoleAssignmentResult,
    summary="Bulk grant direct access to an application",
    responses={
        404: {"model": ErrorDetail, "description": "Application not found."},
        409: {"model": ErrorDetail, "description": "SSO applications require an app-scoped role assignment."},
    },
)
async def bulk_grant_application_access(
    application_id: UUID,
    payload: BulkUserIds,
    db: AsyncSession = Depends(get_db),
):
    """Grants every listed user direct access to a catalog application (1-500 ids per request). SSO applications reject this endpoint because a per-app role is required to launch and authenticate."""
    application = await db.get(Application, application_id)

    if application is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")
    if application.access_policy == ApplicationAccessPolicy.SSO_ROLE.value:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="SSO applications require app-scoped role assignments")

    updated_user_ids, not_found_ids = await AccessService.bulk_grant_application_access(db, payload.user_ids, application_id)
    return BulkRoleAssignmentResult(updated_user_ids=updated_user_ids, not_found_ids=not_found_ids)


@router.post(
    "/bulk/applications/{application_id}/revoke",
    response_model=BulkRoleAssignmentResult,
    summary="Bulk revoke direct access to an application",
)
async def bulk_revoke_application_access(
    application_id: UUID,
    payload: BulkUserIds,
    db: AsyncSession = Depends(get_db),
):
    """Revokes direct access for every listed user id (1-500 ids per request)."""
    updated_user_ids, not_found_ids = await AccessService.bulk_revoke_application_access(db, payload.user_ids, application_id)
    return BulkRoleAssignmentResult(updated_user_ids=updated_user_ids, not_found_ids=not_found_ids)


@router.patch(
    "/{user_id}/status",
    response_model=UserAdminRead,
    summary="Enable or disable a single user",
    responses={
        404: {"model": ErrorDetail, "description": "User not found."},
        400: {"model": ErrorDetail, "description": "Caller tried to deactivate their own account."},
    },
)
async def update_user_status(
    user_id: UUID,
    payload: UserStatusUpdate,
    current_admin: User = Depends(get_current_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """
    Sets `is_active`. New users (self-registered or via Microsoft) start inactive by default — this is
    how a platform admin turns on access. Setting it false immediately blocks every authenticated call
    the user makes (they can still complete login itself, but every subsequent call 403s). An admin can't
    deactivate their own account this way — only a direct SQL change can do that.
    """
    if user_id == current_admin.id and not payload.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account",
        )

    user = await UserService.get_user_by_id(db, user_id)

    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return await UserService.set_active_status(db, user, payload.is_active)


@router.delete(
    "/{user_id}",
    response_model=UserAdminRead,
    summary="Soft-delete a single user",
    responses={
        404: {"model": ErrorDetail, "description": "User not found."},
        400: {"model": ErrorDetail, "description": "Caller tried to delete their own account."},
    },
)
async def delete_user(
    user_id: UUID,
    current_admin: User = Depends(get_current_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """Sets `deleted_at` and `is_active=false`. The row is kept (not hard-deleted) but excluded from the default `GET /users` listing and can no longer authenticate. An admin can't soft-delete their own account this way — only a direct SQL change can do that."""
    if user_id == current_admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )

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


@router.get(
    "/{user_id}/global-roles",
    response_model=list[GlobalRoleRead],
    summary="List a user's assigned global roles",
    responses={404: {"model": ErrorDetail, "description": "User not found."}},
)
async def list_user_global_roles(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Returns the global roles currently held by one user. These only affect catalog application access."""
    user = await UserService.get_user_by_id(db, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return await AccessService.list_global_roles_for_user(db, user_id)


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


@router.post(
    "/{user_id}/applications/{application_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Grant a single user direct access to an application",
    responses={
        404: {"model": ErrorDetail, "description": "User not found, or application not found."},
        409: {"model": ErrorDetail, "description": "SSO applications require an app-scoped role assignment."},
    },
)
async def grant_application_access(
    user_id: UUID,
    application_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Grants direct access to a launcher-only catalog application. For an SSO application use `POST /apps/{client_id}/roles/{role_id}/assign`; that role grants both launcher visibility and SSO access."""
    user = await UserService.get_user_by_id(db, user_id)

    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    application = await db.get(Application, application_id)

    if application is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")
    if application.access_policy == ApplicationAccessPolicy.SSO_ROLE.value:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="SSO applications require app-scoped role assignments")

    await AccessService.grant_application_access(db, user_id, application_id)


@router.delete(
    "/{user_id}/applications/{application_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a single user's direct access to an application",
)
async def revoke_application_access(
    user_id: UUID,
    application_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Revokes the direct grant. No-op if it doesn't exist."""
    await AccessService.revoke_application_access(db, user_id, application_id)


@router.get(
    "/{user_id}/app-roles",
    response_model=list[AppRoleRead],
    summary="List every (app, role) pair a user holds across all SSO apps",
    responses={404: {"model": ErrorDetail, "description": "User not found."}},
)
async def list_user_app_roles(
    user_id: UUID,
    limit: int = Query(default=100, ge=1, le=250),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """Cross-app view: every SSO app this user has a role in, and which role. Complements the per-app GET /apps/{client_id}/users listing."""
    user = await UserService.get_user_by_id(db, user_id)

    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    rows = await RoleService.list_app_roles_for_user(db, user_id, limit=limit, offset=offset)

    return [
        AppRoleRead(app_id=app_id, client_id=client_id, app_name=app_name, role_id=role_id, role_name=role_name)
        for app_id, client_id, app_name, role_id, role_name in rows
    ]


@router.get(
    "/{user_id}/applications",
    response_model=list[AuthorizedApplicationRead],
    summary="List every application a user can currently see",
    responses={404: {"model": ErrorDetail, "description": "User not found."}},
)
async def list_user_applications(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Admin view of one user's launcher: catalog apps resolve through global/direct grants and SSO apps resolve through app-scoped roles, exactly as `GET /applications` does."""
    user = await UserService.get_user_by_id(db, user_id)

    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    apps = await AccessService.authorized_applications(db, user_id)

    return [
        {"id": str(app.id), "slug": app.slug, "name": app.name, "description": app.description, "url": app.url, "icon": app.icon, "access_policy": app.access_policy}
        for app in apps
    ]
