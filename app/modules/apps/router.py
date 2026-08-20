from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.modules.auth.dependencies import get_current_platform_admin
from app.modules.apps.schemas import (
    AppCreate,
    AppCreated,
    AppRead,
    AppStatusUpdate,
    RedirectURICreate,
    RedirectURIRead,
    RoleAssign,
    RoleCreate,
    RoleRead,
    UserAppRoleRead,
)
from app.modules.apps.service import AppService, RoleService
from app.modules.users.schemas import BulkRoleAssignmentResult, BulkUserIds
from app.schemas import ErrorDetail

router = APIRouter(
    prefix="/apps",
    tags=["Apps"],
    dependencies=[Depends(get_current_platform_admin)],
    responses={
        401: {"model": ErrorDetail, "description": "No/invalid session cookie."},
        403: {"model": ErrorDetail, "description": "Caller is not a platform admin."},
    },
)


@router.post(
    "/",
    response_model=AppCreated,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new SSO app",
    responses={409: {"model": ErrorDetail, "description": "client_id already registered."}},
)
async def create_app(
    payload: AppCreate,
    db: AsyncSession = Depends(get_db),
):
    """Registers a new external app allowed to use Orbita SSO. Generates and returns the client_secret once — it is only ever stored as a hash, so save it now."""
    existing = await AppService.get_by_client_id(db, payload.client_id)

    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="client_id already registered",
        )

    existing_application = await AppService.get_catalog_application_by_slug(db, payload.slug)
    if existing_application is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="slug already registered",
        )

    try:
        app, raw_secret = await AppService.create_app(
            db,
            client_id=payload.client_id,
            slug=payload.slug,
            name=payload.name,
            description=payload.description,
            url=payload.url,
            icon=payload.icon,
        )
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="client_id already registered",
        )

    return AppCreated(
        id=app.id,
        application_id=app.application_id,
        client_id=app.client_id,
        name=app.name,
        is_active=app.is_active,
        client_secret=raw_secret,
    )


@router.get("/", response_model=list[AppRead], summary="List registered SSO apps")
async def list_apps(
    limit: int = Query(default=100, ge=1, le=250),
    offset: int = Query(default=0, ge=0),
    is_active: bool | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    """Returns apps registered for SSO, ordered by name."""
    return await AppService.list_apps(db, is_active=is_active, limit=limit, offset=offset)


@router.patch(
    "/{client_id}",
    response_model=AppRead,
    summary="Enable or disable an app's SSO access",
    responses={404: {"model": ErrorDetail, "description": "App not found."}},
)
async def update_app_status(
    client_id: str,
    payload: AppStatusUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Toggling `is_active` to false immediately blocks `/auth/authorize` for this app (existing per-app JWTs already issued still work until they expire, unless the app calls `/auth/introspect`)."""
    app = await AppService.get_by_client_id(db, client_id)

    if app is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="App not found",
        )

    return await AppService.set_active_status(db, app, payload.is_active)


@router.post(
    "/{client_id}/redirect-uris",
    response_model=RedirectURIRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register an allowed redirect URI for an app",
    responses={
        404: {"model": ErrorDetail, "description": "App not found."},
        409: {"model": ErrorDetail, "description": "This redirect_uri is already registered for this app."},
    },
)
async def add_redirect_uri(
    client_id: str,
    payload: RedirectURICreate,
    db: AsyncSession = Depends(get_db),
):
    """Adds a URI this app is allowed to receive the SSO one-time code at. `/auth/authorize` rejects any redirect_uri not registered here."""
    app = await AppService.get_by_client_id(db, client_id)

    if app is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="App not found",
        )

    try:
        return await AppService.add_redirect_uri(db, app, payload.redirect_uri)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This redirect_uri is already registered for this app",
        )


@router.post(
    "/{client_id}/roles",
    response_model=RoleRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a role for an app",
    responses={
        404: {"model": ErrorDetail, "description": "App not found."},
        409: {"model": ErrorDetail, "description": "A role with this name already exists for this app."},
    },
)
async def create_role(
    client_id: str,
    payload: RoleCreate,
    db: AsyncSession = Depends(get_db),
):
    """Creates a role scoped to one app (e.g. "staff", "coder", "admin") that users can be assigned. Role names only need to be unique within the same app."""
    app = await AppService.get_by_client_id(db, client_id)

    if app is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="App not found",
        )

    existing = await RoleService.get_by_app_and_name(db, app, payload.name)

    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Role already exists for this app",
        )

    try:
        return await RoleService.create_role(db, app, payload.name)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Role already exists for this app",
        )


@router.post(
    "/{client_id}/roles/{role_id}/assign",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Assign a role to a user for this app",
    responses={404: {"model": ErrorDetail, "description": "App not found, or role not found for this app."}},
)
async def assign_role(
    client_id: str,
    role_id: UUID,
    payload: RoleAssign,
    db: AsyncSession = Depends(get_db),
):
    """Grants the user this app-scoped role. Idempotent — assigning a role the user already has is a no-op. A user needs at least one role here before `/auth/authorize`/`/auth/token` will issue them a token for this app."""
    app = await AppService.get_by_client_id(db, client_id)

    if app is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="App not found",
        )

    role = await RoleService.get_role_by_id(db, app, role_id)

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found",
        )

    await RoleService.assign_role_to_user(db, payload.user_id, app, role)


@router.post(
    "/{client_id}/roles/{role_id}/assign/bulk",
    response_model=BulkRoleAssignmentResult,
    summary="Bulk assign a role to users for this app",
    responses={404: {"model": ErrorDetail, "description": "App not found, or role not found for this app."}},
)
async def bulk_assign_role(
    client_id: str,
    role_id: UUID,
    payload: BulkUserIds,
    db: AsyncSession = Depends(get_db),
):
    """Grants this app-scoped role to every listed user id (1-500 ids per request). Idempotent per user. Ids that don't match any user are reported in `not_found_ids`, not silently dropped."""
    app = await AppService.get_by_client_id(db, client_id)

    if app is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="App not found",
        )

    role = await RoleService.get_role_by_id(db, app, role_id)

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found",
        )

    updated_ids, not_found_ids = await RoleService.bulk_assign_role_to_users(db, payload.user_ids, app, role)
    return BulkRoleAssignmentResult(updated_user_ids=updated_ids, not_found_ids=not_found_ids)


@router.post(
    "/{client_id}/roles/{role_id}/unassign/bulk",
    response_model=BulkRoleAssignmentResult,
    summary="Bulk unassign a role from users for this app",
    responses={404: {"model": ErrorDetail, "description": "App not found, or role not found for this app."}},
)
async def bulk_unassign_role(
    client_id: str,
    role_id: UUID,
    payload: BulkUserIds,
    db: AsyncSession = Depends(get_db),
):
    """Removes this app-scoped role from every listed user id (1-500 ids per request)."""
    app = await AppService.get_by_client_id(db, client_id)

    if app is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="App not found",
        )

    role = await RoleService.get_role_by_id(db, app, role_id)

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found",
        )

    updated_ids, not_found_ids = await RoleService.bulk_unassign_role_from_users(db, payload.user_ids, app, role)
    return BulkRoleAssignmentResult(updated_user_ids=updated_ids, not_found_ids=not_found_ids)


@router.get(
    "/{client_id}/roles",
    response_model=list[RoleRead],
    summary="List an app's roles",
    responses={404: {"model": ErrorDetail, "description": "App not found."}},
)
async def list_roles(
    client_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Returns every role defined for this app."""
    app = await AppService.get_by_client_id(db, client_id)

    if app is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="App not found",
        )

    return await RoleService.list_for_app(db, app)


@router.delete(
    "/{client_id}/roles/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a role from an app",
    responses={404: {"model": ErrorDetail, "description": "App not found, or role not found for this app."}},
)
async def delete_role(
    client_id: str,
    role_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Deletes the role. Cascades: also deletes every UserAppRole assignment referencing it, so any user who only had this role loses access to the app."""
    app = await AppService.get_by_client_id(db, client_id)

    if app is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="App not found",
        )

    role = await RoleService.get_role_by_id(db, app, role_id)

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found",
        )

    await RoleService.delete_role(db, role)


@router.delete(
    "/{client_id}/roles/{role_id}/assign",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Unassign a role from a user for this app",
    responses={404: {"model": ErrorDetail, "description": "App not found, or role not found for this app."}},
)
async def unassign_role(
    client_id: str,
    role_id: UUID,
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Removes this app-scoped role from the user (query param `user_id`). If it was their only role for this app, they lose access to it until re-assigned."""
    app = await AppService.get_by_client_id(db, client_id)

    if app is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="App not found",
        )

    role = await RoleService.get_role_by_id(db, app, role_id)

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found",
        )

    await RoleService.unassign_role_from_user(db, user_id, app, role)


@router.get(
    "/{client_id}/users",
    response_model=list[UserAppRoleRead],
    summary="List users with a role in this app",
    responses={404: {"model": ErrorDetail, "description": "App not found."}},
)
async def list_app_users(
    client_id: str,
    limit: int = Query(default=100, ge=1, le=250),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """One row per (user, role) pair — a user with two roles in this app appears twice."""
    app = await AppService.get_by_client_id(db, client_id)

    if app is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="App not found",
        )

    rows = await RoleService.list_user_roles_for_app(db, app, limit=limit, offset=offset)

    return [
        UserAppRoleRead(user_id=user_id, email=email, full_name=full_name, role_name=role_name)
        for user_id, email, full_name, role_name in rows
    ]
