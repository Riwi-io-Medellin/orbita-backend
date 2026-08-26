from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.modules.access.models import Application, ApplicationAccessPolicy, AuditLog, GlobalRole
from app.modules.access.schemas import (
    ApplicationCreate,
    ApplicationRead,
    ApplicationStatusUpdate,
    AuditLogRead,
    AuthorizedApplicationRead,
    GlobalRoleRead,
)
from app.modules.access.service import AccessService
from app.modules.apps.application_lifecycle import ApplicationLifecycleService
from app.modules.auth.dependencies import get_current_platform_admin, get_current_user
from app.modules.users.models import User
from app.schemas import ErrorDetail

router = APIRouter(
    prefix="/applications",
    tags=["Applications"],
    responses={
        401: {"model": ErrorDetail, "description": "No/invalid session cookie."},
        403: {"model": ErrorDetail, "description": "User is inactive (or, on admin-only routes, not a platform admin)."},
    },
)


@router.get("/", response_model=list[AuthorizedApplicationRead], summary="List apps the current user can see")
async def list_applications(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """The launcher. Catalog apps require a global/direct grant; SSO apps require an app-scoped role."""
    apps = await AccessService.authorized_applications(db, current_user.id)
    return [{"id": str(app.id), "slug": app.slug, "name": app.name, "description": app.description, "url": app.url, "icon": app.icon, "access_policy": app.access_policy} for app in apps]


@router.post(
    "/{application_id}/access",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Record that the user opened an app",
    responses={404: {"model": ErrorDetail, "description": "Application not found or not authorized for this user."}},
)
async def register_application_access(
    application_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Writes an `application.access` audit log row. Call this from the frontend when the user actually clicks into an app from the launcher."""
    applications = await AccessService.authorized_applications(db, current_user.id)
    application = next((item for item in applications if item.id == application_id), None)
    if application is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not available")

    await AccessService.audit(
        db,
        event="application.access",
        user_id=current_user.id,
        application_id=application.id,
        details={"application_slug": application.slug},
    )


@router.post(
    "/",
    response_model=ApplicationRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(get_current_platform_admin)],
    summary="Register a launcher tile for an app",
    responses={409: {"model": ErrorDetail, "description": "slug already registered."}},
)
async def create_application(
    payload: ApplicationCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Creates a launcher-only entry for systems that do not use SSO. For an integrated application, use
    `POST /apps`, which creates the launcher tile and SSO client together. New launcher-only apps start
    with zero users able to see them until an
    admin grants a global role via `POST /applications/{id}/roles/{role_id}`.
    """
    existing = await db.scalar(select(Application).where(Application.slug == payload.slug))
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="slug already registered")

    try:
        return await ApplicationLifecycleService.create_catalog_application(
            db,
            slug=payload.slug,
            name=payload.name,
            description=payload.description,
            url=payload.url,
            icon=payload.icon,
        )
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="slug already registered")


@router.patch(
    "/{application_id}/status",
    response_model=ApplicationRead,
    dependencies=[Depends(get_current_platform_admin)],
    summary="Enable or disable a launcher tile",
    responses={404: {"model": ErrorDetail, "description": "Application not found."}},
)
async def update_application_status(
    application_id: UUID,
    payload: ApplicationStatusUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Toggling `is_active` to false hides this app from every user's launcher immediately. If it has an SSO client, that client is disabled in the same transaction."""
    application = await db.get(Application, application_id)
    if application is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")

    updated_application, _ = await ApplicationLifecycleService.set_availability(
        db, application=application, is_active=payload.is_active,
    )
    return updated_application


@router.get(
    "/global-roles",
    response_model=list[GlobalRoleRead],
    dependencies=[Depends(get_current_platform_admin)],
    summary="List the fixed global roles",
)
async def list_global_roles(
    db: AsyncSession = Depends(get_db),
):
    """Returns the fixed seeded set (admin/staff/coder) used to gate launcher visibility. Not user-editable — grant/revoke them per user or per app instead."""
    return await AccessService.list_global_roles(db)


@router.post(
    "/{application_id}/roles/{global_role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(get_current_platform_admin)],
    summary="Grant a global role access to an app",
    responses={
        404: {"model": ErrorDetail, "description": "Application not found, or global role not found."},
        409: {"model": ErrorDetail, "description": "SSO applications require an app-scoped role assignment."},
    },
)
async def grant_application_role(
    application_id: UUID,
    global_role_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Links a global role to a launcher-only app. SSO apps are role-provisioned through `/apps/{client_id}/roles/{role_id}/assign` instead."""
    application = await db.get(Application, application_id)
    if application is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")
    if application.access_policy == ApplicationAccessPolicy.SSO_ROLE.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="SSO applications require app-scoped role assignments",
        )

    role = await db.get(GlobalRole, global_role_id)
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Global role not found")

    await AccessService.grant_application_role(db, application_id, global_role_id)


@router.delete(
    "/{application_id}/roles/{global_role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(get_current_platform_admin)],
    summary="Revoke a global role's access to an app",
)
async def revoke_application_role(
    application_id: UUID,
    global_role_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Unlinks the role from the app. Users who only had access via this role stop seeing the app in their launcher. No-op if the link doesn't exist."""
    await AccessService.revoke_application_role(db, application_id, global_role_id)


@router.get(
    "/audit",
    response_model=list[AuditLogRead],
    dependencies=[Depends(get_current_platform_admin)],
    summary="List platform audit log entries",
)
async def list_audit_logs(
    limit: int = Query(default=100, ge=1, le=250),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """Most-recent-first feed of login attempts, app access, and registration events. Platform-admin only."""
    result = await db.execute(
        select(AuditLog, User.full_name, User.email, Application.name)
        .outerjoin(User, AuditLog.user_id == User.id)
        .outerjoin(Application, AuditLog.application_id == Application.id)
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
        .offset(offset)
    )

    return [
        {
            "id": str(log.id),
            "event": log.event,
            "user_name": full_name,
            "user_email": email,
            "application_name": application_name,
            "ip_address": log.ip_address,
            "details": log.details,
            "created_at": log.created_at,
        }
        for log, full_name, email, application_name in result.all()
    ]
