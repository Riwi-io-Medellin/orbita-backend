from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.modules.access.models import (
    Application,
    ApplicationAccessRole,
    ApplicationClient,
    AuditLog,
    user_application_access_roles,
)
from app.modules.access.service import AccessService
from app.modules.auth.dependencies import get_current_user
from app.modules.sso.schemas import (
    ApplicationCreateRequest,
    ApplicationRoleRequest,
    UserApplicationRoleAssignmentRequest,
)
from app.modules.sso.service import SSOService
from app.modules.users.models import User

router = APIRouter(prefix="/applications", tags=["Applications"])


async def require_orbita_admin(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    if "admin" not in await AccessService.role_names(db, current_user.id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Orbita admin access required")
    return current_user


@router.get("/")
async def list_applications(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    apps = await AccessService.authorized_applications(db, current_user.id)
    return [{"id": str(app.id), "slug": app.slug, "name": app.name, "description": app.description, "url": app.url, "icon": app.icon} for app in apps]


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_application(
    payload: ApplicationCreateRequest,
    _: User = Depends(require_orbita_admin),
    db: AsyncSession = Depends(get_db),
):
    if await db.scalar(select(Application.id).where(Application.slug == payload.slug)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Application slug already exists")
    if await db.scalar(select(ApplicationClient.id).where(ApplicationClient.client_id == payload.client_id)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Client ID already exists")

    application = Application(
        slug=payload.slug,
        name=payload.name,
        description=payload.description,
        url=payload.url,
        icon=payload.icon,
    )
    client_secret, client_secret_hash = SSOService.generate_client_secret()
    db.add(application)
    await db.flush()
    db.add(ApplicationClient(
        application_id=application.id,
        client_id=payload.client_id,
        client_secret_hash=client_secret_hash,
        redirect_uri=payload.redirect_uri,
    ))
    await db.commit()

    return {
        "id": str(application.id),
        "slug": application.slug,
        "client_id": payload.client_id,
        "client_secret": client_secret,
        "redirect_uri": payload.redirect_uri,
        "warning": "Store client_secret in the application's Railway variables now; it will not be shown again.",
    }


@router.post("/{application_id}/roles", status_code=status.HTTP_201_CREATED)
async def create_application_role(
    application_id: UUID,
    payload: ApplicationRoleRequest,
    _: User = Depends(require_orbita_admin),
    db: AsyncSession = Depends(get_db),
):
    if await db.get(Application, application_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")
    existing = await db.get(ApplicationAccessRole, {"application_id": application_id, "key": payload.key})
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Application role already exists")
    role = ApplicationAccessRole(application_id=application_id, key=payload.key, name=payload.name, description=payload.description)
    db.add(role)
    await db.commit()
    return {"application_id": str(application_id), "key": role.key, "name": role.name, "description": role.description}


@router.get("/{application_id}/roles")
async def list_application_roles(
    application_id: UUID,
    _: User = Depends(require_orbita_admin),
    db: AsyncSession = Depends(get_db),
):
    roles = await db.scalars(
        select(ApplicationAccessRole)
        .where(ApplicationAccessRole.application_id == application_id)
        .order_by(ApplicationAccessRole.key)
    )
    return [{"key": role.key, "name": role.name, "description": role.description} for role in roles]


@router.put("/{application_id}/users/{user_id}/roles", status_code=status.HTTP_204_NO_CONTENT)
async def assign_user_application_roles(
    application_id: UUID,
    user_id: UUID,
    payload: UserApplicationRoleAssignmentRequest,
    _: User = Depends(require_orbita_admin),
    db: AsyncSession = Depends(get_db),
):
    if await db.get(Application, application_id) is None or await db.get(User, user_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application or user not found")
    valid_roles = set(await db.scalars(
        select(ApplicationAccessRole.key).where(
            ApplicationAccessRole.application_id == application_id,
            ApplicationAccessRole.key.in_(set(payload.role_keys)),
        )
    ))
    if valid_roles != set(payload.role_keys):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="One or more application roles do not exist")

    await db.execute(delete(user_application_access_roles).where(
        user_application_access_roles.c.user_id == user_id,
        user_application_access_roles.c.application_id == application_id,
    ))
    await db.execute(user_application_access_roles.insert(), [
        {"user_id": user_id, "application_id": application_id, "role_key": role_key}
        for role_key in valid_roles
    ])
    await db.commit()


@router.post("/{application_id}/access", status_code=status.HTTP_204_NO_CONTENT)
async def register_application_access(
    application_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
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


@router.get("/audit")
async def list_audit_logs(
    limit: int = Query(default=100, ge=1, le=250),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    roles = await AccessService.role_names(db, current_user.id)
    if "admin" not in roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    result = await db.execute(
        select(AuditLog, User.full_name, User.email, Application.name)
        .outerjoin(User, AuditLog.user_id == User.id)
        .outerjoin(Application, AuditLog.application_id == Application.id)
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
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
