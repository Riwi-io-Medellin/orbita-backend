from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.modules.access.models import Application, AuditLog
from app.modules.access.service import AccessService
from app.modules.auth.dependencies import get_current_user
from app.modules.users.models import User

router = APIRouter(prefix="/applications", tags=["Applications"])


@router.get("/")
async def list_applications(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    apps = await AccessService.authorized_applications(db, current_user.id)
    return [{"id": str(app.id), "slug": app.slug, "name": app.name, "description": app.description, "url": app.url, "icon": app.icon} for app in apps]


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
