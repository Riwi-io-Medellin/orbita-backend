import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.config.settings import settings
from app.modules.access.models import Application
from app.modules.access.service import AccessService
from app.modules.auth.dependencies import get_current_user
from app.modules.sso.schemas import SSOExchangeRequest, SSOExchangeResponse
from app.modules.sso.service import SSOService
from app.modules.users.models import User

router = APIRouter(prefix="/sso", tags=["Single sign-on"])


@router.get("/authorize")
async def authorize(
    request: Request,
    client_id: str = Query(min_length=3, max_length=120),
    redirect_uri: str = Query(min_length=1, max_length=2048),
    state: str = Query(min_length=8, max_length=1024),
    db: AsyncSession = Depends(get_db),
):
    client = await SSOService.get_client(db, client_id)
    if client is None or not secrets.compare_digest(redirect_uri, client.redirect_uri):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown client or redirect URI")

    try:
        current_user = await get_current_user(request, db)
    except HTTPException as exc:
        if exc.status_code != status.HTTP_401_UNAUTHORIZED:
            raise
        login_url = f"{settings.frontend_url}/auth?{urlencode({'continue': str(request.url)})}"
        return RedirectResponse(url=login_url, status_code=status.HTTP_302_FOUND)

    application = await db.get(Application, client.application_id)
    if application is None or not application.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Application is unavailable")
    roles = await SSOService.user_role_keys(db, current_user.id, application.id)
    if not roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not authorized for this application")

    code = await SSOService.create_authorization_code(
        db,
        client=client,
        user=current_user,
        redirect_uri=redirect_uri,
    )
    await AccessService.audit(
        db,
        event="sso.authorize",
        user_id=current_user.id,
        application_id=application.id,
        details={"client_id": client.client_id},
    )
    return RedirectResponse(url=f"{redirect_uri}?{urlencode({'code': code, 'state': state})}", status_code=status.HTTP_302_FOUND)


@router.post("/token", response_model=SSOExchangeResponse)
async def exchange_authorization_code(payload: SSOExchangeRequest, db: AsyncSession = Depends(get_db)):
    user, application, roles = await SSOService.exchange_code(
        db,
        code=payload.code,
        client_id=payload.client_id,
        client_secret=payload.client_secret,
        redirect_uri=payload.redirect_uri,
    )
    await AccessService.audit(
        db,
        event="sso.exchange",
        user_id=user.id,
        application_id=application.id,
        details={"client_id": payload.client_id},
    )
    return {
        "user": {"id": str(user.id), "email": user.email, "name": user.full_name},
        "application": {"id": str(application.id), "slug": application.slug, "name": application.name},
        "roles": roles,
    }
