from fastapi import APIRouter, Request

from app.config.settings import settings

from app.modules.users.models import User

from app.modules.auth.microsoft import oauth

from app.modules.auth.dependencies import get_current_user

from fastapi import Depends

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.modules.users.service import UserService

from app.modules.auth.jwt import create_access_token

from fastapi.responses import RedirectResponse

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.get("/login")
async def login(request: Request):
    redirect_uri = request.url_for("auth_callback")

    return await oauth.microsoft.authorize_redirect(
        request,
        redirect_uri,
    )

@router.post("/logout")
async def logout():

    response = JSONResponse(
        content={
            "message": "Logged out"
        }
    )

    response.delete_cookie(
        key="access_token",
        httponly=True,
        secure=True,  # Put true in Production
        samesite="lax",
    )

    return response

@router.get("/callback", name="auth_callback")
async def auth_callback(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    try:
        token = await oauth.microsoft.authorize_access_token(request)
    except Exception:
        return RedirectResponse(
            url=f"{settings.frontend_url}/auth/callback?error=authentication_failed"
        )

    microsoft_user = token["userinfo"]

    user = await UserService.upsert(
        db=db,
        microsoft_id=microsoft_user["oid"],
        email=microsoft_user["preferred_username"],
        full_name=microsoft_user["name"],
    )

    access_token = create_access_token(
        user_id=str(user.id),
        email=user.email,
    )

    response = RedirectResponse(
        url=f"{settings.frontend_url}/auth/callback",
        status_code=302,
    )

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True, # Change this line to True in Production
        samesite="lax",
        path="/",
        max_age=60 * settings.jwt_expire_minutes,
    )
    return response

@router.get("/me")
async def me(
    current_user: User = Depends(get_current_user),
):
    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "name": current_user.full_name,
        "active": current_user.is_active,
    }