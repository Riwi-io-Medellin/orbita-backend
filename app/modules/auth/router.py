from fastapi import APIRouter, Request

from app.modules.users.models import User

from app.modules.auth.microsoft import oauth

from app.modules.auth.dependencies import get_current_user

from fastapi import Depends

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.modules.users.service import UserService

from app.modules.auth.jwt import create_access_token

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

@router.get("/callback", name="auth_callback")
async def auth_callback(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    token = await oauth.microsoft.authorize_access_token(request)

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

    return {
        "access_token": access_token,
        "token_type": "Bearer",
    }

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