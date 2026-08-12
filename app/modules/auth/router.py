from fastapi import APIRouter, Request

from app.config.settings import settings

from app.modules.users.models import User

from app.modules.auth.microsoft import oauth, ms_claims_options

from app.modules.auth.dependencies import get_current_user

from fastapi import Depends

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.modules.users.service import UserService

from app.modules.auth.jwt import create_access_token
from app.modules.access.service import AccessService
from app.modules.auth.passwords import verify_password
from app.modules.auth.schemas import PasswordLoginRequest

from fastapi.responses import RedirectResponse, JSONResponse

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


def session_cookie_options() -> dict[str, bool | str]:
    is_production = settings.environment == "production"
    return {
        "secure": is_production,
        "samesite": "none" if is_production else "lax",
    }


def authenticated_response(access_token: str) -> JSONResponse:
    response = JSONResponse(content={"message": "Authenticated"})
    response.set_cookie(key="access_token", value=access_token, httponly=True, **session_cookie_options(), path="/", max_age=60 * settings.jwt_expire_minutes)
    return response


@router.get("/login")
async def login(request: Request):
    return await oauth.microsoft.authorize_redirect(
        request,
        settings.microsoft_redirect_uri,
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
        **session_cookie_options(),
    )

    return response

@router.get("/callback", name="auth_callback")
async def auth_callback(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    try:
        token = await oauth.microsoft.authorize_access_token(
            request,
            claims_options=ms_claims_options,
        )
    except Exception as exc:
        print(f"Microsoft OAuth callback failed: {exc!r}")
        return RedirectResponse(
            url=f"{settings.frontend_url}/auth/callback?error=authentication_failed"
        )

    microsoft_user = token["userinfo"]

    try:
        user = await UserService.upsert(
            db=db,
            microsoft_id=microsoft_user["oid"],
            email=microsoft_user["preferred_username"],
            full_name=microsoft_user["name"],
        )
    except Exception as exc:
        print(f"Microsoft OAuth user upsert failed: {exc!r}")
        return RedirectResponse(
            url=f"{settings.frontend_url}/auth/callback?error=authentication_failed"
        )

    await AccessService.ensure_default_role(db, user)

    access_token = create_access_token(
        user_id=str(user.id),
        email=user.email,
        roles=await AccessService.role_names(db, user.id),
    )


    await AccessService.audit(db, event="login", user_id=user.id, request=request)

    response = RedirectResponse(
        url=f"{settings.frontend_url}/auth/callback",
        status_code=302,
    )

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        **session_cookie_options(),
        path="/",
        max_age=60 * settings.jwt_expire_minutes,
    )
    return response


@router.post("/login")
async def password_login(payload: PasswordLoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    user = await UserService.get_by_email(db, str(payload.email))
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        await AccessService.audit(db, event="login.password_failed", request=request, details={"email": str(payload.email)})
        return JSONResponse(status_code=401, content={"detail": "Correo o contraseña inválidos"})
    roles = await AccessService.role_names(db, user.id)
    await AccessService.audit(db, event="login", user_id=user.id, request=request)
    return authenticated_response(create_access_token(user_id=str(user.id), email=user.email, roles=roles))

@router.get("/me")
async def me(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    roles = await AccessService.role_names(db, current_user.id)
    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "name": current_user.full_name,
        "roles": roles,
        "role": roles[0] if roles else None,
        "active": current_user.is_active,
    }
