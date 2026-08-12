from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, status

from app.config.settings import settings

from app.modules.users.models import User

from app.modules.auth.microsoft import oauth, ms_claims_options

from app.modules.auth.dependencies import get_current_user

from fastapi import Depends

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.modules.users.service import UserService

from app.modules.apps.service import AppService, RoleService

from app.modules.auth.jwt import (
    APP_TOKEN_EXPIRE_MINUTES,
    create_access_token,
    create_app_token,
    decode_access_token,
    decode_app_token,
)
from app.modules.auth.schemas import (
    IntrospectRequest,
    IntrospectResponse,
    TokenExchangeRequest,
    TokenResponse,
)
from app.modules.auth.service import (
    AppSessionService,
    AuthorizationCodeService,
    build_authorize_redirect,
)

from fastapi.responses import RedirectResponse, JSONResponse

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)

_IS_PRODUCTION = settings.environment == "production"
_COOKIE_SECURE = _IS_PRODUCTION
_COOKIE_SAMESITE = "none" if _IS_PRODUCTION else "lax"


def _set_access_token_cookie(response, access_token: str) -> None:
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=_COOKIE_SECURE,
        samesite=_COOKIE_SAMESITE,
        path="/",
        max_age=60 * settings.jwt_expire_minutes,
    )


async def _get_optional_current_user(
    request: Request,
    db: AsyncSession,
) -> User | None:

    token = request.cookies.get("access_token")

    if not token:
        return None

    payload = decode_access_token(token)
    sub = payload.get("sub")

    if not sub:
        return None

    user = await UserService.get_user_by_id(db, UUID(sub))

    if user is None or not user.is_active:
        return None

    return user


@router.get("/login")
async def redirect_to_microsoft_login(request: Request):
    return await oauth.microsoft.authorize_redirect(
        request,
        settings.microsoft_redirect_uri,
    )

@router.get("/authorize")
async def start_sso_authorization(
    request: Request,
    client_id: str,
    redirect_uri: str,
    state: str,
    db: AsyncSession = Depends(get_db),
):
    user = await _get_optional_current_user(request, db)

    if user is None:
        request.session["pending_authorize"] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
        }
        return await oauth.microsoft.authorize_redirect(
            request,
            settings.microsoft_redirect_uri,
        )

    return await build_authorize_redirect(db, user, client_id, redirect_uri, state)

@router.post("/token", response_model=TokenResponse)
async def exchange_code_for_app_token(
    payload: TokenExchangeRequest,
    db: AsyncSession = Depends(get_db),
):
    app = await AppService.get_by_client_id(db, payload.client_id)

    if app is None or not AppService.verify_client_secret(app, payload.client_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials",
        )

    code_row = await AuthorizationCodeService.redeem_authorization_code(
        db, payload.code, app, payload.redirect_uri,
    )

    if code_row is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid, expired, or already used code",
        )

    user = await UserService.get_user_by_id(db, code_row.user_id)

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User no longer available",
        )

    roles = await RoleService.list_roles_for_user_in_app(db, user.id, app)

    if not roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not provisioned for this app",
        )

    access_token, jti, expires_at = create_app_token(
        user_id=str(user.id),
        email=user.email,
        client_id=app.client_id,
        roles=roles,
    )

    await AppSessionService.record_app_session(db, jti, user, app, expires_at)

    return TokenResponse(
        access_token=access_token,
        expires_in=60 * APP_TOKEN_EXPIRE_MINUTES,
    )

@router.post("/introspect", response_model=IntrospectResponse)
async def introspect_app_token(
    payload: IntrospectRequest,
    db: AsyncSession = Depends(get_db),
):
    app = await AppService.get_by_client_id(db, payload.client_id)

    if app is None or not AppService.verify_client_secret(app, payload.client_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials",
        )

    claims = decode_app_token(payload.token, audience=payload.client_id)
    jti = claims.get("jti")

    if not jti:
        return IntrospectResponse(active=False)

    session = await AppSessionService.is_session_active(db, jti)

    if session is None:
        return IntrospectResponse(active=False)

    return IntrospectResponse(
        active=True,
        sub=claims.get("sub"),
        email=claims.get("email"),
        roles=claims.get("roles"),
        exp=claims.get("exp"),
    )

@router.post("/logout")
async def logout_and_revoke_sessions(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    user = await _get_optional_current_user(request, db)

    if user is not None:
        await AppSessionService.revoke_all_for_user(db, user.id)

    response = JSONResponse(
        content={
            "message": "Logged out"
        }
    )

    response.delete_cookie(
        key="access_token",
        httponly=True,
        secure=_COOKIE_SECURE,
        samesite=_COOKIE_SAMESITE,
    )

    return response

@router.get("/callback", name="handle_microsoft_callback")
async def handle_microsoft_callback(
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
        user = await UserService.upsert_user(
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

    access_token = create_access_token(
        user_id=str(user.id),
        email=user.email,
    )

    pending = request.session.pop("pending_authorize", None)

    if pending:
        try:
            response = await build_authorize_redirect(
                db,
                user,
                pending["client_id"],
                pending["redirect_uri"],
                pending["state"],
            )
        except HTTPException:
            response = RedirectResponse(
                url=(
                    f"{pending['redirect_uri']}"
                    f"?error=access_denied&state={pending['state']}"
                ),
                status_code=302,
            )
    else:
        response = RedirectResponse(
            url=f"{settings.frontend_url}/auth/callback",
            status_code=302,
        )

    _set_access_token_cookie(response, access_token)
    return response

@router.get("/me")
async def get_current_user_profile(
    current_user: User = Depends(get_current_user),
):
    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "name": current_user.full_name,
        "active": current_user.is_active,
    }