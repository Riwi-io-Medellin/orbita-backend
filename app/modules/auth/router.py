import logging
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy.exc import IntegrityError

from app.config.settings import settings

from app.modules.users.models import User

from app.modules.auth.microsoft import (
    MicrosoftTenantNotAllowedError,
    ms_claims_options,
    oauth,
    validate_microsoft_claims,
)

from app.modules.auth.dependencies import get_authenticated_user, get_current_user

from fastapi import Depends

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.modules.users.service import UserService

from app.modules.apps.service import AppService, RoleService
from app.modules.access.service import AccessService
from app.modules.auth.passwords import hash_password, verify_password

from app.modules.auth.jwt import (
    APP_TOKEN_EXPIRE_MINUTES,
    create_access_token,
    create_app_token,
    decode_access_token,
    decode_app_token,
)
from app.modules.auth.schemas import (
    AuthenticationProvidersResponse,
    IntrospectRequest,
    IntrospectResponse,
    LogoutTicketRequest,
    LogoutTicketResponse,
    MoodleLoginRequest,
    MoodlePasswordResetRequest,
    PasswordLoginRequest,
    PasswordChangeRequest,
    ProfileUpdateRequest,
    RegisterRequest,
    TokenExchangeRequest,
    TokenResponse,
    RoleAdoptionRequest,
    RoleAdoptionResponse,
)
from app.modules.auth.service import (
    AppSessionService,
    AuthorizationCodeService,
    LogoutTicketService,
    build_authorize_redirect,
)
from app.modules.auth.moodle import MoodleClient, MoodleCredentialsError, MoodleUnavailableError, mapped_orbita_role
from app.modules.users.models import UserFederatedAttribute
from app.modules.auth.rate_limit import MoodleLoginRateLimiter, MoodleRateLimitedError
from app.modules.auth.csrf import issue_csrf_token
from app.modules.identity.service import (
    IdentityLinkConflictError,
    IdentityResolver,
    InvalidInstitutionalEmailError,
    ProviderUnavailableError,
)

from fastapi.responses import RedirectResponse, JSONResponse

from app.schemas import ErrorDetail

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)

_IS_PRODUCTION = settings.environment == "production"
_COOKIE_SECURE = _IS_PRODUCTION
_COOKIE_SAMESITE = settings.access_cookie_samesite


def _sso_access_denied_redirect() -> RedirectResponse:
    """Return the central UI error for an authenticated user without app access."""
    return RedirectResponse(
        url=f"{settings.frontend_url}/auth?error=sso_access_denied",
        status_code=302,
    )
logger = logging.getLogger(__name__)


def _set_access_token_cookie(response, access_token: str) -> None:
    response.set_cookie(
        key=settings.access_cookie_name,
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

    token = request.cookies.get(settings.access_cookie_name)

    if not token:
        return None

    payload = decode_access_token(token)
    sub = payload.get("sub")

    if not sub:
        return None

    try:
        user = await UserService.get_user_by_id(db, UUID(sub))
    except (TypeError, ValueError):
        return None

    if user is None or not user.is_active or user.deleted_at is not None:
        return None

    return user


def _user_is_unavailable(user: User) -> bool:
    return not user.is_active or user.deleted_at is not None


async def _issue_central_session(
    db: AsyncSession,
    user: User,
    request: Request,
    response: JSONResponse | RedirectResponse,
    *,
    event: str = "login",
) -> JSONResponse | RedirectResponse:
    if _user_is_unavailable(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tu cuenta se encuentra deshabilitada. Contacta a un administrador.",
        )

    await AccessService.ensure_default_role(db, user)
    roles = await AccessService.role_names(db, user.id)
    access_token = create_access_token(user_id=str(user.id), email=user.email, roles=roles)
    await AccessService.audit(db, event=event, user_id=user.id, request=request)
    _set_access_token_cookie(response, access_token)
    return response


@router.get(
    "/login",
    summary="Start central login via Microsoft",
    responses={302: {"description": "Redirect to Microsoft's OAuth consent screen."}},
)
async def redirect_to_microsoft_login(request: Request):
    """Kicks off the central (Orbita's own) Microsoft OAuth login flow. On success, Microsoft redirects back to `GET /auth/callback`."""
    if not settings.enable_microsoft_login:
        return RedirectResponse(
            url=f"{settings.frontend_url}/auth/callback?error=provider_unavailable",
            status_code=302,
        )
    return await oauth.microsoft.authorize_redirect(
        request,
        settings.microsoft_redirect_uri,
    )


@router.get(
    "/providers",
    response_model=AuthenticationProvidersResponse,
    summary="List currently available central authentication methods",
)
async def authentication_providers(db: AsyncSession = Depends(get_db)):
    moodle = await IdentityResolver.get_provider(db, "moodle")
    microsoft = await IdentityResolver.get_provider(db, "microsoft")
    return AuthenticationProvidersResponse(
        moodle=bool(moodle and moodle.active and MoodleClient(settings).configured),
        microsoft=bool(microsoft and microsoft.active and settings.enable_microsoft_login),
        local=settings.enable_local_login,
    )


@router.get(
    "/csrf",
    summary="Issue a CSRF token for the current browser session",
    responses={401: {"model": ErrorDetail, "description": "No valid central session."}},
)
async def csrf_token(
    request: Request,
    current_user: User = Depends(get_authenticated_user),
):
    """Returns a short-lived CSRF token bound to the current central-session JWT id."""
    payload = decode_access_token(request.cookies.get(settings.access_cookie_name, ""))
    session_jti = payload.get("jti")
    if not session_jti:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    return {"csrf_token": issue_csrf_token(session_jti), "expires_in": 30 * 60}


@router.post(
    "/moodle/login",
    summary="Central login via Moodle credentials",
    responses={
        401: {"model": ErrorDetail, "description": "Invalid Moodle credentials."},
        403: {"model": ErrorDetail, "description": "No valid institutional email, or disabled account."},
        409: {"model": ErrorDetail, "description": "External identity linking conflict."},
        429: {"model": ErrorDetail, "description": "Too many attempts."},
        503: {"model": ErrorDetail, "description": "Moodle is disabled, unavailable, or misconfigured."},
    },
)
async def moodle_login(
    payload: MoodleLoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Authenticates with Moodle without persisting the submitted password or Moodle token."""
    moodle_provider = await IdentityResolver.get_provider(db, "moodle")
    if moodle_provider is None or not moodle_provider.active or not MoodleClient(settings).configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="El servicio de autenticación no está disponible temporalmente. Intenta nuevamente.",
        )
    try:
        await MoodleLoginRateLimiter.ensure_allowed(db, settings, payload.username, request)
    except MoodleRateLimitedError:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos. Intenta nuevamente más tarde.",
        )

    client = MoodleClient(settings)
    try:
        moodle_user = await client.authenticate(payload.username, payload.password)
    except MoodleCredentialsError:
        await MoodleLoginRateLimiter.record_failure(db, settings, payload.username, request)
        await AccessService.audit(db, event="login.moodle_failed", request=request)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales de Moodle inválidas")
    except MoodleUnavailableError:
        await AccessService.audit(db, event="login.moodle_unavailable", request=request)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="El servicio de autenticación no está disponible temporalmente. Intenta nuevamente.",
        )

    try:
        resolution = await IdentityResolver.resolve(
            db,
            settings=settings,
            provider_code="moodle",
            provider_user_id=moodle_user.user_id,
            provider_tenant_id=None,
            provider_email=moodle_user.email,
            full_name=moodle_user.full_name,
            activate_new_user=True,
        )
    except ProviderUnavailableError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="El servicio de autenticación no está disponible temporalmente. Intenta nuevamente.",
        )
    except InvalidInstitutionalEmailError:
        await AccessService.audit(db, event="identity.moodle_invalid_email", request=request)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Moodle no devolvió un correo válido para vincular tu cuenta. Contacta a un administrador.",
        )
    except IdentityLinkConflictError:
        await AccessService.audit(db, event="identity.link_conflict", request=request, details={"provider": "moodle"})
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No pudimos vincular automáticamente tu cuenta institucional. Contacta a un administrador para validar tu acceso.",
        )

    await MoodleLoginRateLimiter.clear_success(db, settings, payload.username, request)
    resolved_role = await AccessService.sync_moodle_role(
        db, resolution.user.id, mapped_orbita_role(moodle_user.role_shortnames),
    )
    await AccessService.sync_moodle_clan(
        db,
        resolution.user.id,
        role_name=mapped_orbita_role(moodle_user.role_shortnames),
        clan=moodle_user.clan_name,
        status=moodle_user.clan_status,
    )
    await AccessService.audit(
        db,
        event="access.moodle_role_synchronized",
        user_id=resolution.user.id,
        request=request,
        details={"role": resolved_role},
    )
    for event, details in resolution.events:
        await AccessService.audit(db, event=event, user_id=resolution.user.id, request=request, details=details)
    response = JSONResponse(content={"message": "Authenticated"})
    return await _issue_central_session(db, resolution.user, request, response, event="login.moodle")


@router.post(
    "/moodle/password-reset",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request a Moodle password-reset email",
    responses={503: {"model": ErrorDetail, "description": "Moodle is unavailable or disabled."}},
)
async def request_moodle_password_reset(
    payload: MoodlePasswordResetRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Proxies Moodle's no-login reset service without storing credentials or tokens."""
    throttle_subject = f"moodle-reset:{payload.identifier_type}:{payload.identifier.strip().lower()}"
    try:
        await MoodleLoginRateLimiter.ensure_allowed(db, settings, throttle_subject, request)
    except MoodleRateLimitedError:
        await AccessService.audit(db, event="moodle.password_reset_rate_limited", request=request)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiadas solicitudes. Intenta nuevamente más tarde.",
        )
    moodle_provider = await IdentityResolver.get_provider(db, "moodle")
    if moodle_provider is None or not moodle_provider.active or not MoodleClient(settings).configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="El servicio de autenticación no está disponible temporalmente. Intenta nuevamente.",
        )
    try:
        await MoodleClient(settings).request_password_reset(
            identifier=payload.identifier.strip(),
            identifier_type=payload.identifier_type,
        )
    except MoodleUnavailableError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="El servicio de autenticación no está disponible temporalmente. Intenta nuevamente.",
        )

    await MoodleLoginRateLimiter.record_attempt(db, settings, throttle_subject, request)
    await AccessService.audit(db, event="moodle.password_reset_requested", request=request)
    return {"message": "Si los datos coinciden con una cuenta Moodle, recibirás instrucciones para restablecer tu contraseña."}

@router.get(
    "/authorize",
    summary="Start an SSO handoff for another app",
    responses={
        302: {"description": "Redirect either to Orbita login, the central access-denied screen, or to the app's redirect_uri with a one-time code."},
        400: {"model": ErrorDetail, "description": "Unknown/inactive app, or redirect_uri not registered for it."},
    },
)
async def start_sso_authorization(
    request: Request,
    client_id: str,
    redirect_uri: str,
    state: str = Query(min_length=16, max_length=512),
    db: AsyncSession = Depends(get_db),
):
    """
    Entry point another app's frontend redirects to for SSO. If the browser has no valid Orbita
    session cookie yet, stashes the request and sends the user to Orbita login, where either a local
    password or Microsoft can be used. Otherwise validates client_id/redirect_uri against the apps
    registry, checks the user has a role for that app, and redirects back with a 60-second one-time code.
    """
    app = await AppService.get_by_client_id(db, client_id)
    if app is None or not await AppService.is_available_for_sso(db, app):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unknown or inactive app",
        )
    if not await AppService.validate_redirect_uri(db, app, redirect_uri):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="redirect_uri is not registered for this app",
        )

    user = await _get_optional_current_user(request, db)

    if user is None:
        request.session["pending_authorize"] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
        }
        return RedirectResponse(
            url=f"{settings.frontend_url}/auth?continue=sso",
            status_code=302,
        )

    try:
        return await build_authorize_redirect(db, user, client_id, redirect_uri, state)
    except HTTPException as exc:
        # This browser-facing endpoint must return a useful UI for an already
        # authenticated user who is not provisioned for the requested app.
        # Keep malformed/inactive-client errors as API errors.
        if exc.status_code == status.HTTP_403_FORBIDDEN:
            return _sso_access_denied_redirect()
        raise


@router.get(
    "/resume",
    summary="Resume an SSO handoff after central login",
    responses={302: {"description": "Redirect to the requesting app with a one-time code."}},
)
async def resume_sso_authorization(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    pending = request.session.get("pending_authorize")
    if pending is None:
        return RedirectResponse(
            url=f"{settings.frontend_url}/auth?error=sso_session_missing",
            status_code=302,
        )

    user = await _get_optional_current_user(request, db)
    if user is None:
        return RedirectResponse(
            url=f"{settings.frontend_url}/auth?continue=sso",
            status_code=302,
        )

    request.session.pop("pending_authorize", None)
    try:
        return await build_authorize_redirect(
            db,
            user,
            pending["client_id"],
            pending["redirect_uri"],
            pending["state"],
        )
    except (HTTPException, KeyError):
        return _sso_access_denied_redirect()

@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Exchange an SSO code for a per-app JWT",
    responses={
        400: {"model": ErrorDetail, "description": "Code is invalid, expired, already used, or the user is no longer available."},
        401: {"model": ErrorDetail, "description": "Invalid client_id/client_secret."},
        403: {"model": ErrorDetail, "description": "User has no role assigned for this app."},
    },
)
async def exchange_code_for_app_token(
    payload: TokenExchangeRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Called by another app's *backend* (not the browser), authenticated with its client_id/client_secret,
    to redeem the one-time code from `/auth/authorize` for a short-lived (30 min) RS256 JWT carrying
    that user's role(s) for this specific app. Also records the session so it can later be revoked.
    """
    app = await AppService.get_by_client_id(db, payload.client_id)

    if app is None or not await AppService.is_available_for_sso(db, app) or not AppService.verify_client_secret(app, payload.client_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials",
        )

    try:
        code_row = await AuthorizationCodeService.redeem_authorization_code(
            db, payload.code, app, payload.redirect_uri,
        )
        if code_row is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid, expired, or already used code",
            )

        user = await UserService.get_user_by_id(db, code_row.user_id)
        if user is None or _user_is_unavailable(user):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User no longer available")

        access = await RoleService.resolve_access(db, user.id, app)
        if not access.roles and not access.migration:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not provisioned for this app")

        attributes: dict[str, str] = {}
        if access.roles == ["coder"] and "clan" in (app.released_claims or []):
            clan = await db.scalar(select(UserFederatedAttribute.value).where(
                UserFederatedAttribute.user_id == user.id,
                UserFederatedAttribute.name == "clan",
            ))
            if clan:
                attributes["clan"] = clan

        access_token, jti, expires_at = create_app_token(
            user_id=str(user.id), email=user.email, name=user.full_name,
            client_id=app.client_id, roles=access.roles,
            migration=access.migration,
            attributes=attributes,
        )
        await AppSessionService.record_app_session(db, jti, user, app, expires_at)
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    return TokenResponse(
        access_token=access_token,
        expires_in=60 * APP_TOKEN_EXPIRE_MINUTES,
    )

@router.post(
    "/introspect",
    response_model=IntrospectResponse,
    summary="Check whether a per-app JWT is still active",
    responses={
        401: {"model": ErrorDetail, "description": "Invalid client_id/client_secret."},
    },
)
async def introspect_app_token(
    payload: IntrospectRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Opt-in check for apps that want revocation to take effect before a token's natural 30-minute expiry
    (e.g. right after logout). Returns `active: false` (200, not an error) for a token whose signature is
    valid but whose session was revoked or has expired, since per-app tokens are stateless JWTs otherwise.
    """
    app = await AppService.get_by_client_id(db, payload.client_id)

    if app is None or not await AppService.is_available_for_sso(db, app) or not AppService.verify_client_secret(app, payload.client_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials",
        )

    claims = decode_app_token(payload.token, audience=payload.client_id)
    jti = claims.get("jti")

    if not jti:
        return IntrospectResponse(active=False)

    session = await AppSessionService.is_session_active(db, jti)

    if session is None or session.app_id != app.id:
        return IntrospectResponse(active=False)

    user = await UserService.get_user_by_id(db, session.user_id)
    if user is None or _user_is_unavailable(user):
        return IntrospectResponse(active=False)

    access = await RoleService.resolve_access(db, user.id, app)
    token_roles = claims.get("roles")
    if not isinstance(token_roles, list) or set(access.roles) != set(token_roles) or bool(claims.get("migration")) != access.migration:
        return IntrospectResponse(active=False)

    return IntrospectResponse(
        active=True,
        sub=claims.get("sub"),
        email=claims.get("email"),
        roles=claims.get("roles"),
        exp=claims.get("exp"),
    )


@router.post("/adopt-role", response_model=RoleAdoptionResponse, summary="Adopt a legacy app role during migration")
async def adopt_legacy_app_role(
    payload: RoleAdoptionRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    app = await AppService.get_by_client_id(db, payload.client_id)
    if (
        app is None
        or not await AppService.is_available_for_sso(db, app)
        or not AppService.verify_client_secret(app, payload.client_secret)
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid client credentials")
    if not app.jit_role_adoption_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Role adoption is disabled")

    claims = decode_app_token(payload.token, audience=payload.client_id)
    jti = claims.get("jti")
    sub = claims.get("sub")
    if not jti or not sub:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid app token")
    if claims.get("migration") is not True or claims.get("roles") != []:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Role adoption requires a migration token")
    session = await AppSessionService.is_session_active(db, jti)
    if session is None or session.app_id != app.id or str(session.user_id) != str(sub):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive app session")
    user = await UserService.get_user_by_id(db, session.user_id)
    if user is None or _user_is_unavailable(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User unavailable")

    # Re-evaluate current platform access instead of trusting claims issued earlier.
    # In particular, a user changed to guest after token issuance must not be able
    # to adopt a role during the remainder of that token's lifetime.
    access = await RoleService.resolve_access(db, user.id, app)
    if not access.migration:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Application access is unavailable")

    current = await RoleService.list_roles_for_user_in_app(db, user.id, app)
    if current:
        if current == [payload.role]:
            await AppSessionService.revoke_for_user_in_app(db, user.id, app.id)
            return RoleAdoptionResponse(role=payload.role)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An explicit app role already exists")

    role = await RoleService.get_by_app_and_name(db, app, payload.role)
    if role is None or not role.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown or inactive app role")
    try:
        await RoleService.assign_role_to_user(db, user.id, app, role, source="jit_migration")
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await AppSessionService.revoke_for_user_in_app(db, user.id, app.id)
    await AccessService.audit(
        db,
        event="access.app_role_adopted",
        user_id=user.id,
        application_id=app.application_id,
        request=request,
    )
    return RoleAdoptionResponse(role=payload.role)


@router.post("/logout-ticket", response_model=LogoutTicketResponse, summary="Create a federated logout ticket")
async def create_logout_ticket(payload: LogoutTicketRequest, db: AsyncSession = Depends(get_db)):
    app = await AppService.get_by_client_id(db, payload.client_id)
    if app is None or not await AppService.is_available_for_sso(db, app) or not AppService.verify_client_secret(app, payload.client_secret):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid client credentials")
    if not await AppService.validate_post_logout_uri(db, app, payload.post_logout_uri):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="post_logout_uri is not registered")
    ticket = await LogoutTicketService.issue(db, app, payload.post_logout_uri)
    return LogoutTicketResponse(logout_url=f"{settings.resolved_public_base_url}/api/auth/end-session?ticket={ticket}")


@router.get("/end-session", summary="Consume a federated logout ticket")
async def end_federated_session(request: Request, ticket: str = Query(min_length=32, max_length=512), db: AsyncSession = Depends(get_db)):
    row = await LogoutTicketService.redeem(db, ticket)
    if row is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired logout ticket")
    user = await _get_optional_current_user(request, db)
    if user is not None:
        await AppSessionService.revoke_all_for_user(db, user.id)
    response = RedirectResponse(row.post_logout_uri, status_code=302)
    response.delete_cookie(
        key=settings.access_cookie_name,
        httponly=True,
        secure=_COOKIE_SECURE,
        samesite=_COOKIE_SAMESITE,
        path="/",
    )
    return response

@router.post(
    "/logout",
    summary="Log out and revoke all per-app sessions",
)
async def logout_and_revoke_sessions(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Clears the central session cookie and revokes every `app_sessions` row for this user, so any app that
    calls `POST /auth/introspect` will immediately see their token as inactive. Apps that never call
    introspect keep honoring their already-issued token until its natural 30-minute expiry (by design).
    Safe to call with no session — always returns 200.
    """
    user = await _get_optional_current_user(request, db)

    if user is not None:
        await AppSessionService.revoke_all_for_user(db, user.id)

    response = JSONResponse(
        content={
            "message": "Logged out"
        }
    )

    response.delete_cookie(
        key=settings.access_cookie_name,
        httponly=True,
        secure=_COOKIE_SECURE,
        samesite=_COOKIE_SAMESITE,
    )

    return response

@router.get(
    "/callback",
    name="handle_microsoft_callback",
    summary="Microsoft OAuth callback",
    responses={
        302: {"description": "Redirect to the frontend (or, if resuming an SSO handoff, to the other app's redirect_uri) with the session cookie set."},
    },
)
async def handle_microsoft_callback(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Where Microsoft redirects back to after login. Creates or updates the local user record, rejects
    inactive accounts, issues the central session cookie, and resumes a pending SSO handoff if one was
    stashed by `/auth/authorize`.
    Never raises to the caller: on any OAuth/upsert failure it redirects to the frontend with `?error=...`.
    """
    if not settings.enable_microsoft_login:
        return RedirectResponse(
            url=f"{settings.frontend_url}/auth/callback?error=provider_unavailable",
            status_code=302,
        )

    try:
        token = await oauth.microsoft.authorize_access_token(
            request,
            claims_options=ms_claims_options,
        )
    except Exception:
        logger.warning("Microsoft OAuth callback failed")
        return RedirectResponse(
            url=f"{settings.frontend_url}/auth/callback?error=authentication_failed"
        )

    try:
        tenant_id, oid, email, full_name = validate_microsoft_claims(token["userinfo"])
        resolution = await IdentityResolver.resolve(
            db=db,
            settings=settings,
            provider_code="microsoft",
            provider_user_id=oid,
            provider_tenant_id=tenant_id,
            provider_email=email,
            full_name=full_name,
            activate_new_user=False,
        )
    except ProviderUnavailableError:
        return RedirectResponse(
            url=f"{settings.frontend_url}/auth/callback?error=provider_unavailable",
            status_code=302,
        )
    except IdentityLinkConflictError:
        await AccessService.audit(db, event="identity.link_conflict", request=request, details={"provider": "microsoft"})
        return RedirectResponse(
            url=f"{settings.frontend_url}/auth/callback?error=identity_link_conflict",
            status_code=302,
        )
    except MicrosoftTenantNotAllowedError as exc:
        await AccessService.audit(
            db,
            event="MICROSOFT_TENANT_NOT_ALLOWED",
            request=request,
            details={"tenant_id": exc.tenant_id},
        )
        return RedirectResponse(
            url=f"{settings.frontend_url}/auth/callback?error=authentication_failed"
        )
    except (InvalidInstitutionalEmailError, ValueError):
        logger.info("Microsoft identity claims or email were rejected")
        return RedirectResponse(
            url=f"{settings.frontend_url}/auth/callback?error=authentication_failed"
        )

    user = resolution.user
    for event, details in resolution.events:
        await AccessService.audit(db, event=event, user_id=user.id, request=request, details=details)

    await AccessService.bootstrap_platform_admins(
        db,
        settings.platform_admin_emails.split(","),
    )

    if _user_is_unavailable(user):
        await AccessService.audit(db, event="login.inactive", user_id=user.id, request=request)
        return RedirectResponse(
            url=f"{settings.frontend_url}/auth/callback?error=user_inactive"
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
        except (HTTPException, KeyError):
            response = RedirectResponse(
                url=f"{settings.frontend_url}/auth/callback?error=sso_access_denied",
                status_code=302,
            )
    else:
        response = RedirectResponse(
            url=f"{settings.frontend_url}/auth/callback",
            status_code=302,
        )

    return await _issue_central_session(db, user, request, response, event="login.microsoft")

@router.post(
    "/login",
    summary="Central login via email/password",
    responses={
        401: {"model": ErrorDetail, "description": "Unknown email or wrong password."},
        403: {"model": ErrorDetail, "description": "The account is inactive."},
    },
)
async def password_login(
    payload: PasswordLoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Local-account login for users with a `password_hash` set. Valid credentials only receive a central
    session cookie when the account is active.
    """
    if not settings.enable_local_login:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Local login is disabled")

    throttle_subject = f"local:{str(payload.email).strip().lower()}"
    try:
        await MoodleLoginRateLimiter.ensure_allowed(db, settings, throttle_subject, request)
    except MoodleRateLimitedError:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos. Intenta nuevamente más tarde.",
        )

    user = await UserService.get_by_email(db, str(payload.email))

    if user is None or not verify_password(payload.password, user.password_hash):
        await MoodleLoginRateLimiter.record_failure(db, settings, throttle_subject, request)
        await AccessService.audit(
            db,
            event="login.password_failed",
            request=request,
            details={"email": str(payload.email)},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if _user_is_unavailable(user):
        await AccessService.audit(
            db,
            event="login.inactive",
            user_id=user.id,
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tu cuenta se encuentra deshabilitada. Contacta a un administrador.",
        )

    await MoodleLoginRateLimiter.clear_success(db, settings, throttle_subject, request)
    response = JSONResponse(content={"message": "Authenticated"})
    return await _issue_central_session(db, user, request, response, event="login.local")

# Not wired up yet - uncomment to enable local account self-registration.
# @router.post("/register")
async def register_user(
    payload: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Local self-registration by email/password. Disabled (decorator commented out) — deliberately not
    exposed yet. New accounts created this way would default to `is_active=False`, same as any other
    new user, requiring an `orbita_admin` to activate them before they can do anything.
    """
    existing = await UserService.get_by_email(db, str(payload.email))

    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    try:
        user = await UserService.create_local_user(
            db,
            email=str(payload.email),
            full_name=payload.full_name,
            password_hash=hash_password(payload.password),
        )
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    await AccessService.ensure_default_role(db, user)
    roles = await AccessService.role_names(db, user.id)

    access_token = create_access_token(
        user_id=str(user.id),
        email=user.email,
        roles=roles,
    )

    await AccessService.audit(db, event="register", user_id=user.id, request=request)

    response = JSONResponse(content={"message": "Registered"})
    _set_access_token_cookie(response, access_token)
    return response

@router.get(
    "/me",
    summary="Get the current user's profile",
    responses={
        401: {"model": ErrorDetail, "description": "No/invalid session cookie."},
        403: {"model": ErrorDetail, "description": "User is inactive."},
    },
)
async def get_current_user_profile(
    current_user: User = Depends(get_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns the caller's identity plus their global roles (not per-app roles), read from the central session cookie."""
    roles = await AccessService.role_names(db, current_user.id)
    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "name": current_user.full_name,
        "active": current_user.is_active,
        "roles": roles,
        "role": roles[0] if roles else None,
        "must_change_password": current_user.must_change_password,
        "is_local_account": current_user.is_local_account,
    }


@router.patch("/me", summary="Update the current local user's profile")
async def update_current_user_profile(
    payload: ProfileUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not current_user.is_local_account:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This account is managed by an external provider")
    current_user.full_name = payload.full_name.strip()
    await db.commit()
    return {"name": current_user.full_name}


@router.post("/me/password", summary="Change the current local user's password")
async def change_current_user_password(
    payload: PasswordChangeRequest,
    current_user: User = Depends(get_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    if not current_user.is_local_account:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This account is managed by an external provider")
    if not verify_password(payload.current_password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="La contraseña actual no coincide")
    if payload.current_password == payload.new_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="La nueva contraseña debe ser diferente")
    current_user.password_hash = hash_password(payload.new_password)
    current_user.must_change_password = False
    await db.commit()
    return {"message": "Contraseña actualizada"}
