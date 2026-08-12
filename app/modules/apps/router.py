from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.modules.auth.dependencies import get_current_platform_admin
from app.modules.apps.schemas import (
    AppCreate,
    AppCreated,
    AppRead,
    RedirectURICreate,
    RedirectURIRead,
    RoleAssign,
    RoleCreate,
    RoleRead,
)
from app.modules.apps.service import AppService, RoleService

router = APIRouter(
    prefix="/apps",
    tags=["Apps"],
    dependencies=[Depends(get_current_platform_admin)],
)


@router.post("/", response_model=AppCreated, status_code=status.HTTP_201_CREATED)
async def create_app(
    payload: AppCreate,
    db: AsyncSession = Depends(get_db),
):
    existing = await AppService.get_by_client_id(db, payload.client_id)

    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="client_id already registered",
        )

    app, raw_secret = await AppService.create_app(
        db,
        client_id=payload.client_id,
        name=payload.name,
    )

    return AppCreated(
        id=app.id,
        client_id=app.client_id,
        name=app.name,
        is_active=app.is_active,
        client_secret=raw_secret,
    )


@router.get("/", response_model=list[AppRead])
async def list_apps(
    db: AsyncSession = Depends(get_db),
):
    return await AppService.list_apps(db)


@router.post(
    "/{client_id}/redirect-uris",
    response_model=RedirectURIRead,
    status_code=status.HTTP_201_CREATED,
)
async def add_redirect_uri(
    client_id: str,
    payload: RedirectURICreate,
    db: AsyncSession = Depends(get_db),
):
    app = await AppService.get_by_client_id(db, client_id)

    if app is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="App not found",
        )

    return await AppService.add_redirect_uri(db, app, payload.redirect_uri)


@router.post(
    "/{client_id}/roles",
    response_model=RoleRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_role(
    client_id: str,
    payload: RoleCreate,
    db: AsyncSession = Depends(get_db),
):
    app = await AppService.get_by_client_id(db, client_id)

    if app is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="App not found",
        )

    existing = await RoleService.get_by_app_and_name(db, app, payload.name)

    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role already exists for this app",
        )

    return await RoleService.create_role(db, app, payload.name)


@router.post(
    "/{client_id}/roles/{role_id}/assign",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def assign_role(
    client_id: str,
    role_id: UUID,
    payload: RoleAssign,
    db: AsyncSession = Depends(get_db),
):
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
