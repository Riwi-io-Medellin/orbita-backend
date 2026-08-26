from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.modules.apps.schemas import RoleCatalogSyncRequest, RoleCatalogSyncResult
from app.modules.apps.service import AppService, RoleService
from app.schemas import ErrorDetail

router = APIRouter(
    prefix="/apps",
    tags=["Apps"],
    responses={401: {"model": ErrorDetail, "description": "Invalid client_id/client_secret."}},
)


@router.put(
    "/{client_id}/role-catalog",
    response_model=RoleCatalogSyncResult,
    summary="Synchronize an app-owned role catalog",
    responses={404: {"model": ErrorDetail, "description": "App not found."}},
)
async def sync_role_catalog(
    client_id: str,
    payload: RoleCatalogSyncRequest,
    db: AsyncSession = Depends(get_db),
):
    """Server-to-server endpoint. The caller may synchronize only its own catalog. Missing previously synchronized roles are set inactive; assignments are preserved and inactive roles no longer grant SSO access."""
    app = await AppService.get_by_client_id(db, client_id)
    if app is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="App not found")
    if not AppService.verify_client_secret(app, payload.client_secret):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid client credentials")

    roles, deactivated = await RoleService.sync_catalog(db, app, payload.roles)
    return RoleCatalogSyncResult(roles=roles, deactivated_role_keys=deactivated)
