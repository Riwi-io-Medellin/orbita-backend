from contextlib import asynccontextmanager
from pathlib import Path

import anyio
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from app.config.settings import settings
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware

from app.modules.users.router import router as users_router
from app.modules.auth.router import router as auth_router
from app.modules.access.router import router as applications_router
from app.modules.access.service import AccessService
from app.database.session import AsyncSessionLocal

BASE_DIR = Path(__file__).resolve().parent.parent


def run_migrations() -> None:
    cfg = Config(BASE_DIR / "alembic.ini")
    command.upgrade(cfg, "head")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await anyio.to_thread.run_sync(run_migrations)
    async with AsyncSessionLocal() as db:
        await AccessService.seed(db)
    yield


app = FastAPI(
    title="Orbita API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        settings.frontend_url,
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.jwt_secret,
)

@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "service": "orbita-backend",
    }


app.include_router(
    users_router,
    prefix="/api",
)

app.include_router(
    auth_router,
    prefix="/api",
)

app.include_router(applications_router, prefix="/api")
