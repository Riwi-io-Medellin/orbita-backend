from fastapi import FastAPI
from app.config.settings import settings
from starlette.middleware.sessions import SessionMiddleware

from app.modules.users.router import router as users_router
from app.modules.auth.router import router as auth_router

app = FastAPI(
    title="Orbita API",
    version="1.0.0",
)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.jwt_secret,
)

@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "service": "teamup-backend",
    }


app.include_router(
    users_router,
    prefix="/api",
)

app.include_router(auth_router)