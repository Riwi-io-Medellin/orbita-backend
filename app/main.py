from fastapi import FastAPI

from app.modules.users.router import router as users_router

app = FastAPI(
    title="Orbita API",
    version="1.0.0",
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