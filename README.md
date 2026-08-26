# Orbita Backend

Backend API de Orbita desarrollado con Python y FastAPI.

## Requisitos

- Python 3.11+
- Docker (para Postgres local) o una instancia de Postgres 17 accesible

## Instalación

```bash
docker-compose up -d
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Completar en `.env`: `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, `MICROSOFT_TENANT_ID`, `JWT_SECRET`, `DATABASE_URL` y, para SSO, las claves RSA descritas en `SSO_INTEGRATION.md`.

## Ejecución

```bash
source .venv/bin/activate
uvicorn app.main:app --reload
```

Las migraciones de Alembic corren automáticamente al iniciar (no hace falta `alembic upgrade` manual).

## Contrato API

El contrato ejecutable está en `/docs` (Swagger), `/redoc` y `/openapi.json`. La guía completa de
autenticación, respuestas y política de acceso está en [API_CONTRACT.md](API_CONTRACT.md).
Las aplicaciones que consumen SSO deben seguir [SSO_CLIENT_CONTRACT.md](SSO_CLIENT_CONTRACT.md).

## Endpoints principales

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/api/health` | Health check |
| GET | `/api/auth/login` | Redirige a Microsoft OAuth |
| GET | `/api/auth/callback` | Callback OAuth, emite cookie JWT |
| POST | `/api/auth/logout` | Limpia cookie de sesión |
| GET | `/api/auth/me` | Usuario autenticado actual |
| GET | `/api/users/` | Placeholder (aún sin CRUD real) |
