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

Completar en `.env`: `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, `MICROSOFT_TENANT_ID`, `JWT_SECRET`, `DATABASE_URL`.

## Ejecución

```bash
source .venv/bin/activate
uvicorn app.main:app --reload
```

Las migraciones de Alembic corren automáticamente al iniciar (no hace falta `alembic upgrade` manual).

## Integración de aplicaciones (SSO)

Órbita centraliza las credenciales y los accesos. Cada aplicación integrada se
registra como un cliente confidencial, con una URL de callback exacta y un
secreto propio. El flujo es de código de un solo uso:

1. La aplicación genera y conserva un `state` en la sesión del navegador y redirige a
   `GET /api/sso/authorize?client_id=...&redirect_uri=...&state=...`.
2. Órbita valida la sesión del usuario y su rol para esa aplicación, y redirige al
   callback con `code` y el mismo `state`.
3. El backend de la aplicación canjea el código con `POST /api/sso/token`, enviando
   `code`, `client_id`, `client_secret` y `redirect_uri` como JSON.
4. La respuesta contiene la identidad y únicamente los roles de esa aplicación. La
   aplicación crea entonces su propia sesión.

El código expira en 60 segundos y no puede canjearse dos veces. El secreto del
cliente se devuelve una sola vez al registrar una aplicación; debe guardarse como
variable privada en Railway, nunca en el frontend ni en Git.

## Endpoints principales

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/api/health` | Health check |
| GET | `/api/auth/login` | Redirige a Microsoft OAuth |
| GET | `/api/auth/callback` | Callback OAuth, emite cookie JWT |
| POST | `/api/auth/logout` | Limpia cookie de sesión |
| GET | `/api/auth/me` | Usuario autenticado actual |
| GET | `/api/users/` | Placeholder (aún sin CRUD real) |
