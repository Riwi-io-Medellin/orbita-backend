# Orbita Backend

API central de identidad, acceso, catálogo y SSO de Órbita, desarrollada con FastAPI, PostgreSQL asíncrono y JWT RS256.

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

Completar las variables requeridas de `.env.example`: base de datos, secretos de sesión/JWT y claves RSA. Moodle, Microsoft y login local se habilitan por configuración; Microsoft requiere además su tenant y credenciales OAuth. No poner contraseñas de usuario ni tokens Moodle en `.env`.

En Windows, `uvloop` se omite automáticamente mediante su marcador de plataforma:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Ejecución

```bash
source .venv/bin/activate
uvicorn app.main:app --reload
```

Las migraciones de Alembic corren automáticamente al iniciar (no hace falta `alembic upgrade` manual).

## Contrato API

El contrato ejecutable está en `/docs` (Swagger), `/redoc` y `/openapi.json`. La guía completa de
autenticación, respuestas y política de acceso está en [API_CONTRACT.md](API_CONTRACT.md).
Las aplicaciones que consumen SSO deben seguir [SSO_CLIENT_CONTRACT.md](SSO_CLIENT_CONTRACT.md) y el proceso operativo de [SSO_INTEGRATION.md](SSO_INTEGRATION.md).
La limitación de sesión causada por usar frontend y backend en hosts `*.up.railway.app`, incluido su
impacto sobre Moodle, Microsoft y aplicaciones SSO, está documentada en
[DEPLOYMENT_DOMAINS.md](DEPLOYMENT_DOMAINS.md).
El trabajo de seguridad y operación pendiente está priorizado en [SECURITY_HARDENING_PLAN.md](SECURITY_HARDENING_PLAN.md).

## Endpoints principales

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/api/health` | Health check |
| GET | `/api/auth/providers` | Métodos de autenticación habilitados |
| POST | `/api/auth/moodle/login` | Login delegado a Moodle |
| POST | `/api/auth/moodle/password-reset` | Solicitud genérica de recuperación Moodle |
| GET | `/api/auth/login` | Redirige a Microsoft OAuth cuando está habilitado |
| POST | `/api/auth/login` | Login local temporal cuando está habilitado |
| GET | `/api/auth/callback` | Callback Microsoft, resuelve identidad y emite cookie |
| POST | `/api/auth/logout` | Limpia cookie de sesión |
| GET | `/api/auth/me` | Usuario autenticado actual |
| GET | `/api/auth/authorize` | Inicia un handoff SSO |
| POST | `/api/auth/token` | Canje server-to-server por JWT de aplicación |
| POST | `/api/auth/introspect` | Consulta optativa de sesión emitida |
| GET | `/api/applications/` | Catálogo autorizado del usuario |
| * | `/api/apps/*` | Registro SSO, callbacks, roles y miembros |
| * | `/api/users/*` | Administración de usuarios, accesos e identidades externas |

## Verificación

```bash
python -m compileall app
python -m alembic heads
python -m pytest -q
```

El arranque ejecuta `alembic upgrade head` y siembra roles globales/provisionamiento administrativo. En despliegues con múltiples réplicas, coordinar el arranque para evitar carreras de migración.
