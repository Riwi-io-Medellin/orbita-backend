# AGENTS.md — Órbita Backend

## Propósito

Órbita es el portal central de identidad, acceso y lanzamiento de aplicaciones del ecosistema Riwi. Este repositorio contiene su API y actúa en dos papeles relacionados, pero distintos:

1. Backend de Órbita: autentica usuarios, mantiene la sesión central, administra usuarios, aplicaciones, permisos y auditoría.
2. Broker de identidad: resuelve cuentas externas de Moodle y Microsoft hacia una sola identidad canónica de Órbita, sin persistir contraseñas ni tokens de Moodle.
3. Proveedor SSO interno: entrega a aplicaciones registradas una identidad verificable y los roles que esa persona tiene específicamente en esa aplicación.

Órbita no decide qué puede hacer un rol dentro de TeamLead, Riwi Calls u otra aplicación. Cada aplicación es dueña de la semántica de sus roles; Órbita es dueña de la identidad, la asignación y la entrega segura de esos roles.

Antes de cambiar contratos de autenticación o autorización, leer `API_CONTRACT.md`, `SSO_CLIENT_CONTRACT.md` y `SSO_INTEGRATION.md`. El contrato ejecutable definitivo es OpenAPI (`/openapi.json`, `/docs`). Si el comportamiento cambia, actualizar el código, los esquemas y la documentación en el mismo cambio.

## Stack técnico

- Python 3.11+ y FastAPI.
- Pydantic 2 y `pydantic-settings` para contratos y configuración.
- SQLAlchemy 2 asíncrono con `asyncpg` y PostgreSQL.
- Alembic para versionar el esquema.
- Authlib para Microsoft OAuth/OIDC.
- JWT RS256 mediante `python-jose` y `cryptography`.
- Cookies HTTP-only para la sesión central.
- Uvicorn como servidor ASGI.
- Railway como entorno habitual de despliegue.
- Pytest y pytest-asyncio para la suite automatizada disponible en `tests/`.

La cobertura actual se concentra en identidad externa, constraints y clientes de proveedor; todavía faltan pruebas de integración amplias para SSO, acceso y administración. Toda lógica nueva o corregida debe añadir la prueba correspondiente, especialmente para autorización y fallos de seguridad.

## Arquitectura

Es un monolito modular orientado a capacidades de negocio:

```text
app/
├── main.py                  composición de FastAPI, middleware, lifespan y routers
├── config/                  Settings y validación de variables de entorno
├── database/                Base SQLAlchemy, engine y sesiones async
└── modules/
    ├── auth/                login local/Moodle/Microsoft, sesión central y protocolo SSO
    ├── identity/            proveedores y correlación hacia el usuario canónico
    ├── users/               ciclo de vida y administración de usuarios
    ├── apps/                clientes SSO, redirect URIs y roles por aplicación
    └── access/              catálogo, roles globales, resolución de acceso y auditoría
alembic/                     migraciones del esquema
clients/                     adaptadores de referencia para aplicaciones consumidoras
tests/                       pruebas de identidad, proveedores y constraints
```

Dentro de cada módulo:

- `router.py`: transporte HTTP, dependencias, códigos de estado y traducción de errores.
- `schemas.py`: modelos de entrada/salida y validación del contrato.
- `service.py`: reglas de negocio y operaciones de aplicación.
- `models.py`: persistencia SQLAlchemy.

`ApplicationLifecycleService` es el punto canónico para crear y habilitar/deshabilitar el agregado formado por una tarjeta `Application` y su posible cliente SSO `App`. No duplicar esa coordinación en routers.

Las dependencias deben apuntar hacia reglas de negocio, no hacia detalles HTTP. Un servicio no debe conocer `Request` o `Response` salvo que su responsabilidad sea explícitamente auditar metadatos de la petición.

## Modelo de acceso

Mantener separadas estas tres capas:

- `is_platform_admin`: autoriza la administración de la plataforma. Es el límite real para usuarios, registro SSO, roles y auditoría.
- Roles globales (`admin`, `staff`, `coder`): habilitan aplicaciones de catálogo; no expresan permisos internos de una app SSO.
- Roles por aplicación: pertenecen a un cliente SSO, habilitan su tarjeta, autorizan el handoff y viajan en el claim `roles` del JWT con `aud=client_id`.

Hay dos políticas de aplicación:

- `catalog`: es un lanzador. El acceso proviene de un rol global o de una asignación directa; Órbita no emite un token SSO.
- `sso_role`: su visibilidad y autenticación dependen de al menos un rol asignado en esa app. Los grants directos y globales no deben saltarse esta regla.

Un usuario nuevo comienza inactivo. `PLATFORM_ADMIN_EMAILS` activa y promueve cuentas administrativas durante el arranque. La eliminación de usuarios es lógica (`deleted_at` + `is_active=false`), no física.

El frontend puede ocultar opciones, pero nunca es un límite de seguridad. Toda ruta administrativa debe depender de `get_current_platform_admin`; toda ruta autenticada debe validar en backend la cookie y que el usuario siga activo.

## Flujo de sesión de Órbita

Órbita permite tres formas de iniciar la misma sesión central:

- correo y contraseña mediante `POST /api/auth/login`;
- credenciales Moodle mediante `POST /api/auth/moodle/login`, sin conservar contraseña ni token Moodle;
- Microsoft mediante `GET /api/auth/login` y el callback OAuth, solo cuando el proveedor está habilitado.

`GET /api/auth/providers` es la fuente de verdad para los métodos disponibles. El frontend debe respetarla y no ofrecer un proveedor deshabilitado. Moodle puede activar una cuenta nueva según la política configurada; Microsoft crea nuevas identidades inactivas. La correlación automática por correo debe cumplir `ALLOWED_IDENTITY_EMAIL_DOMAINS` y la excepción explícita de Moodle, y nunca puede unir dos personas ante una colisión ambigua.

Al completar cualquiera, el backend firma un JWT central RS256 y lo guarda en la cookie HTTP-only `__Host-orbita_access` (en desarrollo: `access_token`). El navegador nunca necesita leer el token. `/api/auth/me` reconstruye el usuario actual y sus roles globales. En producción la cookie usa `Secure` y `SameSite=None` mientras frontend/backend tengan dominios Railway distintos; toda mutación de la SPA usa el CSRF ligado a sesión de `/api/auth/csrf`.

No almacenar tokens o secretos en logs, respuestas de error ni documentación versionada. La clave privada RSA vive únicamente en el backend; el público consume JWKS.

## Flujo SSO para aplicaciones

El protocolo es un authorization-code flow interno, descrito por `Orbita SSO Client Contract v1`:

1. El backend cliente genera un `state` criptográficamente aleatorio y redirige el navegador a `/api/auth/authorize`.
2. Órbita valida `client_id`, coincidencia exacta del `redirect_uri`, sesión del usuario y rol activo en esa app.
3. Órbita devuelve un código opaco, almacenado como hash, de un solo uso y vigencia aproximada de 60 segundos.
4. El backend cliente canjea el código en `/api/auth/token` usando su secreto, nunca desde el navegador.
5. Órbita entrega un JWT RS256 de aproximadamente 30 minutos con `sub`, `email`, `name`, `aud`, `roles`, `jti` y `exp`.
6. El cliente verifica firma, `kid`, expiración y que `aud` sea exactamente su propio `client_id`, y crea su sesión local.

Invariantes que no se negocian:

- `redirect_uri` debe compararse exactamente contra la allowlist y ser HTTP(S) absoluta sin fragmentos.
- `state` protege el navegador contra CSRF; Órbita debe preservarlo y el cliente debe compararlo en tiempo constante.
- El código debe ser corto, opaco, hasheado, de un solo uso y consumido de forma atómica.
- `client_secret` se muestra una sola vez, se persiste únicamente como hash y jamás se expone al frontend.
- Los tokens son RS256; no permitir downgrade ni algoritmos configurables desde el request.
- `aud` aísla tokens entre aplicaciones.
- La revocación inmediata se consulta en `/api/auth/introspect`; valida disponibilidad actual de app/usuario y roles exactos. Sin introspección, el límite es la expiración del JWT.
- Un rol inactivo no puede asignarse ni autorizar SSO. La sincronización del catálogo desactiva roles ausentes, pero conserva asignaciones históricas.

## Base de datos y migraciones

- Todo acceso normal a PostgreSQL debe usar `AsyncSession` y expresiones SQLAlchemy 2.
- Los cambios de esquema se hacen exclusivamente con una nueva migración Alembic. No ejecutar DDL ad hoc desde routers o servicios.
- No editar una migración que ya pudo aplicarse en un entorno compartido; crear una revisión nueva y verificar que existe una sola cabeza.
- Importar nuevos modelos en el flujo de metadata de Alembic antes de autogenerar.
- Usar constraints e índices para invariantes persistentes y mantener los nombres estables.
- Delimitar la transacción en el caso de uso. Para operaciones sobre varios registros relacionados, usar `flush` y un solo `commit`; no dejar estados parciales.
- Las operaciones idempotentes deben apoyarse en `ON CONFLICT DO NOTHING` o una restricción equivalente, no solo en un `SELECT` previo.

Actualmente `app.main` ejecuta `alembic upgrade head` durante el lifespan y luego siembra roles y administradores. Cualquier cambio en esta estrategia debe considerar despliegues con múltiples réplicas y evitar carreras de migración.

## SOLID es obligatorio

Aplicar SOLID como criterio de diseño, no como ceremonia:

- **S — Single Responsibility:** un router traduce HTTP; un schema valida; un servicio ejecuta un caso de uso; un modelo representa persistencia. Si una clase cambia por razones de dominios distintos, dividirla.
- **O — Open/Closed:** agregar políticas, adaptadores o casos de uso mediante funciones/clases enfocadas y composición. Evitar cadenas de condicionales distribuidas por varios routers.
- **L — Liskov Substitution:** cualquier implementación que cumpla una interfaz debe conservar precondiciones, resultados y semántica de errores. No crear “sustitutos” que debiliten validaciones de seguridad.
- **I — Interface Segregation:** exponer dependencias pequeñas por capacidad. No crear servicios gigantes ni pasar objetos con métodos que el consumidor no usa.
- **D — Dependency Inversion:** los casos de uso dependen de abstracciones y datos del dominio; FastAPI, SQLAlchemy, Microsoft y JWT son detalles conectados en los bordes. Usar `Depends` o inyección explícita, no singletons ocultos ni imports circulares.

Antes de crear una abstracción, confirmar que separa una responsabilidad o una dependencia real. SOLID no significa añadir capas vacías ni patrones sin necesidad.

## Convenciones de implementación

- Usar `async def` de extremo a extremo para I/O; no bloquear el event loop.
- Mantener type hints completos y nombres de dominio explícitos.
- Validar formas y límites en Pydantic; validar autorización y estado actual en servicios/dependencias.
- Normalizar correos y claves de rol de forma consistente. Las claves de rol sincronizadas son estables, minúsculas y forman parte del contrato.
- Responder errores HTTP como `{ "detail": "..." }`; no filtrar excepciones internas.
- Los endpoints bulk deben informar IDs desconocidos en `not_found_ids` y respetar límites de tamaño.
- Conservar idempotencia en asignaciones y revocaciones.
- Evitar consultas N+1 y cargar únicamente los datos necesarios.
- No añadir dependencias sin justificar por qué el stack actual no resuelve el problema.
- Nunca modificar `.env` ni versionar credenciales, URLs privadas, claves PEM o secretos de Railway.
- No dejar `echo=True`, payloads de autenticación ni parámetros SQL sensibles en logs de producción.
- Todo login y recuperación de contraseña debe tener throttling persistente o compartido entre réplicas; no añadir rate limit solo en memoria.
- Una mutación autenticada por cookie necesita una defensa CSRF deliberada. CORS no es una defensa CSRF.
- `introspect` y el canje de código deben validar el estado actual de app, usuario, sesión y contrato de audiencia según la semántica prometida; documentar con precisión qué revocaciones son inmediatas.

## Cómo trabajar

Configuración local típica:

```bash
python -m venv .venv
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

En Windows se puede usar `./.venv/Scripts/python.exe` y `./.venv/Scripts/uvicorn.exe`. La URL y el puerto reales dependen del `.env`; no codificarlos en el dominio.

Verificación mínima antes de entregar:

```bash
python -m compileall app
python -m alembic heads
python -m pytest -q
```

Además:

- probar los endpoints tocados desde `/docs` o con un cliente HTTP;
- si cambió persistencia, aplicar `alembic upgrade head` contra una base desechable y comprobar upgrade/downgrade razonable;
- si cambió SSO, probar happy path y fallos de `state`, código expirado/reutilizado, `redirect_uri`, secreto, audiencia, usuario/rol inactivo y revocación;
- si se agregan tests, ejecutarlos completos antes de entregar.

## Documentación viva obligatoria

La documentación forma parte de la definición de terminado. Después de cada cambio de lógica, contrato, esquema, seguridad, proveedor, configuración o comportamiento observable, actualizar en el mismo cambio:

- schemas/descripciones OpenAPI y `API_CONTRACT.md` para APIs y reglas generales;
- `SSO_CLIENT_CONTRACT.md`, `SSO_INTEGRATION.md` y `clients/` para cualquier cambio consumible por aplicaciones;
- `README.md` y `.env.example` para instalación, dependencias, ejecución o variables;
- este `AGENTS.md` y el `AGENTS.md` raíz si cambió el contexto estable o una regla de trabajo;
- migraciones y pruebas cuando cambió persistencia o lógica.

No asumir que una edición “solo interna” carece de impacto: verificar explícitamente contratos, ejemplos, códigos de estado, seguridad, observabilidad y operación. Si no se actualiza un documento, debe ser porque se revisó y sigue siendo correcto.

## Regla de entrega

Preservar cambios locales ajenos. Revisar `git status` y el diff antes de editar. No reformatear módulos completos ni mezclar refactors no solicitados. Una entrega debe indicar qué cambió, qué migración requiere, qué variables nuevas necesita, cómo se verificó y cualquier riesgo pendiente.
