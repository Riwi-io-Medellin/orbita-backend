# Plan de hardening de Órbita

Estado: plan aprobado para implementar en `feature/security-hardening` de backend y frontend.

## Objetivo

Cerrar las brechas detectadas en sesión central, SSO, revocación, CSRF, abuso de autenticación,
observabilidad y despliegue Railway sin romper el login actual ni la integración de aplicaciones.

El trabajo se hará en incrementos pequeños y verificables. No se habilitará una nueva integración SSO
en producción hasta completar al menos las fases 0–3 y su matriz de aceptación.

## Decisión provisional para cookies y Railway

Hoy frontend y backend usan dominios públicos Railway diferentes. Para el navegador son peticiones
cross-origin y Railway advierte que las cookies pueden bloquearse si se usa `SameSite=Lax`. Por eso:

- mantener `SameSite=None` en la cookie central `__Host-orbita_access` mientras se usen esos dominios;
- mantener `Secure`, `HttpOnly`, `Path=/` y no establecer `Domain`;
- mantener `credentials: "include"` en el frontend;
- permitir por CORS únicamente los orígenes frontend conocidos, nunca `*` con credenciales;
- añadir CSRF explícito: `SameSite=None` es compatibilidad de despliegue, no defensa de seguridad;
- probar navegadores con cookies de terceros permitidas y bloqueadas. `SameSite=None` no puede forzar a
  un navegador a aceptar cookies de terceros.

La cookie firmada usada para OAuth y `pending_authorize` debe evaluarse por separado. Sus callbacks son
navegaciones GET de nivel superior, por lo que podría usar `SameSite=Lax` aunque la cookie API permanezca
en `None`. No cambiarla hasta demostrar Microsoft, Moodle y reanudación SSO de extremo a extremo.

Objetivo de infraestructura posterior, en orden de preferencia:

1. Servir frontend y `/api` bajo el mismo origen mediante proxy/gateway.
2. Usar subdominios de un dominio propio común, por ejemplo `orbita.example.com` y
   `api.orbita.example.com`, y reevaluar `SameSite=Lax`.
3. Mantener dominios Railway separados solo con las defensas y pruebas cross-site de este plan.

## Fase 0 — Baseline y contrato de despliegue

1. Crear una matriz por ambiente con URL pública de frontend, API, callback Microsoft y callbacks SSO.
   Guardar valores reales en Railway, no en Markdown ni Git.
2. Añadir settings explícitos y validados:
   - `PUBLIC_BASE_URL` del backend;
   - lista `FRONTEND_ORIGINS`;
   - nombre, `SameSite`, `Secure` y TTL de cada cookie por ambiente;
   - `SQL_ECHO=false` por defecto;
   - hosts confiables, incluyendo el hostname de healthcheck Railway cuando aplique.
3. Generar discovery y callbacks desde `PUBLIC_BASE_URL`, no desde `Host` recibido.
4. Capturar pruebas baseline de login local, Moodle, Microsoft, launcher y SSO antes de cambiar cookies.
5. Añadir pruebas de integración con PostgreSQL desechable para auth/SSO; no depender solo de mocks.

Criterio de salida: configuración inválida falla al arrancar, no existen fallbacks silenciosos a una URL
de producción y hay evidencia reproducible del comportamiento actual.

## Fase 1 — Correcciones críticas de SSO y revocación

1. En `/auth/token`, validar antes del canje:
   - cliente existente y activo;
   - launcher vinculado activo;
   - secreto correcto;
   - código vigente, redirect exacto y de un solo uso.
2. Mantener el canje atómico y definir una sola frontera transaccional para consumir código, verificar
   usuario/roles y registrar la sesión.
3. En `/auth/introspect`, validar:
   - firma, algoritmo, audiencia y claims;
   - `session.app_id == app.id`;
   - app y launcher activos;
   - usuario existente, activo y no eliminado;
   - al menos un rol actual activo para esa app.
4. Definir semántica de cambios de roles: si los roles actuales difieren de los incluidos en el JWT,
   devolver `active:false` y forzar reautenticación. No mezclar claims viejos y nuevos.
5. Revocar sesiones activas cuando se deshabilite/elimine un usuario, se deshabilite una app o se quite
   su último rol. Hacerlo en el mismo caso de uso/transacción del cambio administrativo.
6. Añadir índices y limpieza periódica para códigos/sesiones expirados si el volumen lo requiere.

Pruebas obligatorias: app/launcher inactivo, usuario inactivo/eliminado, rol retirado/inactivo, secreto
erróneo, código expirado/reutilizado, redirect parecido pero no exacto, audiencia cruzada y concurrencia
de dos canjes del mismo código.

## Fase 2 — Cookies, CORS y CSRF cross-site

1. Introducir protección CSRF para métodos inseguros autenticados por cookie:
   - token CSRF criptográfico ligado a la sesión;
   - entrega mediante endpoint autenticado y conservación solo en memoria del frontend;
   - envío en `X-CSRF-Token`;
   - validación server-side en `POST`, `PUT`, `PATCH` y `DELETE` aplicables;
   - rotación al iniciar/cerrar sesión.
2. Validar `Origin` y, como fallback controlado, `Referer` contra la allowlist exacta. Rechazar orígenes
   desconocidos antes de ejecutar el caso de uso.
3. Separar endpoints browser-cookie de endpoints server-to-server. `/auth/token`, `/auth/introspect` y
   role-catalog usan credenciales de cliente y no deben exigir el CSRF de la SPA.
4. Proteger también login y logout contra login/logout CSRF. Los endpoints públicos de login pueden
   usar un token pre-sesión o, como mínimo inicial, validación estricta de origen más throttling.
5. Restringir CORS a métodos y headers realmente usados; conservar origen explícito y
   `allow_credentials=true`.
6. Endurecer cookies de producción:
   - host-only, sin atributo `Domain`;
   - `HttpOnly`, `Secure`, TTL y `Path` explícitos;
   - prefijo `__Host-` cuando pueda aplicarse sin romper desarrollo;
   - borrado con los mismos atributos usados al crearlas.
7. Verificar que proxies Railway transmitan esquema/host confiables y configurar Uvicorn/TrustedHost
   sin aceptar indiscriminadamente `X-Forwarded-*` de Internet.

Pruebas obligatorias: petición legítima cross-site, token ausente/incorrecto/reutilizado, Origin malicioso,
preflight, logout forzado, cookies tras login y borrado, Chrome/Firefox/Safari y modo de bloqueo de
cookies de terceros.

## Fase 3 — Abuso de autenticación, privacidad y logs

1. Extraer un servicio de throttling compartido y aplicarlo a:
   - Moodle por usuario/IP;
   - login local por email/IP;
   - recuperación Moodle por identificador/IP;
   - callbacks o reanudaciones susceptibles de abuso.
2. Mantener almacenamiento compartido en PostgreSQL inicialmente; revisar Redis solo si las métricas lo
   justifican. Hacer limpieza acotada, indexada y no en cada request si genera contención.
3. Homogeneizar mensajes para evitar enumeración de cuentas/proveedores.
4. Deshabilitar SQL `echo` en producción y sanitizar auditoría, excepciones y observabilidad.
5. Definir confianza de IP detrás de Railway; no usar ciegamente un header enviado por el cliente.
6. Añadir límites de tamaño a código, secreto, token y parámetros SSO en schemas Pydantic.
7. Revisar algoritmo/costo de hashes y separar secretos criptográficos por propósito: sesión Starlette,
   rate-limit HMAC, JWT y CSRF no deben compartir la misma clave.

Criterio de salida: ataques repetidos quedan limitados entre réplicas, no hay secretos/credenciales en
logs y las respuestas públicas no permiten confirmar si una cuenta existe.

## Fase 4 — Frontend y experiencia segura

1. Consumir `/auth/providers` y mostrar únicamente Moodle, Microsoft o local cuando estén habilitados.
2. Incorporar obtención/renovación del token CSRF en `apiFetch` sin `localStorage`/`sessionStorage`.
3. Reintentar una sola vez después de renovar CSRF cuando el contrato lo permita; no repetir mutaciones
   ambiguas automáticamente.
4. Conservar mensajes diferenciados para `401`, `403`, `409`, `429` y proveedor no disponible.
5. Sustituir imágenes remotas de login por assets versionados locales y definir CSP compatible.
6. Añadir Vitest/React Testing Library para providers, auth y cliente CSRF; mantener lint/build.
7. Verificar manualmente móvil, teclado, sesión expirada y `continue=sso` con cada proveedor.

## Fase 5 — Clientes SSO y ciclo de secretos

1. Endurecer el adaptador FastAPI de referencia:
   - validar origen de discovery;
   - exigir todos los claims y sus tipos;
   - refrescar JWKS una vez ante `kid` desconocido;
   - límites y timeouts explícitos;
   - fallar cerrado.
2. Añadir un ejemplo completo de callback con almacenamiento/consumo de `state` y sesión local segura.
3. Diseñar rotación de `client_secret` con dos secretos temporalmente válidos, expiración del anterior,
   auditoría y visualización única. No sobrescribir sin ventana de transición.
4. Añadir pruebas contractuales reutilizables que una nueva app pueda ejecutar contra staging.

## Fase 6 — Operación Railway

1. Sacar `alembic upgrade head` del lifespan web y configurarlo como Railway Pre-Deploy Command. Un fallo
   debe impedir que el deployment nuevo reciba tráfico.
2. Extraer seed/bootstrap a un comando idempotente controlado y decidir si corre en pre-deploy o en una
   tarea operativa separada.
3. Configurar `/api/health` como liveness y añadir readiness que compruebe dependencias necesarias sin
   filtrar detalles. Usar el healthcheck de Railway para activar el deployment nuevo.
4. Documentar rollback: las migraciones deben ser compatibles con la versión anterior durante despliegue
   gradual; no depender de `downgrade` destructivo como respuesta principal.
5. Separar ambientes y registros SSO de development/staging/production, incluidos callbacks y secretos.
6. Configurar alertas mínimas: tasa de `401/403/429/5xx`, fallos de proveedor, conflictos de identidad,
   fallos de pre-deploy y crecimiento de códigos/sesiones expirados.
7. Evaluar dominio propio o gateway same-origin. Cuando exista, ejecutar pruebas antes de cambiar
   `SameSite=None` a `Lax`.

## Orden propuesto de entregas

1. PR backend: baseline, settings seguros y pruebas SSO.
2. PR backend: canje/introspección/revocación crítica.
3. PR coordinado backend+frontend: CSRF, cookies y CORS Railway.
4. PR coordinado: rate limiting, providers UI, logs y assets.
5. PR backend: adaptador SSO y rotación de secretos.
6. PR operativo: pre-deploy, healthchecks, métricas y runbook Railway.

Cada PR debe actualizar OpenAPI, contratos, README, `.env.example`, AGENTS y este plan si cambia una
decisión. Cada paso se despliega primero a staging con dominios Railway separados.

## Estado de ejecución (2026-09-01)

Implementado en `feature/security-hardening`: secretos separados obligatorios en producción, cookies
`__Host-*`, CORS/orígenes explícitos, CSRF ligado a la sesión, revocación por disponibilidad y roles,
limitación HMAC de login/reset, rotación de secreto con ventana de 15 minutos, JWKS con refresco por
`kid`, migración Railway pre-deploy y readiness `/api/ready`. Resta la validación operativa en staging
Railway y el flujo TeamLead con sus credenciales de staging.

## Gate para integrar una nueva app

Se puede desarrollar la integración en paralelo desde ahora. Para habilitarla en producción se exige:

- fases 0–3 completas;
- todos los casos de `SSO_CLIENT_CONTRACT.md` aprobados en staging;
- evidencia de login cross-site y CSRF en navegadores objetivo;
- rollback y pre-deploy de migraciones probados;
- registro/secret/callback exclusivos de producción;
- riesgo de cookies de terceros aceptado explícitamente o resuelto con dominio/gateway propio.
