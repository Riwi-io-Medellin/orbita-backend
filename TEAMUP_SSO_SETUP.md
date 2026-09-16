# Registro local de TeamUp

1. Registrar una aplicación SSO con `client_id=teamup`, `slug=teamup`, icono `teamup` y launcher
   `http://localhost:3010/api/auth/orbita/login`. Guardar el secreto mostrado una sola vez.
2. Registrar el callback exacto `http://localhost:3010/api/auth/orbita/callback` y la URI posterior al
   logout `http://localhost:5174/login`.
3. Iniciar TeamUp backend con sus variables `ORBITA_SSO_*`; el backend sincroniza los seis roles.
4. En la política de TeamUp activar cardinalidad única, acceso temporal, adopción JIT y claim `clan`.
5. Crear el mapeo global `coder` → rol TeamUp `coder`.
6. Cuando termine la migración, desactivar acceso temporal y adopción JIT. No hay vencimiento automático.

El canal JIT solo adopta el rol de la misma identidad presente en el JWT, no permite indicar otro usuario
y no expone cursos, grupos, tokens ni credenciales Moodle.
