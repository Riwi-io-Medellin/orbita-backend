# Dominios, cookies y sesión central en producción

## Limitación conocida con los dominios por defecto de Railway

Órbita usa una cookie HTTP-only del backend para representar la sesión central. En producción la
cookie se llama `__Host-orbita_access`, pertenece exclusivamente al host del backend y usa `Secure`,
`Path=/` y `SameSite=None`.

El despliegue actual separa la SPA y la API en hosts similares a estos:

```text
https://orbita-frontend.up.railway.app
https://orbita-backend.up.railway.app
```

Aunque ambos nombres terminan en `up.railway.app`, no son subdominios de un sitio compartido para el
navegador. `up.railway.app` figura en la Public Suffix List, por lo que cada hostname de Railway se
considera un sitio independiente. Una petición de la SPA al backend es, por tanto, una petición
cross-site y la cookie del backend se trata como cookie de terceros.

`SameSite=None; Secure` es necesario para ese despliegue, pero no obliga al navegador a aceptar la
cookie. Chrome, Edge, Safari, Firefox, modos privados y políticas corporativas pueden bloquear o
particionar cookies de terceros. CORS y `credentials: "include"` tampoco anulan esa política: solo
permiten enviar la cookie cuando el navegador decide admitirla.

## Síntomas esperados

La restricción puede manifestarse de varias formas:

- Moodle o el login local responden correctamente, pero la siguiente petición a `/api/auth/me`
  devuelve `401` y la SPA vuelve a mostrar el login.
- Microsoft completa OAuth y el callback del backend establece la cookie durante una navegación de
  nivel superior. Después, el backend redirige a la SPA y su petición cross-site a `/api/auth/me`
  puede no enviar la cookie; el usuario parece no haber iniciado sesión o entra en un ciclo de login.
- Una aplicación como TeamLead navega a `/api/auth/authorize`. Esa navegación puede ver una cookie
  existente del backend, pero si el navegador la bloqueó o particionó durante el login previo, Órbita
  vuelve a pedir autenticación aunque la persona hubiera iniciado sesión antes en la SPA.
- Cerrar la sesión local de TeamLead no debe cerrar la sesión central de Órbita. Sin embargo, la SPA
  puede aparentar que perdió esa sesión por la misma restricción de cookies entre sitios.

Este comportamiento no indica por sí solo un secreto SSO incorrecto ni un fallo de Microsoft,
Moodle o TeamLead. Se distingue revisando que el login/callback haya respondido correctamente y que
la petición posterior a `/api/auth/me` sea la que recibe `401` por ausencia de la cookie.

## Solución permanente recomendada

Publicar frontend y backend bajo el mismo dominio registrable controlado por Riwi, por ejemplo:

```text
https://orbita.riwi.io       # frontend
https://api.orbita.riwi.io   # backend
```

Los hosts continúan siendo orígenes distintos, así que se conservan CORS con credenciales y la
protección CSRF. Sin embargo, ambos son del mismo sitio (`riwi.io`) y la cookie deja de depender del
soporte para cookies de terceros. Otra opción válida es servir `/api` mediante un proxy del mismo
origen que la SPA.

Cambiar únicamente el DNS o añadir un dominio en Railway no completa la migración. Deben actualizarse
de forma coordinada:

1. En el backend de Órbita: `FRONTEND_URL`, `FRONTEND_ORIGINS`, `PUBLIC_BASE_URL` y
   `MICROSOFT_REDIRECT_URI`.
2. En el frontend: `VITE_API_URL`, apuntando a la nueva base pública `/api`.
3. En Microsoft Entra: registrar exactamente el nuevo callback indicado por
   `MICROSOFT_REDIRECT_URI` antes de retirar el anterior.
4. En cada consumidor SSO, incluido TeamLead: cambiar la URL base/discovery de Órbita a su nuevo
   dominio. Esto no requiere rotar `client_secret`.
5. En Órbita: revisar launcher URLs y callbacks allow-listed únicamente si también cambia el dominio
   de la aplicación consumidora.
6. Verificar CORS, cookies, login Moodle/local, login Microsoft, autorización SSO, acceso denegado y
   logout en navegadores normales y privados antes de retirar los hosts anteriores.

## Mitigación temporal

Mientras se mantengan los hosts `*.up.railway.app`, permitir cookies de terceros para ambos hosts
puede recuperar la sesión en algunos navegadores. Es una ayuda de diagnóstico y no una solución de
producción, porque depende de la configuración individual del usuario y de políticas que cambian con
el navegador.

