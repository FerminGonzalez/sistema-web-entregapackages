# SISTEMA WEB ENTREGAPAQUETES — Quick start

Este documento es el manual de programación del sitio. El texto completo,
con todo el código HTML/PHP/CSS integrado y las medidas de seguridad
explicadas línea por línea, está en el documento Word:

    Manual_de_Programación.docx

Además está el video tutorial:

    video/tutorial_sitio_entregapackages.mp4

## Arranque rápido (servidor integrado de PHP)

1. Asegúrate de que los scripts SQL ya se aplicaron:
       mysql -h 127.0.0.1 -u root -D EntregaPaquetes < db_schema_web.sql
       mysql -h 127.0.0.1 -u root -D EntregaPaquetes < setup_users.sql
2. Arranca el servidor web (desde la carpeta raíz del proyecto):
       C:\php83\php.exe -S 127.0.0.1:8080 -t site
3. Abre: http://127.0.0.1:8080/login.php

Cuentas de demostración:
- admin       / Adm1n$EntregaWeb2026
- operador    / Oper4$SistemaWeb2026

Credenciales: la base de datos es la existente EntregaPaquetes
(MySQL 8.4). El sitio se conecta desde 127.0.0.1 (bind-address restringido
a loopback; el acceso remoto aún se demuestra en el taller con el control 7).

## Ejecutar con Apache (configuración .htaccess)

- Copia la carpeta `site/` dentro de Apache y arráncala.
- El archivo `site/.htaccess` implementa las cabeceras de seguridad,
  el bloqueo de archivos internos y sin listado de directorios.
- Los permisos se fijan con los archivos .htaccess del proyecto.

## Bitácora de seguridad del sitio

```sql
SELECT id, creado_at, evento, usuario, ip, user_agent, detalle
  FROM EntregaPaquetes.seguridad_log ORDER BY id DESC LIMIT 20;
```

## Estructura

```
site/
  config.php          Conexión PDO (prepared statements reales)
  headers.php         Cabeceras de seguridad (CSP, HSTS, etc.)
  seguridad.php       Utilidades: h(), validadores, CSRF, log_seguridad, RBAC
  login.php           Formulario de login
  login_post.php      Autenticación (bcrypt, lockout, session fixation, CSRF)
  logout.php          Cerrar sesión
  mantenimiento.php   Listado de Camióner
  insertar.php        Insertar camióner
  modificar.php       Modificar camióner
  eliminar.php        Eliminar camióner
  index.php           Página de inicio
  assets/css/style.css
  .htaccess           Hardening para Apache
```

## Medidas de seguridad web (lista aplicada; ver Manual_de_Programación.docx)

1.  SQLi prevention (prepared statements reales): config.php
    (PDO::ATTR_EMULATE_PREPARES = false).
2.  XSS prevention (codificación de salida): seguridad.php → h() + h() en
    todos los datos impresos.
3.  CSRF (prevención): validar_csrf() en login_post, insertar, modificar,
    eliminar (hash_equals con token de sesión).
4.  Contraseñas hasheadas (bcrypt): password_hash/password_verify.
5.  Hash falso para usuarios desconocidos: login_post (anti oráculos).
6.  Rate limiting + lockout por intentos fallidos: login_post + usuarios table.
7.  Session fixation: session_regenerate_id(true) tras login exitoso.
8.  Acceso autenticado + RBAC: requerir_autenticado() + requerir_rol_valido().
9.  Expiración de sesión (25 min inactividad): sesion_expirada().
10. Redirecciones: páginas sin sesión se redirigen a login.php (no mensajes info).
11. Validación de entrada: validar_cedula, validar_telef, validar_provincia,
    validar_numerico, validar_salario, regexps.
12. Saneamiento de entrada: limpieza() (trim, strip_tags, bytes control).
13. Cabeceras de seguridad: headers.php (CSP, X-Frame-Options: DENY,
    X-Content-Type-Options: nosniff, HSTS, Referrer-Policy, Cache-Control).
14. .htaccess: bloqueo de config.php/headers.php/seguridad.php/login_post.php
    (Apache).
15. Auditoría: log_seguridad() en seguridad_log para login_ok/login_error/
    cuenta_bloqueada/insertar_cami/modificar_cami/eliminar_cami/logout.
16. Detalle de errores: mensajes genéricos; errores en error_log.
17. HTTPS/HSTS: para producción se asume TLS (documentado en manual).

## Nota sobre medidas de la base de datos del taller

Las medidas estudiadas en el taller de seguridad de la base de datos
(control 6: limpieza de cuentas con ALL PRIVILEGES + REVOKE, control 10:
FAILED_LOGIN_ATTEMPTS/PASSWORD_LOCK_TIME, prepared statements, etc.) se
aplican en el proyecto, pero no cuentan como medidas de seguridad web:
las medidas web listadas arriba son las que se detallan en el manual.

## Generación del video (if you want to reproduce)

```
site/README.txt
```
Ver manual + video en:
- Manual_de_Programación.docx
- video/tutorial_sitio_entregapackages.mp4
