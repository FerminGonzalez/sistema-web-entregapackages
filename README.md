# Sistema Web Entrega de Paquetes

Sistema web para la gestión de Camióner — Desarrollado en el semestre (CS5_IISem_2026).

Módulos: Módulo de Login + Módulo de Mantenimiento (Camióner) con medidas de seguridad web.

## Documentos

| Archivo | Descripción |
|---|---|
| `Manual_de_Programación.docx` | Manual completo: código de todos los módulos, medidas de seguridad y material de investigación. |
| `db_schema_web.sql` | Script de instalación de la base de datos (tablas `usuarios`, `seguridad_log`). |
| `setup_users.sql` | Cuentas de acceso de prueba (hasheadas con bcrypt). |
| `video/tutorial_sitio_entregapackages.mp4` | Video tutorial con demostración de las medidas de seguridad. |
| `site/` | Código fuente del sitio web (PHP 8.3). |

## Arranque rápido

1. Arranca el servidor web (PHP):
   ```
   C:\php83\php.exe -S 127.0.0.1:8080 -t site
   ```
2. Accede a [http://127.0.0.1:8080/login.php](http://127.0.0.1:8080/login.php)
3. Cuentas de prueba:
   - `admin` / `Adm1n$EntregaWeb2026`
   - `operador` / `Oper4$SistemaWeb2026`

## Medidas de seguridad implementadas

Ver el **Manual_de_Programación.docx** (sección "Matriz de medidas de seguridad web"):
SQLi prevention, XSS prevention, CSRF, bcrypt (contraseñas hasheadas), rate-limiting
y lockout por intentos fallidos, session fixation, RBAC, expiración de sesión,
CSP/HSTS/Cabeceras HttpOnly/SameSite/Strict, validación de entrada, saneamiento de
entrada, log_seguridad (auditoría), detalle de errores controlado, etc. (17 medidas).

## Bitácora de seguridad

```sql
SELECT * FROM EntregaPaquetes.seguridad_log ORDER BY id DESC;
```
