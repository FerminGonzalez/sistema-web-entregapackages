<?php
/**
 * headers.php
 * Cabeceras de seguridad impuestas en TODA la aplicación web.
 *
 * Las medidas se aplican a todas las respuestas:
 *   - CSP: solo scripts y estilos del propio sitio ('self'), sin execuciones en línea.
 *   - X-Frame-Options: DENY - el sitio no se puede embeber en otra página.
 *   - X-Content-Type-Options: nosniff - el navegador no puede cambiar el tipo MIME.
 *   - Referrer-Policy: no se envía el Referer completo.
 *   - HSTS: obliga HTTPS durante 1 año.
 *   - Cache-Control: no-store, con modified-by-defensive.
 *
 * Con el servidor PHP integrado (php -S) estas cabeceras via PHP funcionan igual;
 * con Apache, se siguen los Includes en .htaccess con Header always set.
 */

header('Content-Security-Policy: '
    . 'default-src \'self\'; '
    . 'script-src \'self\'; '
    . 'style-src \'self\'; '
    . 'img-src \'self\'; '
    . 'font-src \'self\'; '
    . 'object-src \'none\'; '
    . 'base-uri \'self\'; '
    . 'form-action \'self\'; '
    . 'frame-ancestors \'none\';'
);
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('X-XSS-Protection: 0'); // CSP cubre el XSS; desactivamos el filtro legacy
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private');
header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
header('Pragma: no-cache');
