<?php
/**
 * login.php
 * Formulario de inicio de sesión (Módulo de Login).
 *
 * Mejoras de seguridad implementadas (ver seguridad.php y Manual_de_Programación.docx):
 *   - Token CSRF: $_SESSION['csrf_token'] oculto en el formulario; comparación constante
 *     con hash_equals en login_post.php (evita CSRF).
 *   - Saneamiento de usuario/contraseña (limpieza/trim, sin impresión en el formulario).
 *   - Hash falso para usuarios desconocidos (en login_post.php): el tiempo de respuesta
 *     es muy parecido sea el usuario o no (evita oráculos de enumeración).
 *   - Rate limiting basado en intentos fallidos + lockout por cuenta.
 *   - Retardos artificiales entre intentos (min(intentos,6) x 0.25 s).
 */

session_start();
require 'headers.php';
require 'seguridad.php';

if (sesion_expirada()) {
    session_destroy();
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Entrega de Paquetes — Módulo de Login</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<main class="page">
    <header class="app-header">
        <h1>Entrega de Paquetes <small>— Módulo de Login</small></h1>
    </header>

    <section class="card">
        <h2>Iniciar sesión</h2>

        <?php
        $err = isset($_GET['error']) ? $_GET['error'] : null;
        $errores = [
            '1'     => 'Credenciales inválidas.',
            'bloqueado' => 'Tu cuenta está bloqueada temporalmente por intentos fallidos. Intenta más tarde.',
            'csrf'  => 'Token de sesión inválido. Descarga y reparte la página.',
            'vacio' => 'Introduce tu nombre de usuario.',
        ];
        if ($err && array_key_exists((string)$err, $errores)) {
            echo '<div class="alert alert-error" role="alert">' . h($errores[(string)$err]) . '</div>';
        }
        ?>

        <form method="post" action="login_post.php" class="form" novalidate>
            <!-- Medida: CSRF - token único de sesión -->
            <input type="hidden" name="csrf_token" value="<?= h(generar_csrf_token()) ?>">

            <label class="field" for="usuario">
                <span>Usuario</span>
                <input id="usuario" name="usuario" type="text" autocomplete="username"
                       placeholder="admin o operador" maxlength="60" required>
            </label>

            <label class="field" for="password">
                <span>Contraseña</span>
                <input id="password" name="password" type="password" autocomplete="current-password"
                       placeholder="Tu contraseña" maxlength="100" required>
            </label>

            <button type="submit" class="btn btn-primary">Iniciar sesión</button>
        </form>

        <div class="hint">
            <p>Medidas de seguridad activas en este formulario: token CSRF, rate-limiting
               (contando intentos fallidos) y lockout por cuenta. Ver el <a href="../Manual_de_Programación.docx">manual de programación</a>.</p>
        </div>
    </section>

    <footer class="page-footer"><a href="index.php">← Volver al inicio</a></footer>
</main>
</body>
</html>
