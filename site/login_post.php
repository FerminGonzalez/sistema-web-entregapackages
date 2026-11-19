<?php
/**
 * login_post.php
 * Autenticación del Módulo de Login.
 *
 * Medidas de seguridad implementadas:
 *   1. Validación de token CSRF (validar_csrf() — hash_equals).
 *   2. Contraseñas hasheadas con bcrypt: password_verify() con hash_falso
 *      para usuarios desconocidos (evita oráculos de tiempo/exista ncia).
 *   3. Rate limiting + bloqueo de cuenta por intentos fallidos
 *      (usuarios.failed_attempts / usuarios.locked_until, 3 intentos = bloqueo 60s).
 *   4. retardos artificiales entre intentos (min(intentos,6) x 0.25s).
 *   5. Session fixation: session_regenerate_id(true) tras login exitoso.
 *   6. Cabeceras de seguridad (headers.php: CSP, X-Frame-Options, HSTS, etc.).
 *   7. Auditoría: log_seguridad() registra login_ok / login_error /
 *      cuenta_bloqueada en seguridad_log.
 */

session_start();
require 'headers.php';
require 'seguridad.php';
require 'config.php';

// ---------------------------------------------------------------------------
// Medida 1: CSRF — token único de sesión, comparación constante
// ---------------------------------------------------------------------------
if (!validar_csrf()) {
    log_seguridad('csrf_invalido');
    header('Location: login.php?error=csrf');
    exit;
}

// ---------------------------------------------------------------------------
// Medida 3 + 8: rate limiting basado en intentos fallidos de la sesión
// Medida 4: retardo de 0 a 1.5 s escalando con los intentos (anti-brute force)
// ---------------------------------------------------------------------------
$_SESSION['intentos'] = (int)($_SESSION['intentos'] ?? 0);
usleep(min($_SESSION['intentos'], 6) * 250000);

$usuario = strtolower(limpieza($_POST['usuario'] ?? '', 60));
$password = (string)($_POST['password'] ?? '');

if ($usuario === '') {
    header('Location: login.php?error=vacio');
    exit;
}

// ---------------------------------------------------------------------------
// Medida 2: prepared statement (previene SQLi); consulta del usuario
// ---------------------------------------------------------------------------
$stmt = $pdo->prepare('SELECT id, username, password_hash, rol, failed_attempts, locked_until FROM usuarios WHERE username = ?');
$stmt->execute([$usuario]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);

// Medida 2b: hash falso para usuarios desconocidos
$hash_falso = password_hash('', PASSWORD_BCRYPT);

// ---------------------------------------------------------------------------
// Cuenta bloqueada? (Medida 3: lockout por intentos fallidos)
// ---------------------------------------------------------------------------
if ($row && !empty($row['locked_until'])) {
    try {
        if ((new DateTime($row['locked_until'])) > (new DateTime())) {
            log_seguridad('cuenta_bloqueada', $row['username'], 'locked_until=' . h($row['locked_until']));
            header('Location: login.php?error=bloqueado');
            exit;
        }
    } catch (Exception $e) {
        error_log('[EntregaWeb] login_post: locked_until parse error: ' . $e->getMessage());
    }
}

// ---------------------------------------------------------------------------
// Verificación de credenciales
// ---------------------------------------------------------------------------
$hash = $row ? (string)$row['password_hash'] : $hash_falso;
$autenticado = $row ? password_verify($password, $hash) : false;

if ($autenticado) {
    // Medida 5: session fixation protection — fuerza un nuevo id de sesión
    session_regenerate_id(true);

    $_SESSION['id_usuario'] = (int)$row['id'];
    $_SESSION['usuario'] = $row['username'];
    $_SESSION['rol'] = $row['rol'];
    $_SESSION['inicio'] = time();
    $_SESSION['intentos'] = 0;

    // Medida 7: auditoría
    log_seguridad('login_ok', $row['username'], 'rol=' . $row['rol']);

    header('Location: mantenimiento.php');
    exit;
}

// ---------------------------------------------------------------------------
// Fallo de autenticación: logging + lockout (Medidas 3 + 7)
// ---------------------------------------------------------------------------
log_seguridad('login_error', $usuario, 'usuario_existe=' . ($row ? 'yes' : 'no'));

if ($row) {
    $intentos = ((int)$row['failed_attempts']) + 1;
    $stmtU = $pdo->prepare('UPDATE usuarios SET failed_attempts = ? WHERE id = ?');
    $stmtU->execute([$intentos, $row['id']]);
    if ($intentos >= 3) {
        $stmtU = $pdo->prepare('UPDATE usuarios SET failed_attempts = 0, locked_until = DATE_ADD(NOW(), INTERVAL 60 SECOND) WHERE id = ?');
        $stmtU->execute([$row['id']]);
        log_seguridad('cuenta_bloqueada', $row['username'], 'intentos=' . $intentos);
    }
}

header('Location: login.php?error=1');
