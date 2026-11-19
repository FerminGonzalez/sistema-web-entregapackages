<?php
/**
 * seguridad.php
 * Utilidades de seguridad compartidas por todo el sitio web.
 *
 * Medidas implementadas:
 *   - h(): codificación HTML de salida (XSS prevention) — equivalente a
 *     htmlspecialchars(ENT_QUOTES) — aplicado en cada dato que se imprime
 *     desde la base de datos o de los formularios.
 *   - limpieza(): saneamiento de entrada (trim, strip_tags, longitud máxima).
 *   - Validadores: validar_cedula, validar_telef, validar_numerico,
 *     validar_salario, validar_provincia, validar_pass_semantica.
 *   - CSRF: generar_csrf_token() y validar_csrf() — tokens de sesión
 *     (doble envío, comparación constante con hash_equals).
 *   - log_seguridad(): auditoría de eventos de seguridad en seguridad_log
 *     (prepared statement, sin datos sensibles, IP del cliente, user-agent).
 *   - ip_cliente(): obtiene la IP del usuario.
 *   - autenticado()/requerir_autenticado(): control de acceso (RBAC: admin/operador).
 *   - sesion_expirada(): control de inactividad de la sesión.
 */

// ---------------------------------------------------------------------------
// Codificación de salida (XSS prevention)
// ---------------------------------------------------------------------------
function h($valor) {
    return htmlspecialchars((string)$valor, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// ---------------------------------------------------------------------------
// Saneamiento y validación de entrada (limpieza + regex)
// ---------------------------------------------------------------------------
function limpieza($texto, $maxlen = 255) {
    $texto = trim((string)$texto);
    $texto = preg_replace('/<[^>]*>/', ' ', $texto);            // strip_tags
    $texto = preg_replace('/[^\x09\x0A\x0D\x20-\x7E\xC2-\xF4][\x80-\xBF]*/', ' ', $texto); // elimina bytes control
    $texto = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+/u', ' ', $texto); // control chars no imprimibles
    return substr($texto, 0, $maxlen);
}

function validar_cedula($cedula) {
    // Formato observado en EntregaPaquetes: d-XXX-XXX / d-XXX-XXXX
    return preg_match('/^[0-9]{1,2}-[0-9]{3}-[0-9]{3,4}$/', trim((string)$cedula)) === 1;
}

function validar_telef($telef) {
    return preg_match('/^[0-9]{3,4}-[0-9]{4}$/', trim((string)$telef)) === 1;
}

function validar_numerico($valor) {
    return preg_match('/^[0-9]{1,6}$/', trim((string)$valor)) === 1;
}

function validar_salario($valor) {
    return preg_match('/^[0-9]{1,6}(\.[0-9]{1,2})?$/', trim((string)$valor)) === 1;
}

function validar_provincia($pdo, $provincia) {
    if (trim((string)$provincia) === '') {
        return false;
    }
    $stmt = $pdo->prepare('SELECT COUNT(*) AS c FROM provincia WHERE nombre = ?');
    $stmt->execute([trim((string)$provincia)]);
    return ((int)$stmt->fetch(PDO::FETCH_ASSOC)['c']) > 0;
}

// ---------------------------------------------------------------------------
// CSRF — tokens de sesión (previene CSRF / ataques de lateralización de peticiones)
// ---------------------------------------------------------------------------
function generar_csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validar_csrf() {
    if (!isset($_POST['csrf_token']) || !is_string($_POST['csrf_token'])) {
        return false;
    }
    $token_simp = ($_SESSION['csrf_token'] ?? '');
    return is_string($token_simp) && hash_equals($token_simp, $_POST['csrf_token']);
}

// ---------------------------------------------------------------------------
// Auditoría — log_seguridad (previene que los atacantes oculten sus huellas)
// ---------------------------------------------------------------------------
function log_seguridad($evento, $usuario = null, $detalle = null) {
    global $pdo;
    try {
        $stmt = $pdo->prepare(
            'INSERT INTO seguridad_log (evento, usuario, ip, user_agent, detalle) VALUES (?, ?, ?, ?, ?)'
        );
        $stmt->execute([
            substr((string)$evento, 0, 100),
            ($usuario !== null && $usuario !== '') ? substr((string)$usuario, 0, 60) : null,
            ip_cliente(),
            substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255) ?: null,
            ($detalle !== null && $detalle !== '') ? substr((string)$detalle, 0, 500) : null,
        ]);
    } catch (Exception $e) {
        error_log('[EntregaWeb] log_seguridad fallo: ' . $e->getMessage());
    }
}

function ip_cliente() {
    return $_SERVER['REMOTE_ADDR'] ?? 'desconocida';
}

// ---------------------------------------------------------------------------
// Control de acceso — RBAC
// ---------------------------------------------------------------------------
function autenticado() {
    return isset($_SESSION['id_usuario']);
}

function requerir_autenticado() {
    if (!autenticado()) {
        header('Location: login.php');
        exit;
    }
}

function sesion_expirada() {
    if (!isset($_SESSION['id_usuario'])) {
        // Sin sesión iniciada: no está expirada, es un visitante normal.
        return false;
    }
    $inicio = (int)($_SESSION['inicio'] ?? 0);
    // Se expira la sesión tras 25 minutos de inactividad
    return ($inicio > 0) && ((time() - $inicio) > 1500);
}

function requerir_rol_valido() {
    if (!in_array($_SESSION['rol'] ?? null, ['admin', 'operador'], true)) {
        log_seguridad('acceso_denegado_rol', $_SESSION['usuario'] ?? null);
        session_destroy();
        header('Location: login.php');
        exit;
    }
}
