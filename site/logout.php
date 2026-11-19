<?php
/**
 * logout.php
 * Cerrar sesión.
 *
 * Medidas implementadas:
 *   - Auditoría: log_seguridad('logout', usuario).
 *   - Destrucción de la sesión + invalidación de la cookie de sesión.
 */

session_start();
require 'headers.php';
require 'seguridad.php';
require 'config.php';

$usuario = $_SESSION['usuario'] ?? null;
log_seguridad('logout', $usuario);

session_destroy();
if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), '', time() - 42000, '/', null, false, true);
}
header('Location: login.php');
