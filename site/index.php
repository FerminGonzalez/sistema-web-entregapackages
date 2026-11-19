<?php
/**
 * index.php — Página de inicio del sistema web Entrega de Paquetes.
 *
 * Medidas de seguridad:
 *   - session_start() para mantener sesiones autenticadas.
 *   - headers.php (CSP, X-Frame-Options, etc.).
 *   - h() en los datos impresos.
 */

session_start();
require 'headers.php';
require 'seguridad.php';
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Entrega de Paquetes — Web</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<main class="page">
    <header class="app-header">
        <h1>Entrega de Paquetes <small>— Sistema Web (CS5_IISem_2026)</small></h1>
    </header>

    <section class="card">
        <h2>¿Qué es?</h2>
        <p>
            Sistema de gestión de camióner desarrollado en clase (Informática I).
            Se mantendrá la tabla <code>camionero</code> de la base de datos
            <code>EntregaPaquetes</code> (MySQL 8.4) con controles de seguridad
            web: módulo de Login y módulo de Mantenimiento de Camióner.
        </p>
        <p>
            Todas las operaciones del sitio están protegidas con prevención de
            SQL Injection, XSS, CSRF, rate-limiting, headers de seguridad HttpOnly/SameSite,
            HSTS y auditoría. Ver <a href="../Manual_de_Programación.docx">Manual de Programación</a>.
        </p>
    </section>

    <section class="card">
        <h2>Módulos del sitio</h2>
        <ul class="modules">
            <li>
                <a href="login.php">1. Módulo de Login</a>
                <span class="muted">— Autenticación: CSRF, bcrypt, rate-limit + lockout, session fixation.</span>
            </li>
            <li>
                <a href="mantenimiento.php">2. Módulo de Mantenimiento (CAMIONERO)</a>
                <ul>
                    <li><a href="insertar.php">Insertar camióner</a> — Validación + prepared statements + auditoría</li>
                    <li><a href="modificar.php">Modificar camióner</a> — Validación, CSRF, auditoría</li>
                    <li><a href="eliminar.php">Eliminar camióner</a> — Autorización, confirmación, auditoría</li>
                </ul>
            </li>
        </ul>
    </section>

    <footer class="page-footer">
        <a href="login.php" class="btn btn-primary">Acceder al sistema →</a>
    </footer>
</main>
</body>
</html>
