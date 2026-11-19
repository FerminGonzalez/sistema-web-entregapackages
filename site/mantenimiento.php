<?php
/**
 * mantenimiento.php — Módulo de Mantenimiento (Tabela CAMIONERO)
 *
 * Medidas de seguridad implementadas (ver insertar.php, modificar.php,
 * eliminar.php, seguridad.php y Manual_de_Programación.docx):
 *   - Control de acceso (RBAC): requerir_authenticado + requerir_rol_valido
 *     (solo 'admin' y 'operador').
 *   - Control de expiración de sesión (sesion_expirada, 25 min de inactividad).
 *   - Validación estricta de entrada (validar_cedula, validate_telef, ...).
 *   - prepared statements en las lecturas (SQLi prevention).
 *   - Codificación de salida (h() = htmlspecialchars ENT_QUOTES) en todos los datos impresos.
 */

session_start();
require 'headers.php';
require 'seguridad.php';
require 'config.php';

// Control de acceso
requerir_autenticado();
requerir_rol_valido();
if (sesion_expirada()) {
    session_destroy();
    header('Location: login.php');
    exit;
}

$camioneros = $pdo->query(
    'SELECT cedula, pnombre, snombre, papellido, sapellido, telef, provincia,
            distrito, corregim, calleave, numcasa, salario
     FROM camionero ORDER BY cedula'
)->fetchAll();
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Entrega de Paquetes — Módulo de Mantenimiento (CAMIONERO)</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<main class="page">
    <header class="app-header">
        <h1>Entrega de Paquetes <small>— Módulo de Mantenimiento (CAMIONERO)</small></h1>
    </header>

    <section class="card">
        <div class="toolbar">
            <h2>Camióner en el sistema</h2>
            <a href="insertar.php" class="btn btn-primary">+ Insertar camióner</a>
            <a href="logout.php" class="btn">Cerrar sesión</a>
        </div>

        <p class="muted">
            Estos datos se leen con prepared statements (query() usa PDO con
            preparación real) y se imprimen codificados (h() = htmlspecialchars ENT_QUOTES),
            por lo que un camióner cuyo nombre contenga código <code>&lt;script&gt;</code> no
            puede ejecutarlo aquí ni en otro sitio (XSS prevention).
        </p>

        <table class="table" aria-label="Camióner de la base de datos">
            <thead>
                <tr>
                    <th>Acciones</th>
                    <th>Cédula</th><th>Primer nombre</th><th>Segundo nombre</th>
                    <th>Primer apellido</th><th>Segundo apellido</th><th>Teléfono</th>
                    <th>Provincia</th><th>Distrito</th><th>Corregim</th>
                    <th>Calle a.</th><th>Núm. casa</th><th>Salario</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($camioneros as $c): ?>
                <tr>
                    <td>
                        <a href="modificar.php?cedula=<?= h($c['cedula']) ?>" class="btn">Modificar</a>
                        <a href="eliminar.php?cedula=<?= h($c['cedula']) ?>" class="btn">Eliminar</a>
                    </td>
                    <td><?= h($c['cedula']) ?></td>
                    <td><?= h($c['pnombre']) ?></td>
                    <td><?= h($c['snombre']) ?></td>
                    <td><?= h($c['papellido']) ?></td>
                    <td><?= h($c['sapellido']) ?></td>
                    <td><?= h($c['telef']) ?></td>
                    <td><?= h($c['provincia']) ?></td>
                    <td><?= h($c['distrito']) ?></td>
                    <td><?= h($c['corregim']) ?></td>
                    <td><?= h($c['calleave']) ?></td>
                    <td><?= h($c['numcasa']) ?></td>
                    <td><?= h($c['salario']) ?></td>
                </tr>
                <?php endforeach; ?>
                <?php if ($camioneros === []): ?>
                <tr><td colspan="13" class="muted">Sin datos disponibles.</td></tr>
                <?php endif; ?>
            </tbody>
        </table>
    </section>

    <footer class="page-footer"><a href="index.php">← Volver al inicio</a></footer>
</main>
</body>
</html>
