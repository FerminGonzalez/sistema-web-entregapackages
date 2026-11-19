<?php
/**
 * eliminar.php — Eliminar camióner (Módulo de Mantenimiento)
 *
 * Medidas de seguridad implementadas:
 *   1. Control de acceso (RBAC: admin/operador) + expiración de sesión.
 *   2. CSRF: validar_csrf() en el POST (previene CSRF en eliminación).
 *   3. Validación de la cédula (validar_cedula).
 *   4. prepared statement DELETE (previene SQLi).
 *   5. Confirmación visual del usuario antes de ejecutar el DELETE.
 *   6. Auditoría: log_seguridad('eliminar_cami', usuario, cedula).
 */

session_start();
require 'headers.php';
require 'seguridad.php';
require 'config.php';

if (sesion_expirada()) { session_destroy(); header('Location: login.php'); exit; }
if (!autenticado()) { header('Location: login.php'); exit; }

$cedula = isset($_GET['cedula']) ? limpieza($_GET['cedula'], 13) : (isset($_POST['cedula']) ? limpieza($_POST['cedula'], 13) : '');
if (!validar_cedula($cedula)) {
    header('Location: mantenimiento.php');
    exit;
}

$errores = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Medida 2: CSRF
    if (!validar_csrf()) {
        $errores[] = 'El token de la sesión es inválido o está caducado.';
    } else {
        // Medida 4: DELETE con prepared statement
        $stmt = $pdo->prepare('DELETE FROM camionero WHERE cedula = ?');
        try {
            $stmt->execute([$cedula]);
            if ($stmt->rowCount() === 1) {
                // Medida 6: auditoría
                log_seguridad('eliminar_cami', $_SESSION['usuario'], 'cedula=' . $cedula);
                header('Location: mantenimiento.php');
                exit;
            } else {
                $errores[] = 'Camióner inexistente o sin permisos para eliminarlo.';
            }
        } catch (PDOException $e) {
            $errores[] = 'Error al eliminar.';
            error_log('[EntregaWeb] eliminar_cami: ' . $e->getMessage());
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Entrega de Paquetes — Eliminar camióner</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<main class="page">
    <header class="app-header">
        <h1>Entrega de Paquetes <small>— Eliminar camióner</small></h1>
    </header>

    <section class="card">
        <p><a href="mantenimiento.php" class="btn">← Volver al mantenimiento</a></p>

        <?php if (!empty($errores)): ?>
            <div class="alert alert-error" role="alert">
                <?php foreach ($errores as $err): ?><p><?= h($err) ?></p><?php endforeach; ?>
            </div>
        <?php endif; ?>

        <h3>¿Confirmar la eliminación?</h3>
        <p>Se van a eliminar todos los datos del camióner con cédula <code><?= h($cedula) ?></code>:</p>
        <ul>
            <li>Eliminación definitiva (no hay deshacer en la base de datos).</li>
            <li>Lo registraremos en la bitácora de seguridad (seguridad_log).</li>
            <li>Eliminamos cualquier información sensible.</li>
        </ul>

        <form method="post" action="eliminar.php" class="form">
            <!-- Medida 2: CSRF -->
            <input type="hidden" name="csrf_token" value="<?= h(generar_csrf_token()) ?>">
            <input type="hidden" name="cedula" value="<?= h($cedula) ?>">
            <button type="submit" class="btn btn-danger"
                    onclick="return confirm('¿Estás seguro de eliminar este camióner?\nCédula: <?= addslashes(h($cedula)) ?>');">
                Confirmar eliminación
            </button>
            <a href="mantenimiento.php" class="btn">Cancelar</a>
        </form>
    </section>
</main>
</body>
</html>
