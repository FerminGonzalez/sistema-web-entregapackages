<?php
/**
 * modificar.php — Modificar camióner (Módulo de Mantenimiento)
 *
 * Medidas de seguridad implementadas:
 *   1. Control de acceso (RBAC) + expiración de sesión.
 *   2. CSRF: validar_csrf() en el POST.
 *   3. Validación estricta de entrada (validar_cedula, validar_telef,
 *      validar_provincia, validar_numerico, validar_salario).
 *   4. prepared statements en UPDATE/SELECT (SQLi prevention).
 *   5. Cualquier dato impreso está codificado (h() = htmlspecialchars).
 *   6. Auditoría: log_seguridad('modificar_cami', usuario, cedula).
 */

session_start();
require 'headers.php';
require 'seguridad.php';
require 'config.php';

if (sesion_expirada()) { session_destroy(); header('Location: login.php'); exit; }
if (!autenticado()) { header('Location: login.php'); exit; }

$cedula = isset($_GET['cedula']) ? limpieza($_GET['cedula'], 13) : '';
if (!validar_cedula($cedula)) {
    header('Location: mantenimiento.php');
    exit;
}

// Fijamos la consulta
$stmt = $pdo->prepare(
    'SELECT cedula, pnombre, snombre, papellido, sapellido, telef, provincia, distrito, corregim, calleave, numcasa, salario
     FROM camionero WHERE cedula = ?'
);
$stmt->execute([$cedula]);
$fila = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$fila) {
    $errores = ['Camióner no encontrado en la base de datos.'];
    $fila = null;
} else {
    $errores = [];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($fila)) {
    header('Location: mantenimiento.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validar_csrf()) {
        $errores[] = 'El token de la sesión es inválido o está caducado.';
    } else {
        $cedulaNueva  = limpieza($_POST['cedula'] ?? '', 13);
        $pnombre      = limpieza($_POST['pnombre'] ?? '', 10);
        $snombre      = limpieza($_POST['snombre'] ?? '', 10);
        $papellido    = limpieza($_POST['papellido'] ?? '', 12);
        $sapellido    = limpieza($_POST['sapellido'] ?? '', 12);
        $telef        = limpieza($_POST['telef'] ?? '', 15);
        $provincia    = limpieza($_POST['provincia'] ?? '', 15);
        $distrito     = limpieza($_POST['distrito'] ?? '', 15);
        $corregim     = limpieza($_POST['corregim'] ?? '', 15);
        $calleave     = limpieza($_POST['calleave'] ?? '', 15);
        $numcasa      = limpieza($_POST['numcasa'] ?? '', 4);
        $salario      = limpieza($_POST['salario'] ?? '', 8);

        if (!validar_cedula($cedulaNueva)) {
            $errores[] = 'Cédula inválida.';
        }
        if (!preg_match('/^[A-Za-z ]{2,10}$/', $pnombre) && $pnombre !== '') {
            $errores[] = 'Primer nombre inválido.';
        }
        if (!preg_match('/^[A-Za-z ]{2,10}$/', $snombre) && $snombre !== '') {
            $errores[] = 'Segundo nombre inválido.';
        }
        if (!preg_match('/^[A-Za-z ]{2,12}$/', $papellido) && $papellido !== '') {
            $errores[] = 'Primer apellido inválido.';
        }
        if (!preg_match('/^[A-Za-z ]{2,12}$/', $sapellido) && $sapellido !== '') {
            $errores[] = 'Segundo apellido inválido.';
        }
        if (!validar_telef($telef)) {
            $errores[] = 'Teléfono inválido.';
        }
        if (!validar_provincia($pdo, $provincia)) {
            $errores[] = 'Provincia no válida.';
        }
        if ($distrito === '' || $corregim === '' || $calleave === '') {
            $errores[] = 'Los campos Distrito, Corregim y Calle ave. son obligatorios.';
        }
        if (!validar_numerico($numcasa)) {
            $errores[] = 'Número de casa inválido.';
        }
        if (!validar_salario($salario)) {
            $errores[] = 'Salario inválido.';
        }

        if (empty($errores)) {
            // Medida 4: UPDATE con prepared statement
            $stmtU = $pdo->prepare(
                'UPDATE camionero SET cedula = ?, pnombre = ?, snombre = ?, papellido = ?, sapellido = ?,
                         telef = ?, provincia = ?, distrito = ?, corregim = ?, calleave = ?,
                         numcasa = ?, salario = ?
                 WHERE cedula = ?'
            );
            try {
                $stmtU->execute([
                    $cedulaNueva, $pnombre, $snombre, $papellido, $sapellido,
                    $telef, $provincia, $distrito, $corregim, $calleave,
                    (int)$numcasa, (float)$salario, $cedula,
                ]);
                if ($stmtU->rowCount() === 0) {
                    $errores[] = 'Camióner inexistente (cedula ' . h($cedula) . ').';
                } else {
                    log_seguridad('modificar_cami', $_SESSION['usuario'], 'cedula=' . $cedulaNueva);
                    header('Location: mantenimiento.php');
                    exit;
                }
            } catch (PDOException $e) {
                $errores[] = 'Error al modificar (cedula duplicada o datos rechazados).';
                error_log('[EntregaWeb] modificar_cami: ' . $e->getMessage());
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Entrega de Paquetes — Modificar camióner</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<main class="page">
    <header class="app-header">
        <h1>Entrega de Paquetes <small>— Modificar camióner</small></h1>
    </header>

    <section class="card">
        <p><a href="mantenimiento.php" class="btn">← Volver al mantenimiento</a></p>

        <?php if (!empty($errores)): ?>
            <div class="alert alert-error" role="alert">
                <p>No se actualizó. Errores:</p>
                <ul>
                    <?php foreach ($errores as $err): ?><li><?= h($err) ?></li><?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <form method="post" action="modificar.php?cedula=<?= h($cedula) ?>" class="form">
            <input type="hidden" name="csrf_token" value="<?= h(generar_csrf_token()) ?>">

            <?php $v = function ($f, $def = '') use ($fila) { return $fila ? (string)$fila[$f] : $def; }; ?>
            <label class="field">
                <span>Cédula</span>
                <input name="cedula" type="text" maxlength="13" value="<?= h($v('cedula', $cedula)) ?>" required>
            </label>
            <label class="field">
                <span>Primer nombre</span>
                <input name="pnombre" type="text" maxlength="10" value="<?= h($v('pnombre')) ?>" required>
            </label>
            <label class="field">
                <span>Segundo nombre</span>
                <input name="snombre" type="text" maxlength="10" value="<?= h($v('snombre')) ?>" required>
            </label>
            <label class="field">
                <span>Primer apellido</span>
                <input name="papellido" type="text" maxlength="12" value="<?= h($v('papellido')) ?>" required>
            </label>
            <label class="field">
                <span>Segundo apellido</span>
                <input name="sapellido" type="text" maxlength="12" value="<?= h($v('sapellido')) ?>" required>
            </label>
            <label class="field">
                <span>Teléfono</span>
                <input name="telef" type="text" maxlength="15" value="<?= h($v('telef')) ?>" required>
            </label>
            <label class="field">
                <span>Provincia</span>
                <select name="provincia" required>
                    <option value="">Selecciona una provincia</option>
                    <?php foreach ($pdo->query('SELECT nombre FROM provincia ORDER BY codprov') as $row): ?>
                        <?php $sel = ($fila && $fila['provincia'] === $row['nombre']) ? 'selected' : ''; ?>
                        <option value="<?= h($row['nombre']) ?>" <?= $sel ?>><?= h($row['nombre']) ?></option>
                    <?php endforeach; ?>
                </select>
            </label>
            <label class="field">
                <span>Distrito</span>
                <input name="distrito" type="text" maxlength="15" value="<?= h($v('distrito')) ?>" required>
            </label>
            <label class="field">
                <span>Corregim</span>
                <input name="corregim" type="text" maxlength="15" value="<?= h($v('corregim')) ?>" required>
            </label>
            <label class="field">
                <span>Calle a.</span>
                <input name="calleave" type="text" maxlength="15" value="<?= h($v('calleave')) ?>" required>
            </label>
            <label class="field">
                <span>Núm. casa</span>
                <input name="numcasa" type="text" value="<?= h($v('numcasa')) ?>" required>
            </label>
            <label class="field">
                <span>Salario</span>
                <input name="salario" type="text" value="<?= h($v('salario')) ?>" required>
            </label>

            <button type="submit" class="btn btn-primary">Guardar cambios</button>
        </form>
    </section>
</main>
</body>
</html>
