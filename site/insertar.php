<?php
/**
 * insertar.php — Insertar camióner (Módulo de Mantenimiento)
 *
 * Medidas de seguridad implementadas:
 *   1. Control de acceso (RBAC: admin/operador) + expiración de sesión.
 *   2. CSRF: validar_csrf() (token de sesión con hash_equals).
 *   3. Validación estricta de entrada: validar_cedula (formato d-XXX-XXXX),
 *      validar_telef, validar_provincia (contra provincia table),
 *      validar_numerico (numcasa), validar_salario (decimal).
 *   4. Saneamiento: limpieza() (trim + strip_tags + longitud máxima) para los
 *      campos de texto; preg_replace de control chars invisibles.
 *   5. prepared statement INSERT (previene SQLi).
 *   6. catch PDOException: mensaje genérico + error_log.
 *   7. Auditoría: log_seguridad('insertar_cami', usuario, cedula) en seguridad_log.
 */

session_start();
require 'headers.php';
require 'seguridad.php';
require 'config.php';

if (sesion_expirada()) { session_destroy(); header('Location: login.php'); exit; }
if (!autenticado()) { header('Location: login.php'); exit; }

$errores = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // ------------------------------------------------------------------
    // Medida 2: validación de token CSRF
    // ------------------------------------------------------------------
    if (!validar_csrf()) {
        $errores[] = 'El token de la sesión es inválido o está caducado.';
    }

    // ------------------------------------------------------------------
    // Medidas 3 + 4: validación y saneamiento de entrada
    // ------------------------------------------------------------------
    $cedula    = limpieza($_POST['cedula'] ?? '', 13);
    $pnombre   = limpieza($_POST['pnombre'] ?? '', 10);
    $snombre   = limpieza($_POST['snombre'] ?? '', 10);
    $papellido = limpieza($_POST['papellido'] ?? '', 12);
    $sapellido = limpieza($_POST['sapellido'] ?? '', 12);
    $telef     = limpieza($_POST['telef'] ?? '', 15);
    $provincia = limpieza($_POST['provincia'] ?? '', 15);
    $distrito  = limpieza($_POST['distrito'] ?? '', 15);
    $corregim  = limpieza($_POST['corregim'] ?? '', 15);
    $calleave  = limpieza($_POST['calleave'] ?? '', 15);
    $numcasa   = limpieza($_POST['numcasa'] ?? '', 4);
    $salario   = limpieza($_POST['salario'] ?? '', 8);

    if (!validar_cedula($cedula)) {
        $errores[] = 'Cédula inválida (formato observado en EntregaPaquetes: d-XXX-XXXX, ej. 2-345-678).';
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
        $errores[] = 'Teléfono inválido (formato observado: XXXX-XXXX).';
    }
    if (!validar_provincia($pdo, $provincia)) {
        $errores[] = 'Provincia no válida: elige un valor de la tabla provincia.';
    }
    if ($distrito === '' || $corregim === '' || $calleave === '') {
        $errores[] = 'Los campos Distrito, Corregim y Calle ave. son obligatorios.';
    }
    if (!validar_numerico($numcasa)) {
        $errores[] = 'Número de casa inválido (debe ser un número entero).';
    }
    if (!validar_salario($salario)) {
        $errores[] = 'Salario inválido (debe ser numérico, Ej. 459.08).';
    }

    if (empty($errores)) {
        // ------------------------------------------------------------------
        // Medida 5: prepared statement INSERT
        // ------------------------------------------------------------------
        $stmt = $pdo->prepare(
            'INSERT INTO camionero (cedula, pnombre, snombre, papellido, sapellido, telef, provincia, distrito, corregim, calleave, numcasa, salario)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        );
        try {
            $stmt->execute([
                $cedula, $pnombre, $snombre, $papellido, $sapellido,
                $telef, $provincia, $distrito, $corregim, $calleave,
                (int)$numcasa, (float)$salario,
            ]);

            // ----------------------------------------------------------------
            // Medida 7: auditoría
            // ----------------------------------------------------------------
            log_seguridad('insertar_cami', $_SESSION['usuario'], 'cedula=' . $cedula);

            header('Location: mantenimiento.php');
            exit;
        } catch (PDOException $e) {
            // ----------------------------------------------------------------
            // Medida 6: mensaje genérico + log detallado en el servidor
            // ----------------------------------------------------------------
            $errores[] = 'Error al insertar el camióner (cedula duplicada o datos rechazados).';
            error_log('[EntregaWeb] insertar_cami: ' . $e->getMessage());
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Entrega de Paquetes — Insertar camióner</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<main class="page">
    <header class="app-header">
        <h1>Entrega de Paquetes <small>— Insertar camióner</small></h1>
    </header>

    <section class="card">
        <p><a href="mantenimiento.php" class="btn">← Volver al mantenimiento</a></p>

        <?php if (!empty($errores)): ?>
            <div class="alert alert-error" role="alert">
                <p>No se insertó. Errores:</p>
                <ul>
                    <?php foreach ($errores as $err): ?><li><?= h($err) ?></li><?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <form method="post" action="insertar.php" class="form">
            <!-- Medida 2: CSRF -->
            <input type="hidden" name="csrf_token" value="<?= h(generar_csrf_token()) ?>">

            <label class="field">
                <span>Cédula</span>
                <input name="cedula" type="text" placeholder="Ej. 2-345-678" maxlength="13"
                       value="<?= h($cedula ?? '') ?>" required>
            </label>
            <label class="field">
                <span>Primer nombre</span>
                <input name="pnombre" type="text" maxlength="10" value="<?= h($pnombre ?? '') ?>" required>
            </label>
            <label class="field">
                <span>Segundo nombre</span>
                <input name="snombre" type="text" maxlength="10" value="<?= h($snombre ?? '') ?>" required>
            </label>
            <label class="field">
                <span>Primer apellido</span>
                <input name="papellido" type="text" maxlength="12" value="<?= h($papellido ?? '') ?>" required>
            </label>
            <label class="field">
                <span>Segundo apellido</span>
                <input name="sapellido" type="text" maxlength="12" value="<?= h($sapellido ?? '') ?>" required>
            </label>
            <label class="field">
                <span>Teléfono</span>
                <input name="telef" type="text" placeholder="Ej. 6834-3333" maxlength="15" value="<?= h($telef ?? '') ?>" required>
            </label>
            <label class="field">
                <span>Provincia</span>
                <select name="provincia" required>
                    <option value="">Selecciona una provincia</option>
                    <?php foreach ($pdo->query('SELECT nombre FROM provincia ORDER BY codprov') as $row): ?>
                        <option value="<?= h($row['nombre']) ?>" <?= (isset($provincia) && $provincia === $row['nombre']) ? 'selected' : '' ?>>
                            <?= h($row['nombre']) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </label>
            <label class="field">
                <span>Distrito</span>
                <input name="distrito" type="text" maxlength="15" value="<?= h($distrito ?? '') ?>" required>
            </label>
            <label class="field">
                <span>Corregim</span>
                <input name="corregim" type="text" maxlength="15" value="<?= h($corregim ?? '') ?>" required>
            </label>
            <label class="field">
                <span>Calle a.</span>
                <input name="calleave" type="text" maxlength="15" value="<?= h($calleave ?? '') ?>" required>
            </label>
            <label class="field">
                <span>Núm. casa</span>
                <input name="numcasa" type="text" placeholder="Ej. 12" value="<?= h($numcasa ?? '') ?>" required>
            </label>
            <label class="field">
                <span>Salario</span>
                <input name="salario" type="text" placeholder="Ej. 459.08" value="<?= h($salario ?? '') ?>" required>
            </label>

            <button type="submit" class="btn btn-primary">Insertar camióner</button>
        </form>
    </section>
</main>
</body>
</html>
