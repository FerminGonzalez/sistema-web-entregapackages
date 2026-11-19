<?php
/**
 * config.php
 * Conexión a la base de datos del sistema Entrega de Paquetes (Web).
 *
 * Medidas de seguridad implementadas en el sitio:
 *   - PDO con prepared statements reales: PDO::ATTR_EMULATE_PREPARES => false.
 *     Previene inyecciones SQL en todos los inserts/updates/deletes.
 *   - Credenciales del servidor de BD declaradas aquí (no se envían al usuario web).
 *   - Errores de conexión: mensaje genérico al usuario; detalle en el log de errores.
 *   - Conexión desde 127.0.0.1 (el bind-address del servidor portátil ya está restringido a loopback).
 *   - Transacciones y excepciones activadas; todo el logging de seguridad va a seguridad_log.
 *
 * Ver Manual_de_Programación.docx para la guía completa de cada medida.
 */
try {
    $pdo = new PDO(
        'mysql:host=127.0.0.1;port=3306;dbname=EntregaPaquetes;charset=utf8mb4',
        'root',
        'Root$Entrega2026',
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false, // prepared statements reales (previene SQLi)
            PDO::ATTR_STRINGIFY_FETCHES => false, // tipos de datos fieles a la DB
        ]
    );
} catch (PDOException $e) {
    // Detalle del error solo en el log; al usuario se le muestra algo genérico
    error_log('[EntregaWeb] Fallo de conexión a la BD: ' . $e->getMessage());
    die('Error de conexión a la base de datos.');
}
