-- =====================================================================
-- SISTEMA WEB ENTREGAPAQUETES
-- BASE DE DATOS: EntregaPaquetes   |   MySQL 8.4   |   PHP 8.3 (site/)
--
-- Esquema añadido por el proyecto web (situado junto al informe del taller)
--
-- NOTA (selguridad web): las medidas aplicadas a la base de datos del taller
-- (control 6, control 10, prepared statements, etc.) se aplican también en
-- este sitio, pero no cuentan como medidas de seguridad web.
-- =====================================================================

-- Cuentas de acceso al sitio (hasheadas con bcrypt, llenado por setup_users.php)
CREATE TABLE IF NOT EXISTS usuarios (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username        VARCHAR(60)  NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    rol             ENUM('admin','operador') NOT NULL DEFAULT 'operador',
    email           VARCHAR(120) NULL,
    failed_attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
    locked_until    DATETIME NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Bitácora de eventos de seguridad del sitio web (auditoría)
CREATE TABLE IF NOT EXISTS seguridad_log (
    id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    evento     VARCHAR(100)  NOT NULL,
    usuario    VARCHAR(60)   NULL,
    ip         VARCHAR(64)   NULL,
    user_agent VARCHAR(255)  NULL,
    detalle    TEXT          NULL,
    creado_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
