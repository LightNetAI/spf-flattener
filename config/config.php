<?php
/**
 * SPF Flattener Configuration
 *
 * Defaults live here. Machine-specific values (database credentials, URL,
 * auto-update switch) belong in config/config.local.php, which is loaded
 * afterwards and is excluded from version control.
 */

/* ------------------------------------------------------------
 * Load the local overrides first. Because every setting below is
 * defined with the ??= pattern, anything already set here wins.
 * ---------------------------------------------------------- */
$localConfig = __DIR__ . '/config.local.php';
if (is_readable($localConfig)) {
    require_once $localConfig;
}

/* ------------------------------------------------------------
 * Defaults — only applied when the local file did not set them.
 * ---------------------------------------------------------- */
defined('DB_HOST')    || define('DB_HOST', 'localhost');
defined('DB_NAME')    || define('DB_NAME', 'spf_flattener');
defined('DB_USER')    || define('DB_USER', 'root');
defined('DB_PASS')    || define('DB_PASS', '');
defined('DB_CHARSET') || define('DB_CHARSET', 'utf8mb4');

// Application settings
defined('APP_NAME')    || define('APP_NAME', 'SPF Flattener');
defined('APP_VERSION') || define('APP_VERSION', '1.0.0');
defined('APP_URL')     || define('APP_URL', 'http://localhost/spf-flattener');

// Cloudflare API settings (may also be stored in the database)
defined('CLOUDFLARE_API_EMAIL') || define('CLOUDFLARE_API_EMAIL', '');
defined('CLOUDFLARE_API_KEY')   || define('CLOUDFLARE_API_KEY', '');

// Email settings
defined('SMTP_SERVER')     || define('SMTP_SERVER', '');
defined('SMTP_PORT')       || define('SMTP_PORT', 587);
defined('SMTP_FROM_EMAIL') || define('SMTP_FROM_EMAIL', '');
defined('SMTP_FROM_NAME')  || define('SMTP_FROM_NAME', 'SPF Flattener');
defined('SMTP_USERNAME')   || define('SMTP_USERNAME', '');
defined('SMTP_PASSWORD')   || define('SMTP_PASSWORD', '');
defined('ENABLE_EMAIL_NOTIFICATIONS') || define('ENABLE_EMAIL_NOTIFICATIONS', true);

// Flattening settings
defined('MAX_SPF_LENGTH')  || define('MAX_SPF_LENGTH', 255);
defined('MAX_DNS_LOOKUPS') || define('MAX_DNS_LOOKUPS', 10);
defined('DNS_CACHE_TTL')   || define('DNS_CACHE_TTL', 3600); // seconds

// Byte budget per generated SPF record. Matches sender_policy_flattener's
// fit_bytes() default of 450, so record splitting mirrors cfspflat.
defined('SPF_RECORD_BYTES') || define('SPF_RECORD_BYTES', 450);

// Logging
defined('LOG_FILE')  || define('LOG_FILE', __DIR__ . '/../logs/spf-flattener.log');
defined('LOG_LEVEL') || define('LOG_LEVEL', 'INFO'); // DEBUG, INFO, WARNING, ERROR

// Auto-update settings
defined('AUTO_UPDATE_ENABLED')  || define('AUTO_UPDATE_ENABLED', false);
defined('AUTO_UPDATE_INTERVAL') || define('AUTO_UPDATE_INTERVAL', 3600); // seconds

// Paths
defined('BASE_PATH')     || define('BASE_PATH', dirname(__DIR__));
defined('INCLUDES_PATH') || define('INCLUDES_PATH', BASE_PATH . '/includes');
defined('ASSETS_PATH')   || define('ASSETS_PATH', BASE_PATH . '/assets');
defined('CONFIG_PATH')   || define('CONFIG_PATH', BASE_PATH . '/config');
defined('CRON_PATH')     || define('CRON_PATH', BASE_PATH . '/cron');
defined('LOGS_PATH')     || define('LOGS_PATH', BASE_PATH . '/logs');

// Create logs directory if it doesn't exist
if (!file_exists(LOGS_PATH)) {
    @mkdir(LOGS_PATH, 0755, true);
}

// Timezone
if (!defined('APP_TIMEZONE')) {
    define('APP_TIMEZONE', 'UTC');
}
date_default_timezone_set(APP_TIMEZONE);

// Error reporting (set display_errors to 0 in production)
defined('APP_DEBUG') || define('APP_DEBUG', false);
error_reporting(E_ALL);
ini_set('display_errors', APP_DEBUG ? '1' : '0');
ini_set('log_errors', '1');
ini_set('error_log', LOG_FILE);

// Do not advertise the PHP version.
ini_set('expose_php', '0');
if (!headers_sent() && PHP_SAPI !== 'cli') {
    header_remove('X-Powered-By');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: same-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    // The app ships its own CSS and a small amount of inline JS for the UI.
    header("Content-Security-Policy: default-src 'self'; "
         . "img-src 'self' data:; "
         . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
         . "font-src 'self' https://fonts.gstatic.com; "
         . "script-src 'self' 'unsafe-inline'; "
         . "connect-src 'self'; "
         . "form-action 'self'; "
         . "frame-ancestors 'none'; "
         . "base-uri 'self'");
}

// Session settings
ini_set('session.cookie_httponly', 1);
ini_set('session.use_strict_mode', 1);
ini_set('session.gc_maxlifetime', 3600);
