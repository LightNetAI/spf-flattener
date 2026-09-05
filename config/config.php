<?php
/**
 * SPF Flattener Configuration
 * 
 * This file contains database and application settings.
 * Edit these values to match your environment.
 */

// Database configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'spf_flattener');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_CHARSET', 'utf8mb4');

// Application settings
define('APP_NAME', 'SPF Flattener');
define('APP_VERSION', '1.0.0');
define('APP_URL', 'http://localhost/spf-flattener');

// Cloudflare API settings (can also be stored in database)
define('CLOUDFLARE_API_EMAIL', '');
define('CLOUDFLARE_API_KEY', '');

// Email settings
define('SMTP_SERVER', '');
define('SMTP_PORT', 587);
define('SMTP_FROM_EMAIL', '');
define('SMTP_FROM_NAME', 'SPF Flattener');
define('SMTP_USERNAME', '');
define('SMTP_PASSWORD', '');
define('ENABLE_EMAIL_NOTIFICATIONS', true);

// Flattening settings
define('MAX_SPF_LENGTH', 255);
define('MAX_DNS_LOOKUPS', 10);
define('DNS_CACHE_TTL', 3600); // seconds

// Logging
define('LOG_FILE', __DIR__ . '/../logs/spf-flattener.log');
define('LOG_LEVEL', 'INFO'); // DEBUG, INFO, WARNING, ERROR

// Auto-update settings
define('AUTO_UPDATE_ENABLED', false);
define('AUTO_UPDATE_INTERVAL', 3600); // seconds between checks

// Paths
define('BASE_PATH', dirname(__DIR__));
define('INCLUDES_PATH', BASE_PATH . '/includes');
define('ASSETS_PATH', BASE_PATH . '/assets');
define('CONFIG_PATH', BASE_PATH . '/config');
define('CRON_PATH', BASE_PATH . '/cron');
define('LOGS_PATH', BASE_PATH . '/logs');

// Create logs directory if it doesn't exist
if (!file_exists(LOGS_PATH)) {
    mkdir(LOGS_PATH, 0755, true);
}

// Timezone
date_default_timezone_set('UTC');

// Error reporting (set to 0 in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);
ini_set('error_log', LOG_FILE);

// Session settings
ini_set('session.cookie_httponly', 1);
ini_set('session.use_strict_mode', 1);
ini_set('session.gc_maxlifetime', 3600);
