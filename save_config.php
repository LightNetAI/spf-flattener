<?php
/**
 * Save Configuration Handler
 * Processes configuration form submissions
 */

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/includes/Database.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: index.php');
    exit;
}

$db = getDB();
$referer = $_SERVER['HTTP_REFERER'] ?? 'index.php';

try {
    // Cloudflare settings
    if (isset($_POST['cloudflare_api_email'])) {
        $stmt = $db->prepare("
            INSERT INTO config (config_key, config_value) 
            VALUES ('cloudflare_api_email', ?)
            ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)
        ");
        $stmt->execute([$_POST['cloudflare_api_email']]);
    }
    
    if (isset($_POST['cloudflare_api_key']) && !empty($_POST['cloudflare_api_key'])) {
        $stmt = $db->prepare("
            INSERT INTO config (config_key, config_value) 
            VALUES ('cloudflare_api_key', ?)
            ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)
        ");
        $stmt->execute([$_POST['cloudflare_api_key']]);
    }
    
    // SMTP settings
    if (isset($_POST['smtp_server'])) {
        $stmt = $db->prepare("
            INSERT INTO config (config_key, config_value) 
            VALUES ('smtp_server', ?)
            ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)
        ");
        $stmt->execute([$_POST['smtp_server']]);
    }
    
    if (isset($_POST['smtp_port'])) {
        $stmt = $db->prepare("
            INSERT INTO config (config_key, config_value) 
            VALUES ('smtp_port', ?)
            ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)
        ");
        $stmt->execute([$_POST['smtp_port']]);
    }
    
    if (isset($_POST['smtp_from_email'])) {
        $stmt = $db->prepare("
            INSERT INTO config (config_key, config_value) 
            VALUES ('smtp_from_email', ?)
            ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)
        ");
        $stmt->execute([$_POST['smtp_from_email']]);
    }
    
    if (isset($_POST['smtp_from_name'])) {
        $stmt = $db->prepare("
            INSERT INTO config (config_key, config_value) 
            VALUES ('smtp_from_name', ?)
            ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)
        ");
        $stmt->execute([$_POST['smtp_from_name']]);
    }
    
    if (isset($_POST['smtp_username'])) {
        $stmt = $db->prepare("
            INSERT INTO config (config_key, config_value) 
            VALUES ('smtp_username', ?)
            ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)
        ");
        $stmt->execute([$_POST['smtp_username']]);
    }
    
    if (isset($_POST['smtp_password']) && !empty($_POST['smtp_password'])) {
        $stmt = $db->prepare("
            INSERT INTO config (config_key, config_value) 
            VALUES ('smtp_password', ?)
            ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)
        ");
        $stmt->execute([$_POST['smtp_password']]);
    }
    
    // Update local config file if it exists
    $localConfig = CONFIG_PATH . '/config.local.php';
    if (file_exists($localConfig) && is_writable($localConfig)) {
        // Could update the file here, but for now just update database
    }
    
    $_SESSION['message'] = "Configuration saved successfully";
    $_SESSION['message_type'] = 'success';
    
} catch (Exception $e) {
    $_SESSION['message'] = "Error saving configuration: " . $e->getMessage();
    $_SESSION['message_type'] = 'error';
}

header('Location: ' . $referer);
exit;
