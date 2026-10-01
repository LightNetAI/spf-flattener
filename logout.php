<?php
/**
 * Logout handler
 */

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/includes/Database.php';
require_once __DIR__ . '/includes/Security.php';
require_once __DIR__ . '/includes/Auth.php';

Auth::startSession();
$auth = new Auth();

// Accept GET only with a valid session; POST preferred so links can't be forced.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !verifyCSRFToken($_POST['csrf_token'] ?? '')) {
    header('Location: index.php');
    exit;
}

$auth->logout();
header('Location: login.php');
exit;
