<?php
/**
 * Security Helper Functions
 * 
 * Input validation and sanitization utilities
 */

/**
 * Validate domain name format
 * 
 * @param string $domain Domain name to validate
 * @return bool True if valid domain format
 */
function isValidDomain($domain) {
    if (!is_string($domain) || empty($domain) || strlen($domain) > 253) {
        return false;
    }
    
    // RFC 1035 compliant domain validation
    return (bool) preg_match('/^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9]))*$/i', $domain);
}

/**
 * Validate email address
 * 
 * @param string $email Email to validate
 * @return bool True if valid email format
 */
function isValidEmail($email) {
    return is_string($email) && filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Sanitize domain name for shell commands
 * 
 * @param string $domain Domain name
 * @return string|false Sanitized domain or false if invalid
 */
function sanitizeDomainForShell($domain) {
    if (!isValidDomain($domain)) {
        return false;
    }
    return escapeshellarg($domain);
}

/**
 * Sanitize string for database storage
 * 
 * @param string $input String to sanitize
 * @param int $maxLength Maximum length
 * @return string Sanitized string
 */
function sanitizeString($input, $maxLength = 255) {
    if (!is_string($input)) {
        return '';
    }
    return substr(trim($input), 0, $maxLength);
}

/**
 * Sanitize integer
 * 
 * @param mixed $input Value to sanitize
 * @param int $default Default value if invalid
 * @return int Sanitized integer
 */
function sanitizeInt($input, $default = 0) {
    return filter_var($input, FILTER_VALIDATE_INT) !== false ? (int)$input : $default;
}

/**
 * Validate Cloudflare API key format
 * 
 * @param string $key API key to validate
 * @return bool True if valid format
 */
function isValidCloudflareApiKey($key) {
    // Cloudflare API keys are typically 37 characters
    return is_string($key) && strlen($key) >= 30 && preg_match('/^[a-zA-Z0-9_-]+$/', $key);
}

/**
 * Generate CSRF token
 * 
 * @return string CSRF token
 */
function generateCSRFToken() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Verify CSRF token
 * 
 * @param string $token Token to verify
 * @return bool True if valid
 */
function verifyCSRFToken($token) {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Safe redirect with whitelist
 * 
 * @param string $url URL to redirect to
 * @param string $default Default URL if invalid
 * @return void
 */
function safeRedirect($url, $default = 'index.php') {
    // Only allow relative URLs or same-origin
    if (filter_var($url, FILTER_VALIDATE_URL)) {
        $parsed = parse_url($url);
        $currentHost = $_SERVER['HTTP_HOST'] ?? '';
        if (($parsed['host'] ?? '') !== $currentHost) {
            $url = $default;
        }
    }
    
    // Prevent header injection
    $url = preg_replace('/[\r\n]/', '', $url);
    header('Location: ' . $url);
    exit;
}

/**
 * Log security event
 * 
 * @param string $event Event description
 * @param array $context Additional context
 * @return void
 */
function logSecurityEvent($event, $context = []) {
    $logFile = LOG_FILE ?? __DIR__ . '/../logs/security.log';
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    
    $logEntry = sprintf(
        "[%s] [IP: %s] [UA: %s] %s %s\n",
        $timestamp,
        $ip,
        $userAgent,
        $event,
        !empty($context) ? json_encode($context) : ''
    );
    
    error_log($logEntry, 3, $logFile);
}
