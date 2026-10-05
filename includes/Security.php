<?php
/**
 * Security Helper Functions
 * 
 * Input validation and sanitization utilities
 */

/**
 * Validate a DNS name suitable for use in an SPF include: or an A/MX lookup.
 *
 * Underscores are permitted because they are ubiquitous in SPF and DKIM
 * records (_spf.google.com, _netblocks.google.com, _dmarc.example.com).
 * The character class is deliberately narrow: it admits nothing that could
 * be interpreted by a shell, so the value is safe to pass to dig after
 * escapeshellarg() as well.
 *
 * @param string $domain
 * @return bool
 */
function isValidDomain($domain) {
    if (!is_string($domain) || $domain === '' || strlen($domain) > 253) {
        return false;
    }

    // Each label: alphanumerics, hyphen or underscore; must not start or
    // end with a hyphen. At least two labels are required.
    if (!preg_match('/^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)+$/i', $domain)) {
        return false;
    }

    // Reject a trailing dot and any residual whitespace.
    if (str_ends_with($domain, '.') || preg_match('/\s/', $domain)) {
        return false;
    }

    return true;
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
 * Validate a Cloudflare API token's format.
 *
 * Tokens are 40 characters of [A-Za-z0-9_-]. This is a format check only — it
 * cannot tell whether the token is valid, scoped correctly, or still active.
 * Cloudflare remains the authority on that.
 *
 * @param string $token Token to validate
 * @return bool True if the format looks right
 */
function isValidCloudflareApiToken($token) {
    return is_string($token)
        && preg_match('/^[A-Za-z0-9_-]{40}$/', $token) === 1;
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
