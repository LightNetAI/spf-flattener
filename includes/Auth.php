<?php
/**
 * Authentication & Session Management
 *
 * Username / password login with:
 *  - Argon2id (or bcrypt) password hashing
 *  - Brute-force lockout
 *  - Session hardening (regeneration, idle timeout, fingerprint binding)
 *  - Audit logging (date/time, ip, action, username)
 */

require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/Security.php';

class Auth {
    private $db;

    /** Failed attempts before the account is locked */
    const MAX_FAILED_ATTEMPTS = 5;
    /** Lockout duration in seconds (15 minutes) */
    const LOCKOUT_SECONDS = 900;
    /** Session idle timeout in seconds (30 minutes) */
    const IDLE_TIMEOUT = 1800;

    public function __construct() {
        $this->db = getDB();
    }

    /* --------------------------------------------------------
     * Session bootstrap
     * ------------------------------------------------------ */

    /**
     * Start a hardened session. Safe to call multiple times.
     */
    public static function startSession() {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');

        session_set_cookie_params([
            'lifetime' => 0,
            'path'     => '/',
            'domain'   => '',
            'secure'   => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);

        session_name('spfsid');
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        session_start();
    }

    /* --------------------------------------------------------
     * Authentication
     * ------------------------------------------------------ */

    /**
     * Attempt a login.
     *
     * @param string $username
     * @param string $password
     * @return array{success:bool, error?:string, user?:array}
     */
    public function login($username, $password) {
        $username = sanitizeString($username, 64);

        if ($username === '' || $password === '') {
            return ['success' => false, 'error' => 'Username and password are required.'];
        }

        $stmt = $this->db->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        // Uniform failure message — do not reveal which part was wrong.
        if (!$user) {
            $this->audit(null, $username, 'LOGIN_FAIL', 'Unknown username');
            usleep(random_int(150000, 350000)); // small timing jitter
            return ['success' => false, 'error' => 'Invalid username or password.'];
        }

        if (!$user['is_active']) {
            $this->audit($user['id'], $username, 'LOGIN_FAIL', 'Account disabled');
            return ['success' => false, 'error' => 'This account is disabled.'];
        }

        if (!empty($user['locked_until']) && strtotime($user['locked_until']) > time()) {
            $mins = (int) ceil((strtotime($user['locked_until']) - time()) / 60);
            $this->audit($user['id'], $username, 'LOGIN_FAIL', 'Account locked');
            return ['success' => false, 'error' => "Account locked. Try again in {$mins} minute(s)."];
        }

        if (!password_verify($password, $user['password_hash'])) {
            $this->registerFailedAttempt($user);
            $this->audit($user['id'], $username, 'LOGIN_FAIL', 'Bad password');
            return ['success' => false, 'error' => 'Invalid username or password.'];
        }

        // Success — clear counters and (re)hash if the algorithm changed.
        if (password_needs_rehash($user['password_hash'], $this->hashAlgorithm())) {
            $newHash = password_hash($password, $this->hashAlgorithm());
            $stmt = $this->db->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
            $stmt->execute([$newHash, $user['id']]);
        }

        $stmt = $this->db->prepare("
            UPDATE users
               SET failed_attempts = 0,
                   locked_until = NULL,
                   last_login_at = NOW(),
                   last_login_ip = ?
             WHERE id = ?
        ");
        $stmt->execute([$this->clientIp(), $user['id']]);

        $this->establishSession($user);
        $this->audit($user['id'], $user['username'], 'LOGIN_SUCCESS', null);

        return ['success' => true, 'user' => $user];
    }

    private function registerFailedAttempt($user) {
        $attempts = (int) $user['failed_attempts'] + 1;
        $lockedUntil = null;

        if ($attempts >= self::MAX_FAILED_ATTEMPTS) {
            $lockedUntil = date('Y-m-d H:i:s', time() + self::LOCKOUT_SECONDS);
        }

        $stmt = $this->db->prepare("
            UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?
        ");
        $stmt->execute([$attempts, $lockedUntil, $user['id']]);
    }

    private function establishSession($user) {
        self::startSession();
        session_regenerate_id(true);

        $_SESSION['user_id']       = (int) $user['id'];
        $_SESSION['username']      = $user['username'];
        $_SESSION['display_name']  = $user['display_name'] ?: $user['username'];
        $_SESSION['role']          = $user['role'];
        $_SESSION['must_change']   = (int) $user['must_change_password'];
        $_SESSION['logged_in_at']  = time();
        $_SESSION['last_seen']     = time();
        $_SESSION['fingerprint']   = $this->fingerprint();
    }

    /**
     * Is there a valid, non-expired session?
     */
    public function check() {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            self::startSession();
        }

        if (empty($_SESSION['user_id'])) {
            return false;
        }

        // Bind the session to the client fingerprint.
        if (($_SESSION['fingerprint'] ?? '') !== $this->fingerprint()) {
            $this->logout('Session fingerprint mismatch', 'SESSION_INVALID');
            return false;
        }

        // Idle timeout.
        if (isset($_SESSION['last_seen']) && (time() - $_SESSION['last_seen']) > self::IDLE_TIMEOUT) {
            $this->logout('Session timed out', 'SESSION_TIMEOUT');
            return false;
        }

        $_SESSION['last_seen'] = time();
        return true;
    }

    public function user() {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            self::startSession();
        }
        if (empty($_SESSION['user_id'])) {
            return null;
        }
        return [
            'id'           => $_SESSION['user_id'],
            'username'     => $_SESSION['username'] ?? '',
            'display_name' => $_SESSION['display_name'] ?? ($_SESSION['username'] ?? ''),
            'role'         => $_SESSION['role'] ?? 'viewer',
        ];
    }

    public function isAdmin() {
        $u = $this->user();
        return $u && $u['role'] === 'admin';
    }

    public function logout($reason = null, $action = 'LOGOUT') {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            self::startSession();
        }

        if ($reason !== null && !empty($_SESSION['username'])) {
            $this->audit($_SESSION['user_id'] ?? null, $_SESSION['username'], $action, $reason);
        } elseif (!empty($_SESSION['username'])) {
            $this->audit($_SESSION['user_id'] ?? null, $_SESSION['username'], 'LOGOUT', null);
        }

        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params['path'], $params['domain'], $params['secure'], $params['httponly']);
        }
        session_destroy();
    }

    /**
     * Block the request unless authenticated. Redirects to login.php.
     */
    public function requireLogin() {
        if (!$this->check()) {
            $target = $_SERVER['REQUEST_URI'] ?? 'index.php';
            header('Location: login.php?next=' . urlencode($target));
            exit;
        }
    }

    /**
     * Block the request unless authenticated. Emits JSON 401 (for AJAX).
     */
    public function requireLoginJson() {
        if (!$this->check()) {
            http_response_code(401);
            header('Content-Type: application/json');
            echo json_encode(['success' => false, 'error' => 'Not authenticated']);
            exit;
        }
    }

    public function requireAdmin() {
        $this->requireLogin();
        if (!$this->isAdmin()) {
            $this->audit($_SESSION['user_id'] ?? null, $_SESSION['username'] ?? null,
                'ACCESS_DENIED', $_SERVER['REQUEST_URI'] ?? '');
            http_response_code(403);
            die('Forbidden: administrator access required.');
        }
    }

    /* --------------------------------------------------------
     * Password management
     * ------------------------------------------------------ */

    /**
     * Change a user's password. Verifies the current one for self-service.
     */
    public function changePassword($userId, $newPassword, $currentPassword = null) {
        $stmt = $this->db->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        if (!$user) {
            return ['success' => false, 'error' => 'User not found.'];
        }

        if ($currentPassword !== null) {
            if (!password_verify($currentPassword, $user['password_hash'])) {
                $this->audit($userId, $user['username'], 'PASSWORD_CHANGE_FAIL', 'Wrong current password');
                return ['success' => false, 'error' => 'Current password is incorrect.'];
            }
        }

        $policyError = self::validatePasswordPolicy($newPassword);
        if ($policyError !== null) {
            return ['success' => false, 'error' => $policyError];
        }

        $hash = password_hash($newPassword, $this->hashAlgorithm());
        $stmt = $this->db->prepare("
            UPDATE users
               SET password_hash = ?, must_change_password = 0, password_changed_at = NOW(),
                   failed_attempts = 0, locked_until = NULL
             WHERE id = ?
        ");
        $stmt->execute([$hash, $userId]);

        $this->audit($userId, $user['username'], 'PASSWORD_CHANGED', null);
        return ['success' => true];
    }

    /**
     * Create a user.
     */
    public function createUser($username, $password, $role = 'operator', $email = null, $displayName = null) {
        $username = strtolower(sanitizeString($username, 64));

        if (!preg_match('/^[a-z0-9._-]{3,64}$/', $username)) {
            return ['success' => false, 'error' => 'Username must be 3-64 chars: letters, numbers, dot, dash, underscore.'];
        }

        $policyError = self::validatePasswordPolicy($password);
        if ($policyError !== null) {
            return ['success' => false, 'error' => $policyError];
        }

        if (!in_array($role, ['admin', 'operator', 'viewer'], true)) {
            $role = 'operator';
        }

        if ($email !== null && $email !== '' && !isValidEmail($email)) {
            return ['success' => false, 'error' => 'Invalid email address.'];
        }

        try {
            $stmt = $this->db->prepare("
                INSERT INTO users (username, password_hash, display_name, email, role, must_change_password, password_changed_at)
                VALUES (?, ?, ?, ?, ?, 0, NOW())
            ");
            $stmt->execute([
                $username,
                password_hash($password, $this->hashAlgorithm()),
                $displayName ? sanitizeString($displayName, 128) : $username,
                $email ? sanitizeString($email, 255) : null,
                $role,
            ]);
            $id = (int) $this->db->lastInsertId();

            $this->audit($this->userId(), $this->username(), 'USER_CREATED',
                "Created user '{$username}' with role '{$role}'", $username);

            return ['success' => true, 'id' => $id];
        } catch (PDOException $e) {
            if ($e->getCode() === '23000') {
                return ['success' => false, 'error' => 'That username already exists.'];
            }
            throw $e;
        }
    }

    /**
     * Password policy: minimum 10 chars, upper, lower, digit, symbol.
     */
    public static function validatePasswordPolicy($password) {
        if (!is_string($password) || strlen($password) < 10) {
            return 'Password must be at least 10 characters long.';
        }
        if (strlen($password) > 200) {
            return 'Password must be 200 characters or fewer.';
        }
        if (!preg_match('/[A-Z]/', $password)) {
            return 'Password must contain at least one uppercase letter.';
        }
        if (!preg_match('/[a-z]/', $password)) {
            return 'Password must contain at least one lowercase letter.';
        }
        if (!preg_match('/[0-9]/', $password)) {
            return 'Password must contain at least one number.';
        }
        if (!preg_match('/[^A-Za-z0-9]/', $password)) {
            return 'Password must contain at least one symbol.';
        }
        return null;
    }

    /* --------------------------------------------------------
     * Audit logging
     * ------------------------------------------------------ */

    /**
     * Write an audit entry: date/time, ip, action, username, detail.
     */
    public function audit($userId, $username, $action, $detail = null, $target = null) {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO audit_log (user_id, username, action, detail, target, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ");
            $stmt->execute([
                $userId ?: null,
                $username ? substr((string) $username, 0, 64) : null,
                substr((string) $action, 0, 64),
                $detail,
                $target ? substr((string) $target, 0, 255) : null,
                $this->clientIp(),
                substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255),
            ]);
        } catch (Exception $e) {
            error_log('Audit log write failed: ' . $e->getMessage());
        }
    }

    /**
     * Convenience: audit an action for the current session user.
     */
    public function auditCurrent($action, $detail = null, $target = null) {
        $u = $this->user();
        $this->audit($u['id'] ?? null, $u['username'] ?? null, $action, $detail, $target);
    }

    public function listAuditLog($limit = 200, $offset = 0) {
        $limit  = max(1, min(1000, (int) $limit));
        $offset = max(0, (int) $offset);
        $stmt = $this->db->prepare("
            SELECT * FROM audit_log ORDER BY created_at DESC, id DESC LIMIT {$limit} OFFSET {$offset}
        ");
        $stmt->execute();
        return $stmt->fetchAll();
    }

    public function countAuditLog() {
        return (int) $this->db->query("SELECT COUNT(*) FROM audit_log")->fetchColumn();
    }

    public function listUsers() {
        return $this->db->query("
            SELECT id, username, display_name, email, role, is_active,
                   last_login_at, last_login_ip, created_at
              FROM users ORDER BY username
        ")->fetchAll();
    }

    /* --------------------------------------------------------
     * Internals
     * ------------------------------------------------------ */

    private function hashAlgorithm() {
        return defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
    }

    private function fingerprint() {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $ip = $this->clientIp();
        // Bind to UA + IP; salted with a constant so it is not reversible.
        return hash('sha256', $ua . '|' . $ip . '|spf-flattener');
    }

    private function clientIp() {
        return substr($_SERVER['REMOTE_ADDR'] ?? 'unknown', 0, 45);
    }

    public function userId() {
        return $_SESSION['user_id'] ?? null;
    }

    public function username() {
        return $_SESSION['username'] ?? null;
    }
}
