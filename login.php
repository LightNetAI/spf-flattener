<?php
/**
 * Login page — ATS Solutions branded
 */

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/includes/Database.php';
require_once __DIR__ . '/includes/Security.php';
require_once __DIR__ . '/includes/Auth.php';
require_once __DIR__ . '/includes/Setup.php';
require_once __DIR__ . '/includes/layout.php';

// Not installed yet? Send the user to the installer.
if (!Setup::isInstalled()) {
    header('Location: setup.php');
    exit;
}

Auth::startSession();
$auth = new Auth();

// Already signed in? Go to the dashboard.
if ($auth->check()) {
    header('Location: index.php');
    exit;
}

$error = '';
$next = $_GET['next'] ?? $_POST['next'] ?? 'index.php';

// Only allow same-site relative targets.
if (preg_match('#^(https?:)?//#i', $next) || strpos($next, '..') !== false) {
    $next = 'index.php';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = 'Your session expired. Please try again.';
        $auth->audit(null, sanitizeString($_POST['username'] ?? '', 64), 'LOGIN_FAIL', 'CSRF token mismatch');
    } else {
        $result = $auth->login($_POST['username'] ?? '', $_POST['password'] ?? '');
        if ($result['success']) {
            if (!empty($_SESSION['must_change'])) {
                header('Location: account.php?force=1');
                exit;
            }
            header('Location: ' . $next);
            exit;
        }
        $error = $result['error'];
    }
}

// First-run notice: is the users table empty?
$needsSetup = false;
try {
    $needsSetup = ((int) getDB()->query("SELECT COUNT(*) FROM users")->fetchColumn()) === 0;
} catch (Exception $e) {
    $needsSetup = false;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <?php renderHead('Sign in'); ?>
    <style>
      /* keeps the login page from inheriting the app background */
      body { background: var(--dark); }
    </style>
</head>
<body>
<div class="login-page">
  <div class="login-page__grid" aria-hidden="true"></div>
  <div class="login-card">
    <div class="login-card__logo">
      <img src="assets/img/ats-logo.png" alt="ATS Solutions">
    </div>

    <h1 class="login-card__title">SPF Flattener</h1>
    <p class="login-card__sub">Sign in to manage SPF records</p>

    <?php if ($error): ?>
      <div class="alert alert-error">
        <span class="alert__icon">✕</span>
        <div><?= htmlspecialchars($error) ?></div>
      </div>
    <?php endif; ?>

    <?php if ($needsSetup): ?>
      <div class="alert alert-warning">
        <span class="alert__icon">!</span>
        <div>
          No users exist yet. Create the first administrator from the command line:<br>
          <span class="inline-code">php cli.php user:add --username=admin --role=admin</span>
        </div>
      </div>
    <?php endif; ?>

    <form method="post" autocomplete="on">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCSRFToken()) ?>">
      <input type="hidden" name="next" value="<?= htmlspecialchars($next) ?>">

      <div class="form-group">
        <label class="form-label" for="username">Username</label>
        <input class="form-input" type="text" id="username" name="username"
               autocomplete="username" required autofocus
               maxlength="64" value="<?= htmlspecialchars($_POST['username'] ?? '') ?>">
      </div>

      <div class="form-group">
        <label class="form-label" for="password">Password</label>
        <input class="form-input" type="password" id="password" name="password"
               autocomplete="current-password" required maxlength="200">
      </div>

      <button class="btn btn-primary btn-block" type="submit">Sign in</button>
    </form>

    <div class="login-card__foot">
      Access is restricted to authorised personnel.<br>
      All sign-in attempts are logged.
      <div class="login-card__brand">
        <span class="dot"></span> ATS Solutions · Secure Portal
      </div>
    </div>
  </div>
</div>
<script src="assets/js/app.js"></script>
</body>
</html>
