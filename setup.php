<?php
/**
 * Web installer / database setup
 *
 * Shown automatically the first time index.php runs without a working
 * database. Collects the connection details, imports the schema and writes
 * config/config.local.php — then asks for the first administrator account.
 *
 * Loads only what it needs: it must run before a database is reachable.
 */

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/includes/Security.php';
require_once __DIR__ . '/includes/Setup.php';
require_once __DIR__ . '/includes/Auth.php';

// Start the session BEFORE any output. generateCSRFToken() would otherwise
// call session_start() mid-page, by which point headers are already sent and
// the session cookie is silently dropped — making every request a new session
// and breaking CSRF validation.
Auth::startSession();

// If we are already installed, get out of the way.
if (Setup::isInstalled() && !isset($_GET['restart'])) {
    header('Location: index.php');
    exit;
}

$setup    = new Setup();
$step     = $_POST['step'] ?? 'database';
$errors   = [];
$warnings = [];
$result   = null;

// If the database is already configured and its schema imported but no
// account exists yet, resume at the administrator step instead of making
// the user re-enter their credentials.
if ($_SERVER['REQUEST_METHOD'] !== 'POST' && $step === 'database' && Setup::needsAdminUser()) {
    $step = 'admin';
    $result = ['created_db' => false, 'server_version' => null];
}

$prefill  = [
    'host' => defined('DB_HOST') ? DB_HOST : 'localhost',
    'port' => defined('DB_PORT') ? (int) DB_PORT : 3306,
    'user' => 'root',
    'pass' => '',
    'name' => defined('DB_NAME') ? DB_NAME : 'spf_flattener',
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // The installer runs before a database exists, so this is a plain
    // session-backed CSRF check.
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = 'Your session expired. Please reload the page and try again.';
        $step = 'database';
        $_POST = [];
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($errors)) {
    $prefill['host'] = trim($_POST['db_host'] ?? $prefill['host']);
    $prefill['port'] = (int) ($_POST['db_port'] ?? $prefill['port']);
    $prefill['user'] = trim($_POST['db_user'] ?? $prefill['user']);
    $prefill['pass'] = (string) ($_POST['db_pass'] ?? '');
    $prefill['name'] = trim($_POST['db_name'] ?? $prefill['name']);

    if ($step === 'database') {
        // --- Environment checks ---------------------------------
        if (!extension_loaded('pdo_mysql')) {
            $errors[] = 'The pdo_mysql PHP extension is not loaded. Install php-mysql and restart the web server.';
        }
        if (!is_writable(CONFIG_PATH)) {
            $errors[] = 'The config/ directory is not writable by the web server. Run: chmod 775 config';
        }
        if (trim($prefill['host']) === '' || trim($prefill['user']) === '' || trim($prefill['name']) === '') {
            $errors[] = 'Host, username and database name are all required.';
        }

        if (empty($errors)) {
            $check = $setup->testConnection(
                $prefill['host'], $prefill['port'], $prefill['user'], $prefill['pass'], $prefill['name']
            );

            if (!$check['success']) {
                $errors[] = $check['error'];
            } else {
                // Everything reachable — install.
                $installed = $setup->install(
                    $prefill['host'], $prefill['port'], $prefill['user'], $prefill['pass'], $prefill['name']
                );

                if (!$installed['success']) {
                    $errors[] = $installed['error'];
                } else {
                    $result = $installed;
                    $result['server_version'] = $check['server_version'];
                    $step = 'admin';
                }
            }
        }
    } elseif ($step === 'admin') {
        // --- Create the first administrator ----------------------
        require_once __DIR__ . '/includes/Database.php';
        require_once __DIR__ . '/includes/Auth.php';

        $username = trim($_POST['admin_user'] ?? '');
        $password = (string) ($_POST['admin_pass'] ?? '');
        $confirm  = (string) ($_POST['admin_pass2'] ?? '');
        $email    = trim($_POST['admin_email'] ?? '');

        if ($username === '' || $password === '') {
            $errors[] = 'A username and password are required.';
        } elseif ($password !== $confirm) {
            $errors[] = 'The passwords do not match.';
        } else {
            try {
                $auth = new Auth();
                $res = $auth->createUser($username, $password, 'admin', $email ?: null, 'Administrator');

                if ($res['success']) {
                    $auth->audit(null, $username, 'INSTALL_COMPLETE', 'Initial administrator created by the web installer');
                    header('Location: login.php?installed=1');
                    exit;
                }
                $errors[] = $res['error'];
            } catch (Throwable $e) {
                $errors[] = 'Could not create the administrator: ' . $e->getMessage();
            }
        }

        // Stay on the admin step if something went wrong.
        $step = 'admin';
    }
}

$brandColour = '#0079b8';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Setup · ATS Solutions SPF Flattener</title>
    <link rel="icon" href="assets/img/ats-logo.png">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="assets/css/app.css">
    <style>
      body { background: var(--dark); }
      .setup-steps { display: flex; gap: 10px; justify-content: center; margin-bottom: 26px; flex-wrap: wrap; }
      .setup-step {
        display: flex; align-items: center; gap: 8px;
        font-size: 12px; font-weight: 600; color: rgba(255,255,255,0.42);
      }
      .setup-step__num {
        width: 22px; height: 22px; border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        background: rgba(255,255,255,0.1); font-size: 11px;
      }
      .setup-step.active { color: #fff; }
      .setup-step.active .setup-step__num { background: var(--blue); color: #fff; }
      .setup-step.done .setup-step__num { background: var(--ok); color: #fff; }
      .setup-card { max-width: 620px; }
      .setup-note {
        background: var(--bg-alt); border-left: 3px solid var(--blue);
        border-radius: 0 var(--radius) var(--radius) 0;
        padding: 14px 16px; font-size: 13px; color: var(--muted); line-height: 1.7;
        margin-bottom: 20px;
      }
      .setup-note code {
        font-family: 'SFMono-Regular', Consolas, monospace; font-size: 12px;
        background: #fff; padding: 1px 5px; border-radius: 4px;
        border: 1px solid var(--border); color: var(--blue-dark);
      }

      /* Password field with a show/hide control */
      .input-with-toggle { position: relative; }
      .input-with-toggle .form-input { padding-right: 68px; }
      .input-toggle {
        position: absolute; right: 6px; top: 50%; transform: translateY(-50%);
        padding: 6px 10px; border-radius: 6px;
        font-size: 12px; font-weight: 600; color: var(--blue);
        background: transparent; border: none;
        transition: background var(--transition), color var(--transition);
      }
      .input-toggle:hover { background: var(--blue-light); color: var(--blue-dark); }

      /* Live password policy checklist */
      .pw-policy { list-style: none; margin: 10px 0 0; padding: 0; display: grid; gap: 5px; }
      .pw-policy li {
        position: relative; padding-left: 22px;
        font-size: 12px; color: var(--muted); line-height: 1.5;
        transition: color var(--transition);
      }
      .pw-policy li::before {
        content: '○'; position: absolute; left: 4px; top: -1px;
        font-size: 12px; color: #c3ced8;
        transition: color var(--transition);
      }
      .pw-policy li.ok { color: var(--ok); }
      .pw-policy li.ok::before { content: '✓'; color: var(--ok); font-weight: 700; }

      .form-hint.pw-ok  { color: var(--ok); font-weight: 600; }
      .form-hint.pw-bad { color: var(--danger); font-weight: 600; }
    </style>
</head>
<body>
<div class="login-page">
  <div class="login-page__grid" aria-hidden="true"></div>

  <div class="login-card setup-card">
    <div class="login-card__logo">
      <img src="assets/img/ats-logo.png" alt="ATS Solutions">
    </div>

    <h1 class="login-card__title">SPF Flattener Setup</h1>
    <p class="login-card__sub">Connect the database to finish installing</p>

    <div class="setup-steps">
      <div class="setup-step <?= $step === 'admin' ? 'active' : 'done' ?>">
        <span class="setup-step__num"><?= $step === 'admin' && $result === null ? '1' : '✓' ?></span> Database
      </div>
      <div class="setup-step <?= $step === 'admin' ? 'active' : '' ?>">
        <span class="setup-step__num">2</span> Administrator
      </div>
    </div>

    <?php foreach ($errors as $err): ?>
      <div class="alert alert-error">
        <span class="alert__icon">✕</span>
        <div><?= htmlspecialchars($err) ?></div>
      </div>
    <?php endforeach; ?>

    <?php if ($step === 'database'): ?>

      <div class="setup-note">
        The application could not find a working database. Enter your MySQL or
        MariaDB details below — the installer will create the database if it
        does not exist, import the schema, and write
        <code>config/config.local.php</code> for you.
      </div>

      <form method="post" autocomplete="off">
        <input type="hidden" name="step" value="database">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCSRFToken()) ?>">

        <div class="form-row">
          <div class="form-group">
            <label class="form-label" for="db_host">Database Host <span class="req">*</span></label>
            <input class="form-input" type="text" id="db_host" name="db_host"
                   value="<?= htmlspecialchars($prefill['host']) ?>" required>
            <div class="form-hint">Usually <span class="inline-code">localhost</span> or <span class="inline-code">127.0.0.1</span></div>
          </div>
          <div class="form-group">
            <label class="form-label" for="db_port">Port</label>
            <input class="form-input" type="number" id="db_port" name="db_port"
                   value="<?= (int) $prefill['port'] ?>" min="1" max="65535">
          </div>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label class="form-label" for="db_user">Username <span class="req">*</span></label>
            <input class="form-input" type="text" id="db_user" name="db_user"
                   value="<?= htmlspecialchars($prefill['user']) ?>" required>
          </div>
          <div class="form-group">
            <label class="form-label" for="db_pass">Password</label>
            <input class="form-input" type="password" id="db_pass" name="db_pass"
                   value="<?= htmlspecialchars($prefill['pass']) ?>" autocomplete="new-password">
          </div>
        </div>

        <div class="form-group">
          <label class="form-label" for="db_name">Database Name <span class="req">*</span></label>
          <input class="form-input" type="text" id="db_name" name="db_name"
                 value="<?= htmlspecialchars($prefill['name']) ?>" required
                 pattern="[A-Za-z0-9_]+">
          <div class="form-hint">Created automatically if it does not already exist.</div>
        </div>

        <button class="btn btn-primary btn-block" type="submit">Test &amp; Install</button>
      </form>

    <?php else: ?>

      <div class="alert alert-success">
        <span class="alert__icon">✓</span>
        <div>
          Database ready<?= !empty($result['created_db']) ? ' (created)' : '' ?> —
          schema imported and <span class="inline-code">config/config.local.php</span> written.
          <?php if (!empty($result['server_version'])): ?>
            <br>Server: <?= htmlspecialchars($result['server_version']) ?>
          <?php endif; ?>
        </div>
      </div>

      <div class="setup-note">
        Create the first administrator account. You will use these credentials
        to sign in; every action is written to the audit log against this username.
      </div>

      <form method="post" autocomplete="off" id="adminForm">
        <input type="hidden" name="step" value="admin">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCSRFToken()) ?>">

        <div class="form-row">
          <div class="form-group">
            <label class="form-label" for="admin_user">Username <span class="req">*</span></label>
            <input class="form-input" type="text" id="admin_user" name="admin_user"
                   value="<?= htmlspecialchars($_POST['admin_user'] ?? 'admin') ?>" required
                   pattern="[a-zA-Z0-9._-]{3,64}" autocomplete="username">
            <div class="form-hint">3–64 characters: letters, numbers, dot, dash or underscore.</div>
          </div>
          <div class="form-group">
            <label class="form-label" for="admin_email">Email</label>
            <input class="form-input" type="email" id="admin_email" name="admin_email"
                   value="<?= htmlspecialchars($_POST['admin_email'] ?? '') ?>"
                   autocomplete="email">
            <div class="form-hint">Optional — used for change notifications.</div>
          </div>
        </div>

        <div class="form-group">
          <label class="form-label" for="admin_pass">Password <span class="req">*</span></label>
          <div class="input-with-toggle">
            <input class="form-input" type="password" id="admin_pass" name="admin_pass" required
                   autocomplete="new-password" maxlength="200" aria-describedby="pwPolicy">
            <button type="button" class="input-toggle" id="pwToggle"
                    aria-label="Show password">Show</button>
          </div>

          <ul class="pw-policy" id="pwPolicy">
            <li data-rule="len">At least 10 characters</li>
            <li data-rule="upper">An uppercase letter</li>
            <li data-rule="lower">A lowercase letter</li>
            <li data-rule="digit">A number</li>
            <li data-rule="symbol">A symbol</li>
          </ul>
        </div>

        <div class="form-group">
          <label class="form-label" for="admin_pass2">Confirm Password <span class="req">*</span></label>
          <input class="form-input" type="password" id="admin_pass2" name="admin_pass2" required
                 autocomplete="new-password" maxlength="200">
          <div class="form-hint" id="pwMatchHint"></div>
        </div>

        <button class="btn btn-primary btn-block" type="submit" id="createBtn"
                <?= ($_POST['step'] ?? '') === 'admin' && empty($errors) ? '' : '' ?>>
          Create Administrator &amp; Sign In
        </button>
      </form>

      <script>
      (function () {
        var pw      = document.getElementById('admin_pass');
        var pw2     = document.getElementById('admin_pass2');
        var toggle  = document.getElementById('pwToggle');
        var hint    = document.getElementById('pwMatchHint');
        var btn     = document.getElementById('createBtn');
        if (!pw) return;

        var rules = {
          len:    function (v) { return v.length >= 10; },
          upper:  function (v) { return /[A-Z]/.test(v); },
          lower:  function (v) { return /[a-z]/.test(v); },
          digit:  function (v) { return /[0-9]/.test(v); },
          symbol: function (v) { return /[^A-Za-z0-9]/.test(v); }
        };

        function evaluate() {
          var v = pw.value;
          var allOk = true;

          Object.keys(rules).forEach(function (key) {
            var li = document.querySelector('[data-rule="' + key + '"]');
            if (!li) return;
            var ok = rules[key](v);
            li.classList.toggle('ok', ok && v !== '');
            if (!ok) allOk = false;
          });

          // Confirm-field feedback
          if (pw2.value === '') {
            hint.textContent = '';
            hint.className = 'form-hint';
          } else if (pw2.value === v) {
            hint.textContent = 'Passwords match.';
            hint.className = 'form-hint pw-ok';
          } else {
            hint.textContent = 'Passwords do not match.';
            hint.className = 'form-hint pw-bad';
          }

          return allOk && v === pw2.value && v !== '';
        }

        pw.addEventListener('input', evaluate);
        pw2.addEventListener('input', evaluate);

        toggle.addEventListener('click', function () {
          var showing = pw.type === 'text';
          pw.type = showing ? 'password' : 'text';
          pw2.type = showing ? 'password' : 'text';
          toggle.textContent = showing ? 'Show' : 'Hide';
          toggle.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
        });

        // Block submission only when the browser would otherwise let it through
        document.getElementById('adminForm').addEventListener('submit', function (e) {
          if (!evaluate()) {
            e.preventDefault();
            if (pw.value !== pw2.value) {
              hint.textContent = 'Passwords do not match.';
              hint.className = 'form-hint pw-bad';
            }
            pw.focus();
          }
        });
      })();
      </script>

    <?php endif; ?>

    <div class="login-card__foot">
      ATS Solutions · SPF Flattener installer
    </div>
  </div>
</div>
<script src="assets/js/app.js"></script>
</body>
</html>
