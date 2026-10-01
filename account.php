<?php
/**
 * Account — change your own password
 */

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/includes/Database.php';
require_once __DIR__ . '/includes/Security.php';
require_once __DIR__ . '/includes/Auth.php';
require_once __DIR__ . '/includes/layout.php';

Auth::startSession();
$auth = new Auth();
$auth->requireLogin();

$user  = $auth->user();
$force = isset($_GET['force']) || !empty($_SESSION['must_change']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        setFlash('Your session expired. Please try again.', 'error');
        header('Location: account.php');
        exit;
    }

    $current = $_POST['current_password'] ?? '';
    $new     = $_POST['new_password'] ?? '';
    $confirm = $_POST['confirm_password'] ?? '';

    if ($new !== $confirm) {
        setFlash('The new passwords do not match.', 'error');
    } else {
        $result = $auth->changePassword($user['id'], $new, $force ? null : $current);
        if ($result['success']) {
            unset($_SESSION['must_change']);
            setFlash('Your password has been updated.', 'success');
            header('Location: index.php');
            exit;
        }
        setFlash($result['error'], 'error');
    }
    header('Location: account.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <?php renderHead('Account'); ?>
</head>
<body>
<?php renderHeader($auth, ''); ?>

<?php renderHero('Account', 'Manage the credentials for your own sign-in.', 'Security'); ?>

<div class="container section">
  <?php renderFlash(); ?>

  <div class="grid-2">
    <div class="card">
      <div class="card__head"><div class="card__title">Change Password</div></div>

      <?php if ($force): ?>
        <div class="alert alert-warning">
          <span class="alert__icon">!</span>
          <div>You must set a new password before continuing.</div>
        </div>
      <?php endif; ?>

      <form method="post">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCSRFToken()) ?>">

        <?php if (!$force): ?>
        <div class="form-group">
          <label class="form-label" for="current_password">Current Password</label>
          <input class="form-input" type="password" id="current_password" name="current_password"
                 autocomplete="current-password" required maxlength="200">
        </div>
        <?php endif; ?>

        <div class="form-group">
          <label class="form-label" for="new_password">New Password</label>
          <input class="form-input" type="password" id="new_password" name="new_password"
                 autocomplete="new-password" required maxlength="200">
        </div>

        <div class="form-group">
          <label class="form-label" for="confirm_password">Confirm New Password</label>
          <input class="form-input" type="password" id="confirm_password" name="confirm_password"
                 autocomplete="new-password" required maxlength="200">
        </div>

        <p class="form-note">
          At least 10 characters, including an uppercase letter, a lowercase letter,
          a number and a symbol.
        </p>

        <button class="btn btn-primary mt-8" type="submit">Update Password</button>
      </form>
    </div>

    <div class="card">
      <div class="card__head"><div class="card__title">Your Account</div></div>
      <table class="data">
        <tbody>
          <tr><td class="muted">Username</td><td><strong><?= htmlspecialchars($user['username']) ?></strong></td></tr>
          <tr><td class="muted">Display name</td><td><?= htmlspecialchars($user['display_name']) ?></td></tr>
          <tr><td class="muted">Role</td><td><span class="badge badge-info"><?= htmlspecialchars($user['role']) ?></span></td></tr>
        </tbody>
      </table>
      <p class="form-note">Contact an administrator if you need your role changed or the account disabled.</p>
    </div>
  </div>
</div>

<?php renderFooter(); ?>
<?php renderScripts(); ?>
</body>
</html>
