<?php
/**
 * User Management — administrators only
 */

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/includes/Database.php';
require_once __DIR__ . '/includes/Security.php';
require_once __DIR__ . '/includes/Auth.php';
require_once __DIR__ . '/includes/layout.php';

Auth::startSession();
$auth = new Auth();
$auth->requireAdmin();

$db = getDB();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        setFlash('Your session expired. Please try again.', 'error');
        header('Location: users.php');
        exit;
    }

    $action = $_POST['action'] ?? '';

    if ($action === 'create') {
        $res = $auth->createUser(
            $_POST['username'] ?? '',
            $_POST['password'] ?? '',
            $_POST['role'] ?? 'operator',
            $_POST['email'] ?? null,
            $_POST['display_name'] ?? null
        );
        setFlash($res['success'] ? 'Created the user account.' : $res['error'],
                 $res['success'] ? 'success' : 'error');
        header('Location: users.php');
        exit;
    }

    if ($action === 'reset_password') {
        $userId = sanitizeInt($_POST['user_id'] ?? 0);
        $new    = $_POST['new_password'] ?? '';

        $s = $db->prepare("SELECT username FROM users WHERE id = ?");
        $s->execute([$userId]);
        $name = $s->fetchColumn();

        if (!$name) {
            setFlash('User not found.', 'error');
        } else {
            $res = $auth->changePassword($userId, $new, null);
            if ($res['success']) {
                $auth->auditCurrent('PASSWORD_RESET', "Reset password for '{$name}'", $name);
                setFlash("Reset the password for {$name}.", 'success');
            } else {
                setFlash($res['error'], 'error');
            }
        }
        header('Location: users.php');
        exit;
    }

    if ($action === 'toggle_active') {
        $userId = sanitizeInt($_POST['user_id'] ?? 0);

        if ($userId === (int) $auth->userId()) {
            setFlash('You cannot disable your own account.', 'error');
        } else {
            $s = $db->prepare("SELECT username, is_active FROM users WHERE id = ?");
            $s->execute([$userId]);
            $row = $s->fetch();

            if ($row) {
                $newState = $row['is_active'] ? 0 : 1;
                $u = $db->prepare("UPDATE users SET is_active = ? WHERE id = ?");
                $u->execute([$newState, $userId]);
                $auth->auditCurrent('USER_' . ($newState ? 'ENABLED' : 'DISABLED'),
                    ($newState ? 'Enabled' : 'Disabled') . " user '{$row['username']}'", $row['username']);
                setFlash(($newState ? 'Enabled' : 'Disabled') . " {$row['username']}.", 'success');
            }
        }
        header('Location: users.php');
        exit;
    }
}

$users = $auth->listUsers();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <?php renderHead('Users'); ?>
</head>
<body>
<?php renderHeader($auth, 'users'); ?>

<?php renderHero('User Accounts', 'Create accounts and control who can flatten records, publish to DNS and change settings.', 'Access Control'); ?>

<div class="container container--wide section">
  <?php renderFlash(); ?>

  <div class="grid-2">
    <div class="card">
      <div class="card__head"><div class="card__title">Create User</div></div>
      <form method="post">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCSRFToken()) ?>">
        <input type="hidden" name="action" value="create">

        <div class="form-row">
          <div class="form-group">
            <label class="form-label" for="username">Username <span class="req">*</span></label>
            <input class="form-input" type="text" id="username" name="username" required
                   pattern="[a-zA-Z0-9._-]{3,64}" placeholder="jane.doe">
          </div>
          <div class="form-group">
            <label class="form-label" for="display_name">Display Name</label>
            <input class="form-input" type="text" id="display_name" name="display_name" placeholder="Jane Doe">
          </div>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label class="form-label" for="email">Email</label>
            <input class="form-input" type="email" id="email" name="email" placeholder="jane@example.com">
          </div>
          <div class="form-group">
            <label class="form-label" for="role">Role</label>
            <select class="form-select" id="role" name="role">
              <option value="operator">Operator — manage and flatten</option>
              <option value="admin">Administrator — full access</option>
              <option value="viewer">Viewer — read only</option>
            </select>
          </div>
        </div>

        <div class="form-group">
          <label class="form-label" for="password">Password <span class="req">*</span></label>
          <input class="form-input" type="password" id="password" name="password" required
                 autocomplete="new-password" maxlength="200">
          <div class="form-hint">At least 10 characters with upper, lower, number and symbol.</div>
        </div>

        <button class="btn btn-primary" type="submit">Create User</button>
      </form>
    </div>

    <div class="card">
      <div class="card__head">
        <div class="card__title"><?= count($users) ?> Account<?= count($users) === 1 ? '' : 's' ?></div>
      </div>

      <div class="table-wrap">
        <table class="data">
          <thead>
            <tr><th>User</th><th>Role</th><th>Last Login</th><th>Status</th><th></th></tr>
          </thead>
          <tbody>
            <?php foreach ($users as $u): ?>
              <tr class="<?= $u['is_active'] ? '' : 'row--inactive' ?>">
                <td>
                  <strong><?= htmlspecialchars($u['display_name'] ?: $u['username']) ?></strong><br>
                  <span class="muted" style="font-size:12px"><?= htmlspecialchars($u['username']) ?></span>
                </td>
                <td><span class="badge badge-info"><?= htmlspecialchars($u['role']) ?></span></td>
                <td class="muted" style="font-size:12px;white-space:nowrap">
                  <?= $u['last_login_at'] ? htmlspecialchars(date('Y-m-d H:i', strtotime($u['last_login_at']))) : 'Never' ?>
                  <?php if ($u['last_login_ip']): ?><br><?= htmlspecialchars($u['last_login_ip']) ?><?php endif; ?>
                </td>
                <td>
                  <?php if ($u['is_active']): ?>
                    <span class="badge badge-ok">Active</span>
                  <?php else: ?>
                    <span class="badge badge-neutral">Disabled</span>
                  <?php endif; ?>
                </td>
                <td>
                  <div class="cell-actions">
                    <button class="btn btn-outline btn-sm" type="button"
                            onclick="showReset(<?= (int) $u['id'] ?>, <?= htmlspecialchars(json_encode($u['username']), ENT_QUOTES) ?>)">Reset</button>

                    <?php if ((int) $u['id'] !== (int) $auth->userId()): ?>
                    <form method="post" style="display:inline">
                      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCSRFToken()) ?>">
                      <input type="hidden" name="action" value="toggle_active">
                      <input type="hidden" name="user_id" value="<?= (int) $u['id'] ?>">
                      <button class="btn <?= $u['is_active'] ? 'btn-danger' : 'btn-outline' ?> btn-sm" type="submit">
                        <?= $u['is_active'] ? 'Disable' : 'Enable' ?>
                      </button>
                    </form>
                    <?php endif; ?>
                  </div>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<!-- Password reset dialog -->
<div id="resetModal" style="display:none;position:fixed;inset:0;background:rgba(10,21,32,0.66);z-index:1000;align-items:center;justify-content:center;padding:20px">
  <div class="card" style="max-width:420px;width:100%;margin:0">
    <div class="card__head"><div class="card__title">Reset password</div></div>
    <p class="muted mb-16" style="font-size:14px">Set a new password for <strong id="resetWho"></strong>.</p>
    <form method="post">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCSRFToken()) ?>">
      <input type="hidden" name="action" value="reset_password">
      <input type="hidden" name="user_id" id="resetUserId" value="">
      <div class="form-group">
        <label class="form-label" for="resetPass">New Password</label>
        <input class="form-input" type="password" id="resetPass" name="new_password" required
               autocomplete="new-password" maxlength="200">
      </div>
      <div class="flex-between">
        <button class="btn btn-outline" type="button" onclick="hideReset()">Cancel</button>
        <button class="btn btn-primary" type="submit">Reset Password</button>
      </div>
    </form>
  </div>
</div>

<?php renderFooter(); ?>
<?php renderScripts(); ?>
<script>
function showReset(id, username) {
  document.getElementById('resetUserId').value = id;
  document.getElementById('resetWho').textContent = username;
  document.getElementById('resetModal').style.display = 'flex';
  document.getElementById('resetPass').value = '';
}
function hideReset() {
  document.getElementById('resetModal').style.display = 'none';
}
</script>
</body>
</html>
