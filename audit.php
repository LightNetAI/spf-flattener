<?php
/**
 * Audit Log — date/time, IP, action, username
 */

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/includes/Database.php';
require_once __DIR__ . '/includes/Security.php';
require_once __DIR__ . '/includes/Auth.php';
require_once __DIR__ . '/includes/layout.php';

Auth::startSession();
$auth = new Auth();
$auth->requireLogin();

$page   = max(1, sanitizeInt($_GET['page'] ?? 1, 1));
$perPage = 100;
$offset = ($page - 1) * $perPage;

$entries = $auth->listAuditLog($perPage, $offset);
$total   = $auth->countAuditLog();
$pages   = max(1, (int) ceil($total / $perPage));

$actionBadge = function ($action) {
    if (str_contains($action, 'FAIL') || str_contains($action, 'DENIED')) return 'badge-danger';
    if (str_contains($action, 'DELETE') || str_contains($action, 'REMOVED')) return 'badge-warn';
    if (str_contains($action, 'LOGIN_SUCCESS') || str_contains($action, 'CREATED') || str_contains($action, 'ADDED')) return 'badge-ok';
    if (str_contains($action, 'FLATTENED') || str_contains($action, 'PUSHED')) return 'badge-info';
    return 'badge-neutral';
};
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <?php renderHead('Audit Log'); ?>
</head>
<body>
<?php renderHeader($auth, 'log'); ?>

<?php renderHero('Audit Log', 'Every sign-in, configuration change and SPF operation is recorded with its timestamp, source address and user.', 'Accountability'); ?>

<div class="container container--wide section">
  <?php renderFlash(); ?>

  <div class="card">
    <div class="card__head">
      <div>
        <div class="card__title"><?= number_format($total) ?> recorded event<?= $total === 1 ? '' : 's' ?></div>
        <div class="card__sub">Showing page <?= $page ?> of <?= $pages ?></div>
      </div>
      <?php if ($auth->isAdmin()): ?>
        <span class="badge badge-info">Administrator view</span>
      <?php endif; ?>
    </div>

    <?php if (empty($entries)): ?>
      <div class="empty">
        <div class="empty__icon">◎</div>
        <div class="empty__title">No events recorded</div>
        <p>Activity will appear here once users sign in and manage domains.</p>
      </div>
    <?php else: ?>
      <div class="table-wrap">
        <table class="data">
          <thead>
            <tr>
              <th>Date / Time</th>
              <th>User</th>
              <th>Action</th>
              <th>Detail</th>
              <th>IP Address</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($entries as $e): ?>
              <tr>
                <td style="white-space:nowrap;font-size:13px">
                  <?= htmlspecialchars(date('Y-m-d H:i:s', strtotime($e['created_at']))) ?>
                </td>
                <td><?= htmlspecialchars($e['username'] ?? '—') ?></td>
                <td><span class="badge <?= $actionBadge($e['action']) ?>"><?= htmlspecialchars($e['action']) ?></span></td>
                <td class="muted" style="font-size:13px">
                  <?= htmlspecialchars($e['detail'] ?? '') ?>
                  <?php if (!empty($e['target'])): ?>
                    <br><span class="inline-code"><?= htmlspecialchars($e['target']) ?></span>
                  <?php endif; ?>
                </td>
                <td style="font-size:13px"><span class="inline-code"><?= htmlspecialchars($e['ip_address'] ?? '—') ?></span></td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>

      <?php if ($pages > 1): ?>
        <div class="flex-between mt-16">
          <?php if ($page > 1): ?>
            <a class="btn btn-outline btn-sm" href="?page=<?= $page - 1 ?>">← Newer</a>
          <?php else: ?><span></span><?php endif; ?>
          <span class="muted" style="font-size:13px">Page <?= $page ?> / <?= $pages ?></span>
          <?php if ($page < $pages): ?>
            <a class="btn btn-outline btn-sm" href="?page=<?= $page + 1 ?>">Older →</a>
          <?php else: ?><span></span><?php endif; ?>
        </div>
      <?php endif; ?>
    <?php endif; ?>
  </div>
</div>

<?php renderFooter(); ?>
<?php renderScripts(); ?>
</body>
</html>
