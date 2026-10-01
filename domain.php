<?php
/**
 * Domain detail — review the original SPF records captured on import,
 * alongside the current flattened output.
 */

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/includes/Database.php';
require_once __DIR__ . '/includes/Security.php';
require_once __DIR__ . '/includes/Auth.php';
require_once __DIR__ . '/includes/Setup.php';
require_once __DIR__ . '/includes/layout.php';
require_once __DIR__ . '/includes/SPFFlattener.php';
require_once __DIR__ . '/includes/DNSLookup.php';
require_once __DIR__ . '/includes/IPUtil.php';

// Not installed yet? Send the user to the installer.
if (!Setup::isInstalled()) {
    header('Location: setup.php');
    exit;
}

Auth::startSession();
$auth = new Auth();
$auth->requireLogin();

$db       = getDB();
$user     = $auth->user();
$canWrite = in_array($user['role'], ['admin', 'operator'], true);
$dns      = new DNSLookup();

$domainId = sanitizeInt($_GET['id'] ?? 0);

/* ------------------------------------------------------------
 * Actions
 * ---------------------------------------------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        setFlash('Your session expired. Please try again.', 'error');
        header('Location: domain.php?id=' . $domainId);
        exit;
    }
    if (!$canWrite) {
        $auth->auditCurrent('ACCESS_DENIED', 'Attempted write as ' . $user['role'], 'domain.php');
        setFlash('Your role does not permit changes.', 'error');
        header('Location: domain.php?id=' . $domainId);
        exit;
    }

    $action = $_POST['action'] ?? '';

    // Re-import: capture the record as it is published right now.
    if ($action === 'reimport') {
        $res = $dns->importSPFForDomain($domainId, $user['username'], 'reimport');

        if ($res['success']) {
            $auth->auditCurrent('SPF_REIMPORTED',
                "Re-imported {$res['spf_record']} for domain #{$domainId}" .
                ($res['senders_added'] ? " (+{$res['senders_added']} sender(s))" : ' (record unchanged)'),
                'domain.php');
            setFlash('Re-imported the live SPF record.', 'success');
        } else {
            setFlash('Re-import failed: ' . implode(' ', $res['errors']), 'error');
        }
        header('Location: domain.php?id=' . $domainId);
        exit;
    }

    // Flatten.
    if ($action === 'flatten') {
        $flattener = new SPFFlattener();
        $result = $flattener->flattenDomain($domainId);

        if ($result['success']) {
            $count = count($result['ips_collected']);
            $auth->auditCurrent('SPF_FLATTENED',
                "Flattened domain #{$domainId}: {$count} IP(s), {$result['lookup_count_before']} lookup(s) → {$result['lookup_count_after']}.",
                'domain.php');
            setFlash("Flattened: {$count} IP(s), {$result['lookup_count_before']} lookup(s) → {$result['lookup_count_after']}.", 'success');
        } else {
            $auth->auditCurrent('FLATTEN_FAILED', implode(' ', $result['errors']), 'domain.php');
            setFlash('Flattening failed: ' . implode(' ', $result['errors']), 'error');
        }
        header('Location: domain.php?id=' . $domainId);
        exit;
    }
}

/* ------------------------------------------------------------
 * Load
 * ---------------------------------------------------------- */
$stmt = $db->prepare("SELECT * FROM domains WHERE id = ?");
$stmt->execute([$domainId]);
$domain = $stmt->fetch();

if (!$domain) {
    setFlash('That domain does not exist.', 'error');
    header('Location: index.php');
    exit;
}

$history       = $dns->getRecordHistory($domainId, 100);
$historyCount  = count($history);
$latest        = $history[0] ?? null;

// Senders, grouped by sending domain.
$stmt = $db->prepare("
    SELECT sd.id AS sending_domain_id, sd.sending_domain,
           asp.sender_name, asp.include_domain, asp.is_active
      FROM sending_domains sd
      LEFT JOIN approved_senders asp
             ON sd.id = asp.sending_domain_id AND asp.is_active = 1
     WHERE sd.domain_id = ?
     ORDER BY sd.sending_domain, asp.sender_name
");
$stmt->execute([$domainId]);
$sendersBySending = [];
foreach ($stmt->fetchAll() as $row) {
    $sendersBySending[$row['sending_domain']][] = $row;
}

// Flattened addresses.
$stmt = $db->prepare("
    SELECT ip_address, ip_version, source_include, last_verified
      FROM flattened_ips
     WHERE domain_id = ? AND is_active = 1
     ORDER BY ip_version, ip_address
");
$stmt->execute([$domainId]);
$flattenedIps = $stmt->fetchAll();

// Recent changes.
$stmt = $db->prepare("
    SELECT * FROM change_log WHERE domain_id = ? ORDER BY created_at DESC LIMIT 15
");
$stmt->execute([$domainId]);
$changes = $stmt->fetchAll();

// Audit trail for this domain.
$stmt = $db->prepare("
    SELECT created_at, username, action, detail, ip_address
      FROM audit_log
     WHERE detail LIKE ? OR target LIKE ?
     ORDER BY created_at DESC LIMIT 20
");
$stmt->execute(['%domain #' . $domainId . '%', '%' . $domain['domain'] . '%']);
$domainAudit = $stmt->fetchAll();

$csrf = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <?php renderHead($domain['domain']); ?>
</head>
<body>
<?php renderHeader($auth, 'domains'); ?>

<?php renderHero(
    $domain['domain'],
    'The records captured when this domain was imported, and everything derived from them since.',
    'Domain Detail'
); ?>

<div class="container container--wide section">
  <?php renderFlash(); ?>

  <div class="flex-between mb-16">
    <a class="btn btn-outline btn-sm" href="index.php">← All domains</a>
    <div class="flex-between">
      <?php if ($canWrite): ?>
        <form method="post" style="display:inline">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
          <input type="hidden" name="action" value="reimport">
          <button class="btn btn-outline btn-sm" type="submit"
                  title="Fetch the live record again and store a new snapshot">Re-import live SPF</button>
        </form>
        <form method="post" style="display:inline">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
          <input type="hidden" name="action" value="flatten">
          <button class="btn btn-primary btn-sm" type="submit">Flatten</button>
        </form>
      <?php endif; ?>
    </div>
  </div>

  <!-- Summary -->
  <div class="stat-grid">
    <div class="stat-card">
      <div class="stat-card__value"><?= $historyCount ?></div>
      <div class="stat-card__label">Records Imported</div>
      <div class="stat-card__sub">Snapshots on file</div>
    </div>
    <div class="stat-card">
      <div class="stat-card__value"><?= (int) $domain['lookup_count_before'] ?></div>
      <div class="stat-card__label">Lookups Before</div>
      <div class="stat-card__sub"><?= $domain['lookup_count_before'] > MAX_DNS_LOOKUPS ? 'Over the limit' : 'Within the limit' ?></div>
    </div>
    <div class="stat-card">
      <div class="stat-card__value"><?= count($flattenedIps) ?></div>
      <div class="stat-card__label">Flattened IPs</div>
      <div class="stat-card__sub">Currently active</div>
    </div>
    <div class="stat-card">
      <div class="stat-card__value" style="font-size:15px;padding-top:6px">
        <?= $domain['last_flattened_at'] ? htmlspecialchars(date('d M Y H:i', strtotime($domain['last_flattened_at']))) : 'Never' ?>
      </div>
      <div class="stat-card__label">Last Flattened</div>
      <div class="stat-card__sub"><?= $domain['cloudflare_zone_id'] ? 'Cloudflare linked' : 'No Cloudflare zone' ?></div>
    </div>
  </div>

  <div class="tabs">
    <button class="tab active" onclick="showTab('tab-original', this)">Original SPF Records (<?= $historyCount ?>)</button>
    <button class="tab" onclick="showTab('tab-flattened', this)">Flattened (<?= count($flattenedIps) ?>)</button>
    <button class="tab" onclick="showTab('tab-senders', this)">Senders</button>
    <button class="tab" onclick="showTab('tab-history', this)">Activity</button>
  </div>

  <!-- ORIGINAL RECORDS ---------------------------------------->
  <div id="tab-original" class="tab-content active">
    <?php if (empty($history)): ?>
      <div class="card">
        <div class="empty">
          <div class="empty__icon">◎</div>
          <div class="empty__title">No records captured yet</div>
          <p>Import this domain, or use <strong>Re-import live SPF</strong> to capture the record as published now.</p>
        </div>
      </div>
    <?php else: ?>
      <div class="alert alert-info">
        <span class="alert__icon">i</span>
        <div>
          Each import stores the record as it was published at that moment. These snapshots are never
          overwritten, so the original policy stays reviewable after flattening replaces it.
        </div>
      </div>

      <?php foreach ($history as $i => $snap): ?>
        <div class="card">
          <div class="card__head">
            <div>
              <div class="card__title">
                <?= htmlspecialchars(date('d M Y, H:i:s', strtotime($snap['created_at']))) ?>
                <?php if ($i === 0): ?>
                  <span class="badge badge-ok">Most recent</span>
                <?php elseif ($i === $historyCount - 1 && $historyCount > 1): ?>
                  <span class="badge badge-info">Original import</span>
                <?php endif; ?>
                <?php if ($snap['source'] === 'reimport'): ?>
                  <span class="badge badge-neutral">re-import</span>
                <?php elseif ($snap['source'] === 'cron'): ?>
                  <span class="badge badge-neutral">scheduled</span>
                <?php endif; ?>
              </div>
              <div class="card__sub">
                <?= $snap['imported_by'] ? 'Imported by ' . htmlspecialchars($snap['imported_by']) : 'Imported automatically' ?>
                · <?= (int) $snap['lookup_count'] ?> DNS lookup<?= (int) $snap['lookup_count'] === 1 ? '' : 's' ?>
                <?php if ((int) $snap['lookup_count'] > MAX_DNS_LOOKUPS): ?>
                  <span class="badge badge-danger">over the 10-lookup limit</span>
                <?php else: ?>
                  <span class="badge badge-ok">within the limit</span>
                <?php endif; ?>
              </div>
            </div>
            <button class="btn btn-outline btn-sm" type="button"
                    onclick="copyText(<?= htmlspecialchars(json_encode($snap['spf_record']), ENT_QUOTES) ?>, this)">Copy</button>
          </div>

          <p class="form-hint">SPF record (v=spf1)</p>
          <div class="spf-record mb-16"><?= htmlspecialchars($snap['spf_record']) ?></div>

          <?php
          $mech = $snap['mechanisms_parsed'];
          $hasAny = !empty($mech['includes']) || !empty($mech['ip4']) || !empty($mech['ip6'])
                 || !empty($mech['a_records']) || !empty($mech['mx_records'])
                 || !empty($mech['ptr']) || !empty($mech['exists']) || !empty($mech['redirect']);
          ?>

          <?php if ($hasAny): ?>
            <p class="form-hint">Mechanisms</p>
            <div class="mech-list mb-16">
              <?php foreach (($mech['includes'] ?? []) as $v): ?>
                <div class="mech-item mech-item--warn">include:<?= htmlspecialchars($v) ?></div>
              <?php endforeach; ?>
              <?php foreach (($mech['ip4'] ?? []) as $v): ?>
                <div class="mech-item mech-item--ip4">ip4:<?= htmlspecialchars($v) ?></div>
              <?php endforeach; ?>
              <?php foreach (($mech['ip6'] ?? []) as $v): ?>
                <div class="mech-item mech-item--ip6">ip6:<?= htmlspecialchars($v) ?></div>
              <?php endforeach; ?>
              <?php foreach (($mech['a_records'] ?? []) as $v): ?>
                <div class="mech-item mech-item--warn">a:<?= htmlspecialchars($v) ?></div>
              <?php endforeach; ?>
              <?php foreach (($mech['mx_records'] ?? []) as $v): ?>
                <div class="mech-item mech-item--warn">mx:<?= htmlspecialchars($v) ?></div>
              <?php endforeach; ?>
              <?php foreach (($mech['ptr'] ?? []) as $v): ?>
                <div class="mech-item mech-item--danger"><?= htmlspecialchars($v) ?> (deprecated, cannot be flattened)</div>
              <?php endforeach; ?>
              <?php foreach (($mech['exists'] ?? []) as $v): ?>
                <div class="mech-item mech-item--danger">exists:<?= htmlspecialchars($v) ?> (cannot be flattened)</div>
              <?php endforeach; ?>
              <?php if (!empty($mech['redirect'])): ?>
                <div class="mech-item mech-item--warn">redirect=<?= htmlspecialchars($mech['redirect']) ?></div>
              <?php endif; ?>
            </div>
          <?php endif; ?>

          <?php if (!empty($snap['txt_records_list'])): ?>
            <p class="form-hint">All TXT records returned for <?= htmlspecialchars($domain['domain']) ?> at import time (<?= count($snap['txt_records_list']) ?>)</p>
            <div class="mech-list">
              <?php foreach ($snap['txt_records_list'] as $txt): ?>
                <?php $isSpf = stripos(trim($txt), 'v=spf1') === 0; ?>
                <div class="mech-item <?= $isSpf ? 'mech-item--ip4' : '' ?>" style="word-break:break-all">
                  <?= htmlspecialchars($txt) ?>
                  <?php if ($isSpf): ?><span class="badge badge-ok">SPF</span><?php endif; ?>
                </div>
              <?php endforeach; ?>
            </div>
          <?php endif; ?>
        </div>
      <?php endforeach; ?>
    <?php endif; ?>
  </div>

  <!-- FLATTENED ----------------------------------------------->
  <div id="tab-flattened" class="tab-content">
    <div class="card">
      <div class="card__head">
        <div>
          <div class="card__title">Current flattened record</div>
          <div class="card__sub">
            <?= $domain['last_flattened_at']
                ? 'Generated ' . htmlspecialchars(date('d M Y H:i', strtotime($domain['last_flattened_at'])))
                : 'Not yet flattened' ?>
          </div>
        </div>
        <?php if ($domain['flattened_spf_record']): ?>
          <button class="btn btn-outline btn-sm" type="button"
                  onclick="copyText(<?= htmlspecialchars(json_encode($domain['flattened_spf_record']), ENT_QUOTES) ?>, this)">Copy</button>
        <?php endif; ?>
      </div>

      <?php if ($domain['flattened_spf_record']): ?>
        <div class="spf-record"><?= htmlspecialchars($domain['flattened_spf_record']) ?></div>
        <p class="form-note">
          Publish this at the domain apex. Any <span class="inline-code">include:spfN.&lt;domain&gt;</span>
          entries are chained sub-records listed below.
        </p>
      <?php else: ?>
        <div class="empty">
          <div class="empty__icon">◎</div>
          <div class="empty__title">Nothing flattened yet</div>
          <p>Press <strong>Flatten</strong> above to resolve every sender to direct addresses.</p>
        </div>
      <?php endif; ?>
    </div>

    <?php
    // Rebuild the record chain for display from the stored addresses.
    $chain = [];
    if (!empty($flattenedIps)) {
        $ipTokens = array_map(fn($r) => $r['ip_address'], $flattenedIps);
        $collapsed = IPUtil::collapse($ipTokens);
        $f = new SPFFlattener();
        $blocks = [];
        $budget = SPF_RECORD_BYTES;
        // Re-pack using the same rules the flattener used.
        $tokens = $collapsed['spf'];
        $blocks = [$tokens];
        for ($i = 0; $i < count($blocks); $i++) {
            while (!empty($blocks[$i])) {
                $body = implode(' ', $blocks[$i]);
                $size = strlen("v=spf1 {$body} include:spf1.example.domain.com -all") + 49;
                if ($size < $budget) break;
                $overflow = array_pop($blocks[$i]);
                if (!isset($blocks[$i + 1])) $blocks[$i + 1] = [];
                array_unshift($blocks[$i + 1], $overflow);
            }
        }
        $blocks = array_values(array_filter($blocks, fn($b) => !empty($b)));
        $last = count($blocks) - 1;
        foreach ($blocks as $i => $block) {
            $body = implode(' ', $block);
            $content = ($i === $last)
                ? "v=spf1 {$body} -all"
                : 'v=spf1 ' . $body . ' include:spf' . ($i + 1) . ".{$domain['domain']} -all";
            $chain[] = ['name' => "spf{$i}.{$domain['domain']}", 'content' => $content];
        }
    }
    ?>

    <?php if (count($chain) > 1): ?>
      <div class="card">
        <div class="card__head">
          <div>
            <div class="card__title"><?= count($chain) ?> chained sub-records</div>
            <div class="card__sub">
              Each costs one DNS lookup. Create all of them, then point the apex at
              <span class="inline-code">spf0.<?= htmlspecialchars($domain['domain']) ?></span>.
            </div>
          </div>
        </div>

        <div class="alert alert-info">
          <span class="alert__icon">i</span>
          <div>
            A single DNS character-string is limited to 255 characters. These records
            exceed that, so publish each one as <strong>multiple quoted strings inside
            one TXT record</strong> — use the BIND format below.
          </div>
        </div>

        <?php foreach ($chain as $rec): ?>
          <div class="collapsible" onclick="toggleCollapse(this)">
            <span><span class="inline-code"><?= htmlspecialchars($rec['name']) ?></span></span>
            <span class="badge badge-neutral">
              <?= strlen($rec['content']) ?> chars<span class="collapsible__chev">›</span>
            </span>
          </div>
          <div class="collapsible-body">
            <div class="flex-between mb-8">
              <span class="muted" style="font-size:12px">Single line</span>
              <button class="btn btn-outline btn-sm" type="button"
                      onclick="copyText(<?= htmlspecialchars(json_encode($rec['content']), ENT_QUOTES) ?>, this)">Copy</button>
            </div>
            <div class="spf-record mb-16"><?= htmlspecialchars($rec['content']) ?></div>

            <?php $bind = $f->formatForBind($rec['content']); ?>
            <div class="flex-between mb-8">
              <span class="muted" style="font-size:12px">BIND / multi-string format (publish this)</span>
              <button class="btn btn-outline btn-sm" type="button"
                      onclick="copyText(<?= htmlspecialchars(json_encode($bind), ENT_QUOTES) ?>, this)">Copy</button>
            </div>
            <div class="spf-record spf-record--light" style="color:var(--text)"><?= htmlspecialchars($bind) ?></div>
          </div>
        <?php endforeach; ?>
      </div>
    <?php endif; ?>

    <?php if (!empty($flattenedIps)): ?>
      <div class="card">
        <div class="card__head">
          <div class="card__title"><?= count($flattenedIps) ?> resolved address<?= count($flattenedIps) === 1 ? '' : 'es' ?></div>
        </div>
        <div class="table-wrap">
          <table class="data">
            <thead><tr><th>Address / Network</th><th>Family</th><th>Source sender</th><th>Last verified</th></tr></thead>
            <tbody>
              <?php foreach ($flattenedIps as $ip): ?>
                <tr>
                  <td><span class="inline-code"><?= htmlspecialchars($ip['ip_address']) ?></span></td>
                  <td>
                    <span class="badge <?= $ip['ip_version'] === '4' ? 'badge-info' : 'badge-neutral' ?>">
                      IPv<?= htmlspecialchars($ip['ip_version']) ?>
                    </span>
                  </td>
                  <td class="muted" style="font-size:13px"><?= htmlspecialchars($ip['source_include'] ?? '—') ?></td>
                  <td class="muted" style="font-size:12px">
                    <?= $ip['last_verified'] ? htmlspecialchars(date('d M Y H:i', strtotime($ip['last_verified']))) : '—' ?>
                  </td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div>
    <?php endif; ?>
  </div>

  <!-- SENDERS ------------------------------------------------->
  <div id="tab-senders" class="tab-content">
    <div class="card">
      <div class="card__head">
        <div>
          <div class="card__title">Configured senders</div>
          <div class="card__sub">What the flattener resolves</div>
        </div>
      </div>

      <?php if (empty($sendersBySending)): ?>
        <div class="empty">
          <div class="empty__icon">◎</div>
          <div class="empty__title">No senders configured</div>
          <p>Import the SPF record to populate senders automatically.</p>
        </div>
      <?php else: ?>
        <?php foreach ($sendersBySending as $sendingDomain => $rows):
            $real = array_filter($rows, fn($r) => $r['sender_name'] !== null);
        ?>
          <div class="collapsible" onclick="toggleCollapse(this)">
            <span><?= htmlspecialchars($sendingDomain) ?></span>
            <span class="badge badge-neutral"><?= count($real) ?> sender<?= count($real) === 1 ? '' : 's' ?><span class="collapsible__chev">›</span></span>
          </div>
          <div class="collapsible-body">
            <?php if (empty($real)): ?>
              <p class="muted" style="font-size:13px">No senders.</p>
            <?php else: ?>
              <div class="table-wrap">
                <table class="data">
                  <thead><tr><th>Sender</th><th>Mechanism</th><th>Type</th></tr></thead>
                  <tbody>
                    <?php foreach ($real as $s):
                        $inc = $s['include_domain'];
                        $type = str_starts_with($inc, 'ip4:') ? 'Direct IPv4'
                              : (str_starts_with($inc, 'ip6:') ? 'Direct IPv6'
                              : (str_starts_with($inc, 'a:') ? 'A record'
                              : (str_starts_with($inc, 'mx:') ? 'MX record' : 'Include')));
                        $badge = in_array($type, ['Direct IPv4', 'Direct IPv6'], true) ? 'badge-info' : 'badge-warn';
                    ?>
                      <tr>
                        <td><?= htmlspecialchars($s['sender_name']) ?></td>
                        <td><span class="inline-code"><?= htmlspecialchars($inc) ?></span></td>
                        <td><span class="badge <?= $badge ?>"><?= htmlspecialchars($type) ?></span></td>
                      </tr>
                    <?php endforeach; ?>
                  </tbody>
                </table>
              </div>
            <?php endif; ?>
          </div>
        <?php endforeach; ?>
      <?php endif; ?>
    </div>
  </div>

  <!-- ACTIVITY ------------------------------------------------>
  <div id="tab-history" class="tab-content">
    <?php if (!empty($changes)): ?>
      <div class="card">
        <div class="card__head"><div class="card__title">Detected changes</div></div>
        <div class="table-wrap">
          <table class="data">
            <thead><tr><th>When</th><th>Type</th><th>Added</th><th>Removed</th><th>Published</th></tr></thead>
            <tbody>
              <?php foreach ($changes as $c): ?>
                <tr>
                  <td style="font-size:13px;white-space:nowrap"><?= htmlspecialchars(date('d M Y H:i', strtotime($c['created_at']))) ?></td>
                  <td><span class="badge badge-neutral"><?= htmlspecialchars($c['change_type']) ?></span></td>
                  <td><?= (int) $c['ips_added'] ?></td>
                  <td><?= (int) $c['ips_removed'] ?></td>
                  <td><?= $c['cloudflare_updated'] ? '<span class="badge badge-ok">yes</span>' : '<span class="badge badge-neutral">no</span>' ?></td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div>
    <?php endif; ?>

    <div class="card">
      <div class="card__head">
        <div class="card__title">Audit trail for this domain</div>
      </div>
      <?php if (empty($domainAudit)): ?>
        <div class="empty">
          <div class="empty__icon">◎</div>
          <div class="empty__title">No activity recorded</div>
        </div>
      <?php else: ?>
        <div class="table-wrap">
          <table class="data">
            <thead><tr><th>Date / Time</th><th>User</th><th>Action</th><th>Detail</th><th>IP</th></tr></thead>
            <tbody>
              <?php foreach ($domainAudit as $a): ?>
                <tr>
                  <td style="font-size:13px;white-space:nowrap"><?= htmlspecialchars(date('Y-m-d H:i:s', strtotime($a['created_at']))) ?></td>
                  <td><?= htmlspecialchars($a['username'] ?? '—') ?></td>
                  <td><span class="badge badge-neutral"><?= htmlspecialchars($a['action']) ?></span></td>
                  <td class="muted" style="font-size:13px"><?= htmlspecialchars($a['detail'] ?? '') ?></td>
                  <td style="font-size:12px"><span class="inline-code"><?= htmlspecialchars($a['ip_address'] ?? '—') ?></span></td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      <?php endif; ?>
    </div>
  </div>
</div>

<?php renderFooter('Signed in as ' . $user['username']); ?>
<?php renderScripts(); ?>
</body>
</html>
