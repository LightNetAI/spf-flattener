<?php
/**
 * SPF Flattener — Dashboard
 * ATS Solutions branded, authentication required.
 */

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/includes/Database.php';
require_once __DIR__ . '/includes/Security.php';
require_once __DIR__ . '/includes/Auth.php';
require_once __DIR__ . '/includes/layout.php';
require_once __DIR__ . '/includes/SPFFlattener.php';
require_once __DIR__ . '/includes/CloudflareAPI.php';
require_once __DIR__ . '/includes/EmailNotifier.php';
require_once __DIR__ . '/includes/DNSLookup.php';

Auth::startSession();
$auth = new Auth();
$auth->requireLogin();

$db        = getDB();
$flattener = new SPFFlattener();
$user      = $auth->user();
$canWrite  = in_array($user['role'], ['admin', 'operator'], true);

/* ------------------------------------------------------------
 * POST handling
 * ---------------------------------------------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        setFlash('Your session expired. Please try again.', 'error');
        header('Location: index.php');
        exit;
    }
    if (!$canWrite) {
        $auth->auditCurrent('ACCESS_DENIED', 'Attempted write as ' . $user['role']);
        setFlash('Your role does not permit changes.', 'error');
        header('Location: index.php');
        exit;
    }

    $action = $_POST['action'] ?? '';

    /* ---- Add domain ---- */
    if ($action === 'add_domain') {
        $domain = strtolower(trim($_POST['domain'] ?? ''));
        $zoneId = sanitizeString($_POST['cloudflare_zone_id'] ?? '', 100);
        $import = isset($_POST['import_spf']);

        if (!isValidDomain($domain)) {
            setFlash('Invalid domain name. Use a format like example.com', 'error');
            header('Location: index.php');
            exit;
        }

        $stmt = $db->prepare("
            INSERT INTO domains (domain, cloudflare_zone_id, is_active)
            VALUES (?, ?, 1)
            ON DUPLICATE KEY UPDATE cloudflare_zone_id = VALUES(cloudflare_zone_id)
        ");
        $stmt->execute([$domain, $zoneId]);
        $domainId = (int) $db->lastInsertId();
        if (!$domainId) {
            $s = $db->prepare("SELECT id FROM domains WHERE domain = ?");
            $s->execute([$domain]);
            $domainId = (int) $s->fetchColumn();
        }

        $auth->auditCurrent('DOMAIN_ADDED', "Added domain {$domain}", $domain);

        if ($import) {
            $dns = new DNSLookup();
            $res = $dns->importSPFForDomain($domainId);
            if ($res['success']) {
                $auth->auditCurrent('SPF_IMPORTED',
                    "Imported {$res['senders_added']} sender(s) for {$domain}", $domain);
                setFlash("Added {$domain} and imported {$res['senders_added']} sender(s).", 'success');
            } else {
                setFlash("Added {$domain}, but the SPF import failed: " . implode(' ', $res['errors']), 'warning');
            }
        } else {
            setFlash("Added {$domain}.", 'success');
        }

        header('Location: index.php');
        exit;
    }

    /* ---- Delete domain ---- */
    if ($action === 'delete_domain') {
        $domainId = sanitizeInt($_POST['domain_id'] ?? 0);
        $s = $db->prepare("SELECT domain FROM domains WHERE id = ?");
        $s->execute([$domainId]);
        $name = $s->fetchColumn();

        if ($name) {
            $stmt = $db->prepare("DELETE FROM domains WHERE id = ?");
            $stmt->execute([$domainId]);
            $auth->auditCurrent('DOMAIN_DELETED', "Deleted domain {$name}", $name);
            setFlash("Deleted {$name}.", 'success');
        }
        header('Location: index.php');
        exit;
    }

    /* ---- Add sender ---- */
    if ($action === 'add_sender') {
        $domainId     = sanitizeInt($_POST['domain_id'] ?? 0);
        $sendingName  = strtolower(trim($_POST['sending_domain'] ?? ''));
        $senderName   = sanitizeString($_POST['sender_name'] ?? '', 255);
        $includeRaw   = trim($_POST['include_domain'] ?? '');

        if (!isValidDomain($sendingName) || $includeRaw === '' || $senderName === '') {
            setFlash('Please provide a valid sending domain, sender name and include.', 'error');
            header('Location: index.php#senders');
            exit;
        }

        // Direct ip4:/ip6: entries and plain include domains are both stored here.
        if (!preg_match('/^(ip4|ip6):[0-9a-f:.\/]+$/i', $includeRaw) && !isValidDomain($includeRaw)) {
            setFlash('Include must be a domain, or an ip4:/ip6: entry.', 'error');
            header('Location: index.php#senders');
            exit;
        }
        $include = $includeRaw;

        $stmt = $db->prepare("SELECT id FROM sending_domains WHERE domain_id = ? AND sending_domain = ?");
        $stmt->execute([$domainId, $sendingName]);
        $sendingDomainId = $stmt->fetchColumn();

        if (!$sendingDomainId) {
            $stmt = $db->prepare("INSERT INTO sending_domains (domain_id, sending_domain) VALUES (?, ?)");
            $stmt->execute([$domainId, $sendingName]);
            $sendingDomainId = $db->lastInsertId();
        }

        $stmt = $db->prepare("
            INSERT INTO approved_senders (sending_domain_id, sender_name, include_domain)
            VALUES (?, ?, ?)
        ");
        $stmt->execute([$sendingDomainId, $senderName, $include]);

        $auth->auditCurrent('SENDER_ADDED', "Added sender '{$senderName}' ({$include})", $sendingName);
        setFlash('Added the sender.', 'success');
        header('Location: index.php#senders');
        exit;
    }

    /* ---- Delete sender ---- */
    if ($action === 'delete_sender') {
        $senderId = sanitizeInt($_POST['sender_id'] ?? 0);
        $s = $db->prepare("SELECT sender_name, include_domain FROM approved_senders WHERE id = ?");
        $s->execute([$senderId]);
        $row = $s->fetch();

        if ($row) {
            $stmt = $db->prepare("DELETE FROM approved_senders WHERE id = ?");
            $stmt->execute([$senderId]);
            $auth->auditCurrent('SENDER_DELETED', "Deleted sender '{$row['sender_name']}'");
            setFlash('Removed the sender.', 'success');
        }
        header('Location: index.php#senders');
        exit;
    }

    /* ---- Flatten ---- */
    if ($action === 'flatten') {
        $domainId = sanitizeInt($_POST['domain_id'] ?? 0);
        $push     = isset($_POST['push_cloudflare']);

        $result = $flattener->flattenDomain($domainId);

        if (!$result['success']) {
            $auth->auditCurrent('FLATTEN_FAILED', implode(' ', $result['errors']));
            setFlash('Flattening failed: ' . implode(' ', $result['errors']), 'error');
            header('Location: index.php');
            exit;
        }

        $s = $db->prepare("SELECT domain FROM domains WHERE id = ?");
        $s->execute([$domainId]);
        $name = $s->fetchColumn();

        $msg = "Flattened {$name}: " . count($result['ips_collected']) . ' IP(s), '
             . $result['lookup_count_before'] . ' lookup(s) → 0.';

        $auth->auditCurrent('SPF_FLATTENED', $msg, $name);

        if ($push && $name) {
            try {
                $cf = new CloudflareAPI();
                $cf->updateDomainSPF($name, $result['flattened_record']);
                $auth->auditCurrent('CLOUDFLARE_PUSHED', "Published flattened SPF for {$name}", $name);
                $msg .= ' Published to Cloudflare.';
            } catch (Exception $e) {
                error_log('Cloudflare push failed: ' . $e->getMessage());
                $auth->auditCurrent('CLOUDFLARE_PUSH_FAILED', $e->getMessage(), $name);
                setFlash($msg . ' Cloudflare publish failed.', 'warning');
                header('Location: index.php');
                exit;
            }
        }

        setFlash($msg, 'success');
        header('Location: index.php');
        exit;
    }

    /* ---- Configuration ---- */
    if ($action === 'save_config') {
        if (!$auth->isAdmin()) {
            setFlash('Only administrators can change settings.', 'error');
            header('Location: index.php#config');
            exit;
        }

        $allowed = ['cloudflare_api_email', 'cloudflare_api_key', 'smtp_server',
                    'smtp_port', 'smtp_from_email', 'smtp_from_name',
                    'smtp_username', 'smtp_password', 'enable_email_notifications'];

        $saved = 0;
        foreach ($allowed as $key) {
            if (!isset($_POST[$key])) {
                continue;
            }
            $value = trim((string) $_POST[$key]);

            // Skip blank secrets so they aren't wiped by an empty submit.
            if (in_array($key, ['cloudflare_api_key', 'smtp_password'], true) && $value === '') {
                continue;
            }
            if ($key === 'smtp_from_email' && $value !== '' && !isValidEmail($value)) {
                setFlash('That email address is not valid.', 'error');
                header('Location: index.php#config');
                exit;
            }
            if ($key === 'cloudflare_api_email' && $value !== '' && !isValidEmail($value)) {
                setFlash('That Cloudflare email address is not valid.', 'error');
                header('Location: index.php#config');
                exit;
            }
            if ($key === 'smtp_port') {
                $value = (string) sanitizeInt($value, 587);
            }

            $stmt = $db->prepare("
                INSERT INTO config (config_key, config_value) VALUES (?, ?)
                ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)
            ");
            $stmt->execute([$key, sanitizeString($value, 500)]);
            $saved++;
        }

        $auth->auditCurrent('CONFIG_UPDATED', "Updated {$saved} setting(s)");
        setFlash('Saved the settings.', 'success');
        header('Location: index.php#config');
        exit;
    }
}

/* ------------------------------------------------------------
 * Data for the view
 * ---------------------------------------------------------- */
$domains = $db->query("
    SELECT d.*,
           (SELECT COUNT(*) FROM sending_domains sd WHERE sd.domain_id = d.id) AS sender_count,
           (SELECT COUNT(*) FROM flattened_ips fi WHERE fi.domain_id = d.id AND fi.is_active = 1) AS ip_count
      FROM domains d
     ORDER BY d.created_at DESC
")->fetchAll();

$sendersByDomain = [];
$rows = $db->query("
    SELECT sd.domain_id, sd.sending_domain, asp.sender_name, asp.include_domain, asp.id AS sender_id
      FROM sending_domains sd
      LEFT JOIN approved_senders asp
             ON sd.id = asp.sending_domain_id AND asp.is_active = 1
     ORDER BY sd.domain_id, sd.sending_domain, asp.sender_name
")->fetchAll();

foreach ($rows as $row) {
    $sendersByDomain[$row['domain_id']][] = $row;
}

$config = [];
foreach ($db->query("SELECT config_key, config_value FROM config")->fetchAll() as $c) {
    $config[$c['config_key']] = $c['config_value'];
}

$totalIps      = array_sum(array_column($domains, 'ip_count'));
$overLimit     = count(array_filter($domains, fn($d) => $d['lookup_count_before'] > MAX_DNS_LOOKUPS));
$lookupsSaved  = array_sum(array_map(fn($d) => max(0, $d['lookup_count_before'] - $d['lookup_count_after']), $domains));
$csrf          = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <?php renderHead('Dashboard'); ?>
</head>
<body>
<?php renderHeader($auth, 'domains'); ?>

<?php renderHero(
    'SPF Flattening Console',
    'Resolve include: chains into direct ip4: / ip6: entries and keep every zone inside the RFC 7208 lookup limit.',
    'Mail Authentication'
); ?>

<div class="container container--wide section">
  <?php renderFlash(); ?>

  <div class="stat-grid">
    <div class="stat-card">
      <div class="stat-card__value"><?= count($domains) ?></div>
      <div class="stat-card__label">Domains</div>
      <div class="stat-card__sub">Monitored zones</div>
    </div>
    <div class="stat-card">
      <div class="stat-card__value"><?= $totalIps ?></div>
      <div class="stat-card__label">Flattened IPs</div>
      <div class="stat-card__sub">Across all zones</div>
    </div>
    <div class="stat-card">
      <div class="stat-card__value"><?= $lookupsSaved ?></div>
      <div class="stat-card__label">Lookups Saved</div>
      <div class="stat-card__sub">DNS queries avoided</div>
    </div>
    <div class="stat-card">
      <div class="stat-card__value" style="color: <?= $overLimit ? 'var(--danger)' : 'var(--ok)' ?>"><?= $overLimit ?></div>
      <div class="stat-card__label">Over Limit</div>
      <div class="stat-card__sub">Zones above <?= MAX_DNS_LOOKUPS ?> lookups</div>
    </div>
  </div>

  <div class="tabs">
    <button class="tab active" onclick="showTab('tab-domains', this)">Domains</button>
    <button class="tab" onclick="showTab('tab-add', this)">Add Domain</button>
    <button class="tab" onclick="showTab('tab-senders', this)">Senders</button>
    <button class="tab" onclick="showTab('tab-config', this)">Settings</button>
  </div>

  <!-- DOMAINS -------------------------------------------------->
  <div id="tab-domains" class="tab-content active">
    <div class="card">
      <div class="card__head">
        <div>
          <div class="card__title">Configured Domains</div>
          <div class="card__sub">Flatten, inspect and publish SPF records</div>
        </div>
      </div>

      <?php if (empty($domains)): ?>
        <div class="empty">
          <div class="empty__icon">◎</div>
          <div class="empty__title">No domains yet</div>
          <p>Use <strong>Add Domain</strong> to import an existing SPF record from DNS.</p>
        </div>
      <?php else: ?>
        <div class="table-wrap">
          <table class="data">
            <thead>
              <tr>
                <th>Domain</th>
                <th>Senders</th>
                <th>IPs</th>
                <th>Lookups</th>
                <th>Last Flattened</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($domains as $d): ?>
                <tr>
                  <td>
                    <strong><?= htmlspecialchars($d['domain']) ?></strong><br>
                    <?php if ($d['cloudflare_zone_id']): ?>
                      <span class="badge badge-info">Cloudflare</span>
                    <?php endif; ?>
                    <?php if (!$d['is_active']): ?>
                      <span class="badge badge-neutral">Inactive</span>
                    <?php endif; ?>
                  </td>
                  <td><?= (int) $d['sender_count'] ?></td>
                  <td><?= (int) $d['ip_count'] ?></td>
                  <td>
                    <?php if ($d['lookup_count_before'] > MAX_DNS_LOOKUPS): ?>
                      <span class="badge badge-danger"><?= (int) $d['lookup_count_before'] ?> over</span>
                    <?php else: ?>
                      <span class="badge badge-ok"><?= (int) $d['lookup_count_before'] ?></span>
                    <?php endif; ?>
                  </td>
                  <td class="muted" style="font-size:13px">
                    <?= $d['last_flattened_at'] ? htmlspecialchars(date('Y-m-d H:i', strtotime($d['last_flattened_at']))) : '—' ?>
                  </td>
                  <td>
                    <div class="cell-actions">
                      <?php if ($canWrite): ?>
                      <form method="post" style="display:inline">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
                        <input type="hidden" name="action" value="flatten">
                        <input type="hidden" name="domain_id" value="<?= (int) $d['id'] ?>">
                        <button class="btn btn-primary btn-sm" type="submit">Flatten</button>
                      </form>
                      <?php endif; ?>

                      <?php if ($d['flattened_spf_record']): ?>
                        <button class="btn btn-outline btn-sm"
                                onclick="toggleCollapse(this)">View<span class="collapsible__chev">›</span></button>
                      <?php endif; ?>

                      <?php if ($canWrite): ?>
                      <form method="post" style="display:inline"
                            onsubmit="return confirm('Delete <?= htmlspecialchars($d['domain'], ENT_QUOTES) ?> and all of its records?')">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
                        <input type="hidden" name="action" value="delete_domain">
                        <input type="hidden" name="domain_id" value="<?= (int) $d['id'] ?>">
                        <button class="btn btn-danger btn-sm" type="submit">Delete</button>
                      </form>
                      <?php endif; ?>
                    </div>

                    <?php if ($d['flattened_spf_record']): ?>
                      <div class="collapsible-body">
                        <div class="flex-between mb-8">
                          <span class="muted" style="font-size:12px">Flattened SPF record</span>
                          <button class="btn btn-outline btn-sm" type="button"
                                  onclick="copyText(<?= htmlspecialchars(json_encode($d['flattened_spf_record']), ENT_QUOTES) ?>, this)">Copy</button>
                        </div>
                        <div class="spf-record"><?= htmlspecialchars($d['flattened_spf_record']) ?></div>

                        <?php if (!empty($d['original_spf_record'])): ?>
                          <p class="form-hint mt-8">Original</p>
                          <div class="spf-record spf-record--light"><?= htmlspecialchars($d['original_spf_record']) ?></div>
                        <?php endif; ?>
                      </div>
                    <?php endif; ?>
                  </td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      <?php endif; ?>
    </div>
  </div>

  <!-- ADD ------------------------------------------------------>
  <div id="tab-add" class="tab-content">
    <div class="grid-2">
      <?php if ($canWrite): ?>
      <div class="card">
        <div class="card__head">
          <div>
            <div class="card__title">Import from DNS</div>
            <div class="card__sub">Fetch and parse the live SPF record automatically</div>
          </div>
        </div>

        <div class="form-group">
          <label class="form-label" for="import_domain">Domain <span class="req">*</span></label>
          <input class="form-input" type="text" id="import_domain" placeholder="example.com">
        </div>
        <div class="form-group">
          <label class="form-label" for="import_zone">Cloudflare Zone ID <span class="muted">(optional)</span></label>
          <input class="form-input" type="text" id="import_zone" placeholder="Leave blank if not using Cloudflare">
        </div>

        <div class="flex-between">
          <button class="btn btn-outline" type="button" onclick="fetchSPF()">Fetch SPF</button>
          <button class="btn btn-primary" type="button" id="importBtn" onclick="importSPF()" disabled>Import &amp; Add</button>
        </div>

        <div id="spfPreview" class="mt-16 hidden"></div>
      </div>
      <?php endif; ?>

      <?php if ($canWrite): ?>
      <div class="card">
        <div class="card__head">
          <div>
            <div class="card__title">Add Manually</div>
            <div class="card__sub">Enter a domain without importing</div>
          </div>
        </div>
        <form method="post">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
          <input type="hidden" name="action" value="add_domain">
          <div class="form-group">
            <label class="form-label" for="domain">Domain <span class="req">*</span></label>
            <input class="form-input" type="text" id="domain" name="domain" placeholder="example.com" required>
          </div>
          <div class="form-group">
            <label class="form-label" for="zone">Cloudflare Zone ID</label>
            <input class="form-input" type="text" id="zone" name="cloudflare_zone_id" placeholder="Optional">
          </div>
          <div class="form-group form-check">
            <input type="checkbox" id="import_spf" name="import_spf" value="1" checked>
            <label for="import_spf">Import the SPF record from DNS after adding</label>
          </div>
          <button class="btn btn-primary" type="submit">Add Domain</button>
        </form>
      </div>
      <?php endif; ?>
    </div>
  </div>

  <!-- SENDERS -------------------------------------------------->
  <div id="tab-senders" class="tab-content">
    <div class="grid-2">
      <?php if ($canWrite): ?>
      <div class="card">
        <div class="card__head">
          <div class="card__title">Add Sender</div>
        </div>
        <form method="post">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
          <input type="hidden" name="action" value="add_sender">

          <div class="form-group">
            <label class="form-label" for="s_domain">Domain <span class="req">*</span></label>
            <select class="form-select" id="s_domain" name="domain_id" required>
              <option value="">Select a domain…</option>
              <?php foreach ($domains as $d): ?>
                <option value="<?= (int) $d['id'] ?>"><?= htmlspecialchars($d['domain']) ?></option>
              <?php endforeach; ?>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label" for="s_sending">Sending Domain <span class="req">*</span></label>
            <input class="form-input" type="text" id="s_sending" name="sending_domain" placeholder="example.com" required>
          </div>
          <div class="form-group">
            <label class="form-label" for="s_name">Sender Name <span class="req">*</span></label>
            <input class="form-input" type="text" id="s_name" name="sender_name" placeholder="Google Workspace" required>
          </div>
          <div class="form-group">
            <label class="form-label" for="s_include">Include Domain or IP <span class="req">*</span></label>
            <input class="form-input" type="text" id="s_include" name="include_domain" placeholder="_spf.google.com or ip4:203.0.113.0/24" required>
            <div class="form-hint">An include domain, or a direct <span class="inline-code">ip4:</span>/<span class="inline-code">ip6:</span> entry.</div>
          </div>
          <button class="btn btn-primary" type="submit">Add Sender</button>
        </form>
      </div>
      <?php endif; ?>

      <div class="card">
        <div class="card__head">
          <div class="card__title">Current Senders</div>
        </div>

        <?php if (empty($sendersByDomain)): ?>
          <div class="empty">
            <div class="empty__icon">◎</div>
            <div class="empty__title">No senders configured</div>
            <p>Import a domain's SPF record, or add senders manually.</p>
          </div>
        <?php else: ?>
          <?php foreach ($sendersByDomain as $domainId => $senders):
              $parent = '';
              foreach ($domains as $d) { if ((int) $d['id'] === (int) $domainId) { $parent = $d['domain']; break; } }
              $real = array_filter($senders, fn($s) => $s['sender_id'] !== null);
          ?>
            <div class="collapsible" onclick="toggleCollapse(this)">
              <span><?= htmlspecialchars($parent ?: "Domain #{$domainId}") ?></span>
              <span class="badge badge-neutral"><?= count($real) ?> sender<?= count($real) === 1 ? '' : 's' ?><span class="collapsible__chev">›</span></span>
            </div>
            <div class="collapsible-body">
              <?php if (empty($real)): ?>
                <p class="muted" style="font-size:13px">No senders.</p>
              <?php else: ?>
                <div class="table-wrap">
                  <table class="data">
                    <thead><tr><th>Sender</th><th>Include / IP</th><?php if ($canWrite): ?><th></th><?php endif; ?></tr></thead>
                    <tbody>
                      <?php foreach ($real as $s): ?>
                        <tr>
                          <td><?= htmlspecialchars($s['sender_name']) ?></td>
                          <td><span class="inline-code"><?= htmlspecialchars($s['include_domain']) ?></span></td>
                          <?php if ($canWrite): ?>
                          <td>
                            <form method="post" style="display:inline"
                                  onsubmit="return confirm('Remove this sender?')">
                              <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
                              <input type="hidden" name="action" value="delete_sender">
                              <input type="hidden" name="sender_id" value="<?= (int) $s['sender_id'] ?>">
                              <button class="btn btn-danger btn-sm" type="submit">Remove</button>
                            </form>
                          </td>
                          <?php endif; ?>
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
  </div>

  <!-- SETTINGS ------------------------------------------------->
  <div id="tab-config" class="tab-content">
    <?php if (!$auth->isAdmin()): ?>
      <div class="card">
        <div class="alert alert-info">
          <span class="alert__icon">i</span>
          <div>Only administrators can view or change settings.</div>
        </div>
      </div>
    <?php else: ?>
    <div class="grid-2">
      <div class="card">
        <div class="card__head">
          <div>
            <div class="card__title">Cloudflare</div>
            <div class="card__sub">Publish flattened records to Cloudflare DNS</div>
          </div>
        </div>
        <form method="post">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
          <input type="hidden" name="action" value="save_config">
          <div class="form-group">
            <label class="form-label" for="cf_email">API Email</label>
            <input class="form-input" type="email" id="cf_email" name="cloudflare_api_email"
                   value="<?= htmlspecialchars($config['cloudflare_api_email'] ?? '') ?>">
          </div>
          <div class="form-group">
            <label class="form-label" for="cf_key">API Key</label>
            <input class="form-input" type="password" id="cf_key" name="cloudflare_api_key"
                   placeholder="<?= !empty($config['cloudflare_api_key']) ? '•••••••• (unchanged)' : 'Not set' ?>">
            <div class="form-hint">Leave blank to keep the current key.</div>
          </div>
          <button class="btn btn-primary" type="submit">Save Cloudflare Settings</button>
        </form>
      </div>

      <div class="card">
        <div class="card__head">
          <div>
            <div class="card__title">Email Notifications</div>
            <div class="card__sub">Alert when a sender's IP ranges change</div>
          </div>
        </div>
        <form method="post">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
          <input type="hidden" name="action" value="save_config">
          <div class="form-row">
            <div class="form-group">
              <label class="form-label" for="smtp_server">SMTP Server</label>
              <input class="form-input" type="text" id="smtp_server" name="smtp_server"
                     value="<?= htmlspecialchars($config['smtp_server'] ?? '') ?>">
            </div>
            <div class="form-group">
              <label class="form-label" for="smtp_port">Port</label>
              <input class="form-input" type="number" id="smtp_port" name="smtp_port"
                     value="<?= htmlspecialchars($config['smtp_port'] ?? '587') ?>">
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label" for="smtp_from">From Email</label>
              <input class="form-input" type="email" id="smtp_from" name="smtp_from_email"
                     value="<?= htmlspecialchars($config['smtp_from_email'] ?? '') ?>">
            </div>
            <div class="form-group">
              <label class="form-label" for="smtp_name">From Name</label>
              <input class="form-input" type="text" id="smtp_name" name="smtp_from_name"
                     value="<?= htmlspecialchars($config['smtp_from_name'] ?? 'SPF Flattener') ?>">
            </div>
          </div>
          <div class="form-group form-check">
            <input type="checkbox" id="notify" name="enable_email_notifications" value="1"
                   <?= ($config['enable_email_notifications'] ?? '0') === '1' ? 'checked' : '' ?>>
            <label for="notify">Send email notifications on changes</label>
          </div>
          <button class="btn btn-primary" type="submit">Save Email Settings</button>
        </form>
      </div>
    </div>
    <?php endif; ?>
  </div>
</div>

<?php renderFooter($user ? 'Signed in as ' . $user['username'] : null); ?>
<?php renderScripts(); ?>

<script>
const CSRF = <?= json_encode($csrf) ?>;

async function fetchSPF() {
  const domain = document.getElementById('import_domain').value.trim();
  const box = document.getElementById('spfPreview');
  const btn = document.getElementById('importBtn');

  if (!domain) { alert('Enter a domain name first.'); return; }

  box.className = 'mt-16';
  box.innerHTML = '<p class="muted">Querying DNS…</p>';
  btn.disabled = true;

  const fd = new FormData();
  fd.append('action', 'fetch_spf');
  fd.append('domain', domain);
  fd.append('csrf_token', CSRF);

  try {
    const res = await fetch('import_spf.php', { method: 'POST', body: fd });
    const out = await res.json();

    if (!out.success) {
      box.innerHTML = '<div class="alert alert-error"><span class="alert__icon">✕</span><div>'
        + escapeHtml(out.error || 'No SPF record found.') + '</div></div>';
      return;
    }

    let html = '<div class="alert alert-success"><span class="alert__icon">✓</span><div>SPF record found.</div></div>';
    html += '<p class="form-hint">Original record</p>';
    html += '<div class="spf-record">' + escapeHtml(out.spf_record) + '</div>';

    html += '<div class="flex-between mt-16">';
    html += '<span class="muted" style="font-size:13px">DNS lookups</span>';
    html += out.lookup_count > 10
      ? '<span class="badge badge-danger">' + out.lookup_count + ' — over limit</span>'
      : '<span class="badge badge-ok">' + out.lookup_count + '</span>';
    html += '</div>';

    if (out.includes.length) {
      html += '<p class="form-hint mt-16">Includes (' + out.includes.length + ')</p><div class="mech-list">';
      out.includes.forEach(i => {
        html += '<div class="mech-item mech-item--warn">📧 include:' + escapeHtml(i) + '</div>';
      });
      html += '</div>';
    }

    const ip4 = out.ip4 || [];
    const ip6 = out.ip6 || [];
    if (ip4.length) {
      html += '<p class="form-hint mt-16">Direct IPv4 (' + ip4.length + ')</p><div class="mech-list">';
      ip4.forEach(i => { html += '<div class="mech-item mech-item--ip4">🌐 ip4:' + escapeHtml(i) + '</div>'; });
      html += '</div>';
    }
    if (ip6.length) {
      html += '<p class="form-hint mt-16">Direct IPv6 (' + ip6.length + ')</p><div class="mech-list">';
      ip6.forEach(i => { html += '<div class="mech-item mech-item--ip6">🌐 ip6:' + escapeHtml(i) + '</div>'; });
      html += '</div>';
    }

    if (out.has_a)  html += '<p class="form-hint mt-8">⚠ A mechanism present — resolved during flattening.</p>';
    if (out.has_mx) html += '<p class="form-hint mt-8">⚠ MX mechanism present — resolved during flattening.</p>';
    if (out.redirect) html += '<p class="form-hint mt-8">↻ Redirects to ' + escapeHtml(out.redirect) + '</p>';

    box.innerHTML = html;
    btn.disabled = false;
  } catch (e) {
    box.innerHTML = '<div class="alert alert-error"><span class="alert__icon">✕</span><div>'
      + escapeHtml(e.message) + '</div></div>';
  }
}

async function importSPF() {
  const domain = document.getElementById('import_domain').value.trim();
  const zone = document.getElementById('import_zone').value.trim();
  const box = document.getElementById('spfPreview');

  if (!domain) { alert('Enter a domain name first.'); return; }

  box.innerHTML = '<p class="muted">Importing…</p>';

  const fd = new FormData();
  fd.append('action', 'add_and_import');
  fd.append('domain', domain);
  fd.append('cloudflare_zone_id', zone);
  fd.append('csrf_token', CSRF);

  try {
    const res = await fetch('import_spf.php', { method: 'POST', body: fd });
    const out = await res.json();

    if (out.success) {
      box.innerHTML = '<div class="alert alert-success"><span class="alert__icon">✓</span><div>'
        + escapeHtml(out.import_summary || 'Imported successfully.') + '<br>Reloading…</div></div>';
      setTimeout(() => { window.location.href = 'index.php'; }, 1600);
    } else {
      box.innerHTML = '<div class="alert alert-error"><span class="alert__icon">✕</span><div>'
        + escapeHtml((out.errors && out.errors.join(' ')) || out.error || 'Import failed.') + '</div></div>';
    }
  } catch (e) {
    box.innerHTML = '<div class="alert alert-error"><span class="alert__icon">✕</span><div>'
      + escapeHtml(e.message) + '</div></div>';
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}
</script>
</body>
</html>
