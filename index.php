<?php
/**
 * SPF Flattener - Main Dashboard
 * Web GUI for managing SPF record flattening
 */

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/includes/Database.php';
require_once __DIR__ . '/includes/SPFFlattener.php';
require_once __DIR__ . '/includes/CloudflareAPI.php';
require_once __DIR__ . '/includes/EmailNotifier.php';
require_once __DIR__ . '/includes/DNSLookup.php';

$db = getDB();
$flattener = new SPFFlattener();
$message = '';
$messageType = '';

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    if ($action === 'add_domain') {
        $domain = trim($_POST['domain'] ?? '');
        $cloudflareZoneId = trim($_POST['cloudflare_zone_id'] ?? '');
        $importSpf = isset($_POST['import_spf']);
        
        if (!empty($domain)) {
            try {
                $stmt = $db->prepare("
                    INSERT INTO domains (domain, cloudflare_zone_id, is_active)
                    VALUES (?, ?, 1)
                    ON DUPLICATE KEY UPDATE cloudflare_zone_id = VALUES(cloudflare_zone_id)
                ");
                $stmt->execute([$domain, $cloudflareZoneId]);
                $domainId = $db->lastInsertId();
                
                // Optionally import SPF record via DNS lookup
                if ($importSpf) {
                    $dns = new DNSLookup();
                    $importResult = $dns->importSPFForDomain($domainId);
                    
                    if ($importResult['success']) {
                        $message = "Domain {$domain} added and SPF imported ({$importResult['senders_added']} senders found)";
                    } else {
                        $message = "Domain {$domain} added, but SPF import failed: " . implode(', ', $importResult['errors']);
                        $messageType = 'warning';
                    }
                } else {
                    $message = "Domain {$domain} added successfully";
                }
                $messageType = 'success';
            } catch (Exception $e) {
                $message = "Error adding domain: " . $e->getMessage();
                $messageType = 'error';
            }
        }
    }
    
    elseif ($action === 'add_sender') {
        $domainId = $_POST['domain_id'] ?? 0;
        $sendingDomain = trim($_POST['sending_domain'] ?? '');
        $senderName = trim($_POST['sender_name'] ?? '');
        $includeDomain = trim($_POST['include_domain'] ?? '');
        
        if (!empty($sendingDomain) && !empty($includeDomain)) {
            try {
                // First check if sending domain exists
                $stmt = $db->prepare("SELECT id FROM sending_domains WHERE domain_id = ? AND sending_domain = ?");
                $stmt->execute([$domainId, $sendingDomain]);
                $sendingDomainId = $stmt->fetchColumn();
                
                if (!$sendingDomainId) {
                    // Create sending domain
                    $stmt = $db->prepare("INSERT INTO sending_domains (domain_id, sending_domain) VALUES (?, ?)");
                    $stmt->execute([$domainId, $sendingDomain]);
                    $sendingDomainId = $db->lastInsertId();
                }
                
                // Add approved sender
                $stmt = $db->prepare("
                    INSERT INTO approved_senders (sending_domain_id, sender_name, include_domain)
                    VALUES (?, ?, ?)
                ");
                $stmt->execute([$sendingDomainId, $senderName, $includeDomain]);
                
                $message = "Sender added successfully";
                $messageType = 'success';
            } catch (Exception $e) {
                $message = "Error adding sender: " . $e->getMessage();
                $messageType = 'error';
            }
        }
    }
    
    elseif ($action === 'flatten') {
        $domainId = $_POST['domain_id'] ?? 0;
        
        if ($domainId) {
            try {
                $result = $flattener->flattenDomain($domainId);
                
                if ($result['success']) {
                    // Check if auto-update is enabled
                    if (AUTO_UPDATE_ENABLED && !empty($result['flattened_record'])) {
                        try {
                            $cfApi = new CloudflareAPI();
                            $domainStmt = $db->prepare("SELECT domain FROM domains WHERE id = ?");
                            $domainStmt->execute([$domainId]);
                            $domain = $domainStmt->fetchColumn();
                            
                            $cfApi->updateDomainSPF($domain, $result['flattened_record']);
                            
                            // Send notification
                            $notifier = new EmailNotifier();
                            $notifier->sendUpdateNotification($domain, $result['flattened_record'], count($result['ips_collected']));
                            
                            $message = "SPF flattened and Cloudflare updated successfully";
                        } catch (Exception $cfError) {
                            $message = "SPF flattened but Cloudflare update failed: " . $cfError->getMessage();
                            $messageType = 'warning';
                        }
                    } else {
                        $message = "SPF record flattened successfully";
                    }
                    $messageType = 'success';
                } else {
                    $message = "Flattening failed: " . implode(', ', $result['errors']);
                    $messageType = 'error';
                }
            } catch (Exception $e) {
                $message = "Error: " . $e->getMessage();
                $messageType = 'error';
            }
        }
    }
    
    elseif ($action === 'delete_domain') {
        $domainId = $_POST['domain_id'] ?? 0;
        
        if ($domainId) {
            try {
                $stmt = $db->prepare("DELETE FROM domains WHERE id = ?");
                $stmt->execute([$domainId]);
                $message = "Domain deleted successfully";
                $messageType = 'success';
            } catch (Exception $e) {
                $message = "Error deleting domain: " . $e->getMessage();
                $messageType = 'error';
            }
        }
    }
}

// Get all domains
$domainsStmt = $db->query("
    SELECT d.*, 
           (SELECT COUNT(*) FROM sending_domains sd WHERE sd.domain_id = d.id) as sender_count,
           (SELECT COUNT(*) FROM flattened_ips fi WHERE fi.domain_id = d.id AND fi.is_active = 1) as ip_count
    FROM domains d 
    ORDER BY d.created_at DESC
");
$domains = $domainsStmt->fetchAll();

// Get approved senders for each domain
$sendersByDomain = [];
$sendersStmt = $db->query("
    SELECT sd.domain_id, sd.sending_domain, sd.id as sending_domain_id,
           asp.sender_name, asp.include_domain, asp.id as sender_id
    FROM sending_domains sd
    LEFT JOIN approved_senders asp ON sd.id = asp.sending_domain_id AND asp.is_active = 1
    ORDER BY sd.domain_id, sd.sending_domain
");
while ($row = $sendersStmt->fetch()) {
    $domainId = $row['domain_id'];
    if (!isset($sendersByDomain[$domainId])) {
        $sendersByDomain[$domainId] = [];
    }
    $sendersByDomain[$domainId][] = $row;
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SPF Flattener - Dashboard</title>
    <style>
        :root {
            --primary: #3b82f6;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --dark: #1f2937;
            --light: #f3f4f6;
            --border: #e5e7eb;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--light);
            color: var(--dark);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        header h1 {
            color: var(--primary);
            margin-bottom: 5px;
        }
        
        .alert {
            padding: 15px 20px;
            border-radius: 6px;
            margin-bottom: 20px;
        }
        
        .alert-success { background: #d1fae5; color: #065f46; border: 1px solid var(--success); }
        .alert-error { background: #fee2e2; color: #991b1b; border: 1px solid var(--danger); }
        .alert-warning { background: #fef3c7; color: #92400e; border: 1px solid var(--warning); }
        
        .card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .card h2 {
            margin-bottom: 15px;
            color: var(--dark);
            border-bottom: 2px solid var(--border);
            padding-bottom: 10px;
        }
        
        .btn {
            display: inline-block;
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            text-decoration: none;
            transition: opacity 0.2s;
        }
        
        .btn:hover { opacity: 0.9; }
        .btn-primary { background: var(--primary); color: white; }
        .btn-success { background: var(--success); color: white; }
        .btn-danger { background: var(--danger); color: white; }
        .btn-secondary { background: #6b7280; color: white; }
        .btn-sm { padding: 6px 12px; font-size: 13px; }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
        }
        
        .form-group input, .form-group select, .form-group textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid var(--border);
            border-radius: 6px;
            font-size: 14px;
        }
        
        .form-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        
        th {
            background: var(--light);
            font-weight: 600;
        }
        
        tr:hover {
            background: #f9fafb;
        }
        
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 500;
        }
        
        .badge-success { background: #d1fae5; color: #065f46; }
        .badge-warning { background: #fef3c7; color: #92400e; }
        .badge-danger { background: #fee2e2; color: #991b1b; }
        .badge-info { background: #dbeafe; color: #1e40af; }
        
        .spf-record {
            font-family: 'Courier New', monospace;
            background: #f4f4f4;
            padding: 10px;
            border-radius: 4px;
            word-break: break-all;
            font-size: 13px;
        }
        
        .tabs {
            display: flex;
            border-bottom: 2px solid var(--border);
            margin-bottom: 20px;
        }
        
        .tab {
            padding: 10px 20px;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            margin-bottom: -2px;
        }
        
        .tab.active {
            border-bottom-color: var(--primary);
            color: var(--primary);
            font-weight: 600;
        }
        
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        
        .grid-2 {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
        }
        
        .stat-box {
            background: var(--light);
            padding: 15px;
            border-radius: 6px;
            text-align: center;
        }
        
        .stat-box h3 { font-size: 24px; color: var(--primary); }
        .stat-box p { color: #6b7280; font-size: 14px; }
        
        .collapsible {
            cursor: pointer;
            padding: 10px;
            background: var(--light);
            border-radius: 4px;
            margin: 5px 0;
        }
        
        .collapsible:hover { background: #e5e7eb; }
        
        .collapsible-content {
            display: none;
            padding: 10px;
            border-left: 3px solid var(--primary);
            margin-left: 10px;
        }
        
        .collapsible-content.show { display: block; }
        
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .checkbox-group input[type="checkbox"] {
            width: auto;
        }
        
        #dns-test-result {
            margin-top: 15px;
            padding: 15px;
            background: var(--light);
            border-radius: 6px;
            display: none;
        }
        
        #dns-test-result.show { display: block; }
        
        .spf-preview {
            background: #1f2937;
            color: #10b981;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            word-break: break-all;
            margin-top: 10px;
        }
        
        .mechanism-list {
            margin-top: 10px;
        }
        
        .mechanism-item {
            padding: 5px 10px;
            background: var(--light);
            border-radius: 4px;
            margin: 5px 0;
            font-size: 13px;
        }
        
        .import-status {
            padding: 10px;
            border-radius: 6px;
            margin-top: 10px;
        }
        
        .import-status.success { background: #d1fae5; color: #065f46; }
        .import-status.error { background: #fee2e2; color: #991b1b; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ SPF Flattener</h1>
            <p>Manage and flatten SPF records to stay under the 10-lookup limit</p>
        </header>
        
        <?php if ($message): ?>
            <div class="alert alert-<?= $messageType ?>"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>
        
        <div class="card">
            <div class="grid-2">
                <div class="stat-box">
                    <h3><?= count($domains) ?></h3>
                    <p>Domains Configured</p>
                </div>
                <div class="stat-box">
                    <h3>
                        <?php
                        $totalIps = 0;
                        foreach ($domains as $d) { $totalIps += $d['ip_count']; }
                        echo $totalIps;
                        ?>
                    </h3>
                    <p>Total Flattened IPs</p>
                </div>
            </div>
        </div>
        
        <div class="tabs">
            <div class="tab active" onclick="showTab('domains')">Domains</div>
            <div class="tab" onclick="showTab('add-domain')">Add Domain</div>
            <div class="tab" onclick="showTab('senders')">Approved Senders</div>
            <div class="tab" onclick="showTab('config')">Configuration</div>
        </div>
        
        <div id="domains" class="tab-content active">
            <div class="card">
                <h2>Configured Domains</h2>
                
                <?php if (empty($domains)): ?>
                    <p>No domains configured yet. Click "Add Domain" to get started.</p>
                <?php else: ?>
                    <table>
                        <thead>
                            <tr>
                                <th>Domain</th>
                                <th>Senders</th>
                                <th>Flattened IPs</th>
                                <th>Lookups Before</th>
                                <th>Last Flattened</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($domains as $domain): ?>
                                <tr>
                                    <td>
                                        <strong><?= htmlspecialchars($domain['domain']) ?></strong>
                                        <?php if ($domain['cloudflare_zone_id']): ?>
                                            <span class="badge badge-info">Cloudflare</span>
                                        <?php endif; ?>
                                    </td>
                                    <td><?= $domain['sender_count'] ?></td>
                                    <td><?= $domain['ip_count'] ?></td>
                                    <td>
                                        <?php if ($domain['lookup_count_before'] > 10): ?>
                                            <span class="badge badge-danger"><?= $domain['lookup_count_before'] ?> (Over limit!)</span>
                                        <?php else: ?>
                                            <span class="badge badge-success"><?= $domain['lookup_count_before'] ?></span>
                                        <?php endif; ?>
                                    </td>
                                    <td><?= $domain['last_flattened_at'] ? date('Y-m-d H:i', strtotime($domain['last_flattened_at'])) : 'Never' ?></td>
                                    <td>
                                        <form method="POST" style="display: inline;">
                                            <input type="hidden" name="action" value="flatten">
                                            <input type="hidden" name="domain_id" value="<?= $domain['id'] ?>">
                                            <button type="submit" class="btn btn-primary btn-sm">⚡ Flatten</button>
                                        </form>
                                        
                                        <?php if ($domain['flattened_spf_record']): ?>
                                            <button class="btn btn-sm" onclick="toggleRecord(<?= $domain['id'] ?>)">📋 View</button>
                                        <?php endif; ?>
                                        
                                        <form method="POST" style="display: inline;" onsubmit="return confirm('Delete this domain?')">
                                            <input type="hidden" name="action" value="delete_domain">
                                            <input type="hidden" name="domain_id" value="<?= $domain['id'] ?>">
                                            <button type="submit" class="btn btn-danger btn-sm">🗑️</button>
                                        </form>
                                        
                                        <?php if ($domain['flattened_spf_record']): ?>
                                            <div id="record-<?= $domain['id'] ?>" class="collapsible-content">
                                                <div class="spf-record"><?= htmlspecialchars($domain['flattened_spf_record']) ?></div>
                                            </div>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        </div>
        
        <div id="add-domain" class="tab-content">
            <div class="card">
                <h2>Add New Domain</h2>
                
                <div class="grid-2">
                    <div>
                        <h3>📥 Import from DNS</h3>
                        <p style="margin-bottom: 15px; color: #6b7280; font-size: 14px;">
                            Automatically fetch and parse your existing SPF record from DNS
                        </p>
                        <form id="import-form" onsubmit="return false;">
                            <div class="form-group">
                                <label for="import_domain">Domain Name *</label>
                                <input type="text" id="import_domain" placeholder="example.com" required>
                            </div>
                            <div class="form-group">
                                <label for="import_cloudflare_zone_id">Cloudflare Zone ID (optional)</label>
                                <input type="text" id="import_cloudflare_zone_id" placeholder="Leave empty if not using Cloudflare">
                            </div>
                            <button type="button" class="btn btn-secondary" onclick="testDNS()">🔍 Test DNS Lookup</button>
                            <button type="button" class="btn btn-primary" onclick="fetchSPF()">📡 Fetch SPF Record</button>
                            <button type="button" class="btn btn-success" onclick="importSPF()" id="import_btn" style="display:none;">➕ Import & Add Domain</button>
                            
                            <div id="dns-test-result"></div>
                        </form>
                    </div>
                    
                    <div>
                        <h3>✏️ Add Manually</h3>
                        <form method="POST">
                            <input type="hidden" name="action" value="add_domain">
                            <div class="form-group">
                                <label for="domain">Domain Name *</label>
                                <input type="text" id="domain" name="domain" placeholder="example.com" required>
                            </div>
                            <div class="form-group">
                                <label for="cloudflare_zone_id">Cloudflare Zone ID (optional)</label>
                                <input type="text" id="cloudflare_zone_id" name="cloudflare_zone_id" placeholder="Leave empty if not using Cloudflare">
                            </div>
                            <div class="form-group checkbox-group">
                                <input type="checkbox" id="import_spf" name="import_spf" value="1">
                                <label for="import_spf">Import SPF record from DNS after adding</label>
                            </div>
                            <button type="submit" class="btn btn-primary">➕ Add Domain</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        
        <div id="senders" class="tab-content">
            <div class="card">
                <h2>Approved Senders</h2>
                
                <div class="grid-2">
                    <div>
                        <h3>Add Approved Sender</h3>
                        <form method="POST">
                            <input type="hidden" name="action" value="add_sender">
                            <div class="form-group">
                                <label for="domain_id">Domain *</label>
                                <select id="domain_id" name="domain_id" required>
                                    <option value="">Select domain...</option>
                                    <?php foreach ($domains as $d): ?>
                                        <option value="<?= $d['id'] ?>"><?= htmlspecialchars($d['domain']) ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="sending_domain">Sending Domain *</label>
                                <input type="text" id="sending_domain" name="sending_domain" placeholder="mail.example.com" required>
                            </div>
                            <div class="form-group">
                                <label for="sender_name">Sender Name *</label>
                                <input type="text" id="sender_name" name="sender_name" placeholder="Google Workspace" required>
                            </div>
                            <div class="form-group">
                                <label for="include_domain">Include Domain (SPF mechanism) *</label>
                                <input type="text" id="include_domain" name="include_domain" placeholder="_spf.google.com" required>
                            </div>
                            <button type="submit" class="btn btn-primary">➕ Add Sender</button>
                        </form>
                    </div>
                    
                    <div>
                        <h3>Current Senders</h3>
                        <?php foreach ($sendersByDomain as $domainId => $senders): ?>
                            <div class="collapsible" onclick="toggleSender(this)">
                                <strong><?= htmlspecialchars($domains[array_search($domainId, array_column($domains, 'id'))]['domain']) ?></strong>
                                (<?= count($senders) ?> senders)
                            </div>
                            <div class="collapsible-content">
                                <table>
                                    <thead>
                                        <tr>
                                            <th>Sender</th>
                                            <th>Include Domain</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($senders as $sender): ?>
                                            <tr>
                                                <td><?= htmlspecialchars($sender['sender_name']) ?></td>
                                                <td><code><?= htmlspecialchars($sender['include_domain']) ?></code></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
        </div>
        
        <div id="config" class="tab-content">
            <div class="card">
                <h2>Configuration</h2>
                
                <div class="form-group">
                    <h3>Cloudflare Integration</h3>
                    <p>Enable automatic SPF record updates in Cloudflare DNS</p>
                    <form method="POST" action="save_config.php">
                        <div class="form-row">
                            <div class="form-group">
                                <label>Cloudflare API Email</label>
                                <input type="email" name="cloudflare_api_email" value="">
                            </div>
                            <div class="form-group">
                                <label>Cloudflare API Key</label>
                                <input type="password" name="cloudflare_api_key">
                            </div>
                        </div>
                        <button type="submit" class="btn btn-primary">Save Cloudflare Settings</button>
                    </form>
                </div>
                
                <div class="form-group">
                    <h3>Email Notifications</h3>
                    <p>Get notified when SPF records change</p>
                    <form method="POST" action="save_config.php">
                        <div class="form-row">
                            <div class="form-group">
                                <label>SMTP Server</label>
                                <input type="text" name="smtp_server">
                            </div>
                            <div class="form-group">
                                <label>SMTP Port</label>
                                <input type="number" name="smtp_port" value="587">
                            </div>
                        </div>
                        <div class="form-row">
                            <div class="form-group">
                                <label>From Email</label>
                                <input type="email" name="smtp_from_email">
                            </div>
                            <div class="form-group">
                                <label>From Name</label>
                                <input type="text" name="smtp_from_name" value="SPF Flattener">
                            </div>
                        </div>
                        <button type="submit" class="btn btn-primary">Save Email Settings</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function showTab(tabId) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            event.target.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        }
        
        function toggleRecord(domainId) {
            const content = document.getElementById('record-' + domainId);
            content.classList.toggle('show');
        }
        
        function toggleSender(element) {
            const content = element.nextElementSibling;
            content.classList.toggle('show');
        }
        
        async function testDNS() {
            const domain = document.getElementById('import_domain').value.trim();
            if (!domain) {
                alert('Please enter a domain name');
                return;
            }
            
            const resultDiv = document.getElementById('dns-test-result');
            resultDiv.innerHTML = 'Testing DNS lookup...';
            resultDiv.classList.add('show');
            
            const formData = new FormData();
            formData.append('action', 'test_dns');
            formData.append('domain', domain);
            
            try {
                const response = await fetch('import_spf.php', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                
                if (result.success) {
                    resultDiv.className = 'import-status success';
                    resultDiv.innerHTML = '<strong>✓ DNS lookup successful!</strong><br>' +
                        'Found ' + result.txt_records.length + ' TXT record(s)';
                } else {
                    resultDiv.className = 'import-status error';
                    resultDiv.innerHTML = '<strong>✗ DNS lookup failed</strong><br>' + 
                        (result.errors ? result.errors.join('<br>') : result.error);
                }
            } catch (e) {
                resultDiv.className = 'import-status error';
                resultDiv.innerHTML = '<strong>✗ Error:</strong> ' + e.message;
            }
        }
        
        async function fetchSPF() {
            const domain = document.getElementById('import_domain').value.trim();
            if (!domain) {
                alert('Please enter a domain name');
                return;
            }
            
            const resultDiv = document.getElementById('dns-test-result');
            resultDiv.innerHTML = 'Fetching SPF record...';
            resultDiv.classList.add('show');
            
            const formData = new FormData();
            formData.append('action', 'fetch_spf');
            formData.append('domain', domain);
            
            try {
                const response = await fetch('import_spf.php', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                
                if (result.success) {
                    resultDiv.className = 'import-status success';
                    
                    let html = '<strong>✓ SPF record found!</strong><br><br>';
                    html += '<strong>Original Record:</strong><br>';
                    html += '<div class="spf-preview">' + result.spf_record + '</div><br>';
                    html += '<strong>Lookup Count:</strong> ' + result.lookup_count + ' ';
                    html += result.lookup_count > 10 ? '<span class="badge badge-danger">(Over 10 limit!)</span>' : '<span class="badge badge-success">(Under limit)</span>';
                    html += '<br><br>';
                    
                    if (result.includes.length > 0) {
                        html += '<strong>Include Mechanisms Found (' + result.includes.length + '):</strong>';
                        html += '<div class="mechanism-list">';
                        result.includes.forEach(include => {
                            html += '<div class="mechanism-item">📧 include:' + include + '</div>';
                        });
                        html += '</div>';
                    }
                    
                    if (result.ip4.length > 0) {
                        html += '<br><strong>Direct IPv4 Entries (' + result.ip4.length + '):</strong><br>';
                        result.ip4.forEach(ip => {
                            html += '<div class="mechanism-item">🌐 ip4:' + ip + '</div>';
                        });
                    }
                    
                    if (result.has_a) html += '<br>⚠️ Has A mechanism (causes DNS lookup)';
                    if (result.has_mx) html += '<br>⚠️ Has MX mechanism (causes DNS lookup)';
                    if (result.redirect) html += '<br>🔄 Redirects to: ' + result.redirect;
                    
                    resultDiv.innerHTML = html;
                    document.getElementById('import_btn').style.display = 'inline-block';
                } else {
                    resultDiv.className = 'import-status error';
                    resultDiv.innerHTML = '<strong>✗ No SPF record found</strong><br>' + 
                        (result.error || 'The domain has no SPF record published in DNS.');
                    document.getElementById('import_btn').style.display = 'none';
                }
            } catch (e) {
                resultDiv.className = 'import-status error';
                resultDiv.innerHTML = '<strong>✗ Error:</strong> ' + e.message;
                document.getElementById('import_btn').style.display = 'none';
            }
        }
        
        async function importSPF() {
            const domain = document.getElementById('import_domain').value.trim();
            const cloudflareZoneId = document.getElementById('import_cloudflare_zone_id').value.trim();
            
            if (!domain) {
                alert('Please enter a domain name');
                return;
            }
            
            const resultDiv = document.getElementById('dns-test-result');
            resultDiv.innerHTML = 'Importing SPF record...';
            
            const formData = new FormData();
            formData.append('action', 'add_and_import');
            formData.append('domain', domain);
            formData.append('cloudflare_zone_id', cloudflareZoneId);
            
            try {
                const response = await fetch('import_spf.php', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                
                if (result.success) {
                    resultDiv.className = 'import-status success';
                    resultDiv.innerHTML = '<strong>✓ Import successful!</strong><br>' +
                        (result.import_summary || 'Added ' + result.senders_added + ' sender(s) automatically.') + '<br>' +
                        'Redirecting to domains list...';
                    
                    setTimeout(() => {
                        window.location.href = 'index.php';
                    }, 2000);
                } else {
                    resultDiv.className = 'import-status error';
                    resultDiv.innerHTML = '<strong>✗ Import failed</strong><br>' + 
                        (result.errors ? result.errors.join('<br>') : result.error);
                }
            } catch (e) {
                resultDiv.className = 'import-status error';
                resultDiv.innerHTML = '<strong>✗ Error:</strong> ' + e.message;
            }
        }
    </script>
</body>
</html>
