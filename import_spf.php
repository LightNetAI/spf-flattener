<?php
/**
 * AJAX Handler for SPF Import — authentication required
 */

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/includes/Database.php';
require_once __DIR__ . '/includes/Security.php';
require_once __DIR__ . '/includes/Setup.php';
require_once __DIR__ . '/includes/Auth.php';
require_once __DIR__ . '/includes/DNSLookup.php';

// Not installed yet? Send the user to the installer.
if (!Setup::isInstalled()) {
    if (basename($_SERVER['SCRIPT_NAME'] ?? '') === 'import_spf.php') {
        header('Content-Type: application/json');
        http_response_code(503);
        echo json_encode(['success' => false, 'error' => 'The application is not installed yet.']);
        exit;
    }
    header('Location: setup.php');
    exit;
}

header('Content-Type: application/json');

Auth::startSession();
$auth = new Auth();
$auth->requireLoginJson();

// CSRF is required for every state-changing call.
if (!verifyCSRFToken($_POST['csrf_token'] ?? '')) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Invalid or missing CSRF token']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}

$user = $auth->user();
if (!in_array($user['role'], ['admin', 'operator'], true)) {
    $auth->auditCurrent('ACCESS_DENIED', 'AJAX import as ' . $user['role']);
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Your role does not permit imports']);
    exit;
}

$action = $_POST['action'] ?? '';
$db = getDB();

try {
    if ($action === 'fetch_spf') {
        $domain = strtolower(trim($_POST['domain'] ?? ''));

        if (!isValidDomain($domain)) {
            echo json_encode(['success' => false, 'error' => 'That is not a valid domain name.']);
            exit;
        }

        $dns = new DNSLookup();
        $spfRecord  = $dns->getSPFRecord($domain);
        $mechanisms = $dns->parseSPFRecord($spfRecord);
        $lookupCount = $dns->countLookups($spfRecord);

        if (empty($spfRecord)) {
            echo json_encode([
                'success' => false,
                'error' => "No SPF record found for {$domain}.",
            ]);
            exit;
        }

        $auth->auditCurrent('SPF_FETCHED', "Fetched SPF for {$domain}", $domain);

        echo json_encode([
            'success'      => true,
            'domain'       => $domain,
            'spf_record'   => $spfRecord,
            'lookup_count' => $lookupCount,
            'mechanisms'   => $mechanisms,
            'includes'     => $mechanisms['includes'],
            'ip4'          => $mechanisms['ip4'],
            'ip6'          => $mechanisms['ip6'],
            'has_a'        => !empty($mechanisms['a_records']),
            'has_mx'       => !empty($mechanisms['mx_records']),
            'redirect'     => $mechanisms['redirect'],
        ]);
        exit;
    }

    if ($action === 'add_and_import') {
        $domain = strtolower(trim($_POST['domain'] ?? ''));
        $zoneId = sanitizeString($_POST['cloudflare_zone_id'] ?? '', 100);

        if (!isValidDomain($domain)) {
            echo json_encode(['success' => false, 'error' => 'That is not a valid domain name.']);
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

        $dns = new DNSLookup();
        $res = $dns->importSPFForDomain($domainId, $user['username'], 'import');

        if ($res['success']) {
            $parts = [];
            if (!empty($res['mechanisms']['includes'])) {
                $parts[] = count($res['mechanisms']['includes']) . ' include(s)';
            }
            if (!empty($res['direct_ips']['ip4'])) {
                $parts[] = count($res['direct_ips']['ip4']) . ' IPv4';
            }
            if (!empty($res['direct_ips']['ip6'])) {
                $parts[] = count($res['direct_ips']['ip6']) . ' IPv6';
            }
            if (!empty($res['has_a_records'])) {
                $parts[] = 'A record(s)';
            }
            if (!empty($res['has_mx_records'])) {
                $parts[] = 'MX record(s)';
            }
            $res['import_summary'] = 'Imported ' . $res['senders_added'] . ' sender(s): ' . implode(', ', $parts) . '.';
            $auth->auditCurrent('SPF_IMPORTED', $res['import_summary'], $domain);
        }

        echo json_encode(array_merge(['domain_id' => $domainId, 'domain' => $domain], $res));
        exit;
    }

    echo json_encode(['success' => false, 'error' => 'Unknown action']);

} catch (Exception $e) {
    error_log('import_spf.php error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'An internal error occurred.']);
}
