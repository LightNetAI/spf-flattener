<?php
/**
 * AJAX Handler for SPF Import
 * Handles DNS lookup and import of existing SPF records
 */

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/includes/Database.php';
require_once __DIR__ . '/includes/DNSLookup.php';

header('Content-Type: application/json');

// Only allow POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}

$action = $_POST['action'] ?? '';
$db = getDB();

try {
    if ($action === 'test_dns') {
        // Test DNS lookup functionality
        $dns = new DNSLookup();
        $testDomain = $_POST['domain'] ?? 'google.com';
        $result = $dns->testDNS($testDomain);
        echo json_encode($result);
        
    } elseif ($action === 'fetch_spf') {
        // Fetch SPF record for a domain
        $domain = trim($_POST['domain'] ?? '');
        
        if (empty($domain)) {
            echo json_encode(['success' => false, 'error' => 'Domain is required']);
            exit;
        }
        
        $dns = new DNSLookup();
        $spfRecord = $dns->getSPFRecord($domain);
        $mechanisms = $dns->parseSPFRecord($spfRecord);
        $lookupCount = $dns->countLookups($spfRecord);
        
        if (empty($spfRecord)) {
            echo json_encode([
                'success' => false,
                'error' => "No SPF record found for {$domain}",
                'txt_records' => $dns->getTXTRecords($domain)
            ]);
            exit;
        }
        
        echo json_encode([
            'success' => true,
            'domain' => $domain,
            'spf_record' => $spfRecord,
            'lookup_count' => $lookupCount,
            'mechanisms' => $mechanisms,
            'includes' => $mechanisms['includes'],
            'ip4' => $mechanisms['ip4'],
            'ip6' => $mechanisms['ip6'],
            'has_a' => !empty($mechanisms['a_records']),
            'has_mx' => !empty($mechanisms['mx_records']),
            'redirect' => $mechanisms['redirect']
        ]);
        
    } elseif ($action === 'import') {
        // Import SPF record for an existing domain
        $domainId = $_POST['domain_id'] ?? 0;
        
        if (!$domainId) {
            echo json_encode(['success' => false, 'error' => 'Domain ID is required']);
            exit;
        }
        
        $dns = new DNSLookup();
        $result = $dns->importSPFForDomain($domainId);
        
        echo json_encode($result);
        
    } elseif ($action === 'add_and_import') {
        // Add new domain and immediately import its SPF
        $domain = trim($_POST['domain'] ?? '');
        $cloudflareZoneId = trim($_POST['cloudflare_zone_id'] ?? '');
        
        if (empty($domain)) {
            echo json_encode(['success' => false, 'error' => 'Domain is required']);
            exit;
        }
        
        // Add domain first
        $stmt = $db->prepare("
            INSERT INTO domains (domain, cloudflare_zone_id, is_active)
            VALUES (?, ?, 1)
            ON DUPLICATE KEY UPDATE cloudflare_zone_id = VALUES(cloudflare_zone_id)
        ");
        $stmt->execute([$domain, $cloudflareZoneId]);
        $domainId = $db->lastInsertId();
        
        // Now import SPF
        $dns = new DNSLookup();
        $importResult = $dns->importSPFForDomain($domainId);
        
        echo json_encode(array_merge([
            'domain_id' => $domainId,
            'domain' => $domain
        ], $importResult));
        
    } else {
        echo json_encode(['success' => false, 'error' => 'Unknown action']);
    }
    
} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}
