#!/usr/bin/env php
<?php
/**
 * SPF Flattener - Command Line Interface
 * 
 * Alternative to the web interface for CLI users
 * Replicates cfspflat's CLI functionality
 * 
 * Usage:
 *   php cli.php flatten --domain=example.com
 *   php cli.php check --domain=example.com
 *   php cli.php list
 *   php cli.php import --domain=example.com
 *   php cli.php config --set key=value
 */

chdir(__DIR__);

require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/includes/Database.php';
require_once __DIR__ . '/includes/SPFFlattener.php';
require_once __DIR__ . '/includes/CloudflareAPI.php';
require_once __DIR__ . '/includes/DNSLookup.php';

$db = getDB();
$flattener = new SPFFlattener();
$dns = new DNSLookup();

// Parse command
$command = $argv[1] ?? 'help';
$options = getopt('', ['domain:', 'force', 'no-email', 'set:', 'help']);

switch ($command) {
    case 'flatten':
        cmdFlatten($options);
        break;
    
    case 'check':
        cmdCheck($options);
        break;
    
    case 'list':
        cmdList();
        break;
    
    case 'import':
        cmdImport($options);
        break;
    
    case 'dns-test':
        cmdDNSTest($options);
        break;
    
    case 'config':
        cmdConfig($options);
        break;
    
    case 'help':
    default:
        showHelp();
        break;
}

function cmdFlatten($options) {
    global $flattener, $db;
    
    $domainName = $options['domain'] ?? null;
    
    if (!$domainName) {
        echo "Error: --domain is required\n";
        exit(1);
    }
    
    // Get domain ID
    $stmt = $db->prepare("SELECT id FROM domains WHERE domain = ?");
    $stmt->execute([$domainName]);
    $domainId = $stmt->fetchColumn();
    
    if (!$domainId) {
        echo "Error: Domain '{$domainName}' not found\n";
        exit(1);
    }
    
    echo "Flattening SPF for {$domainName}...\n";
    
    $result = $flattener->flattenDomain($domainId);
    
    if ($result['success']) {
        echo "\n✓ Flattening successful!\n\n";
        echo "Original lookups: {$result['lookup_count_before']}\n";
        echo "Flattened lookups: {$result['lookup_count_after']}\n";
        echo "IPs collected: " . count($result['ips_collected']) . "\n\n";
        echo "Flattened SPF Record:\n";
        echo str_repeat('-', 60) . "\n";
        echo $result['flattened_record'] . "\n";
        echo str_repeat('-', 60) . "\n";
        
        if (!empty($result['warnings'])) {
            echo "\nWarnings:\n";
            foreach ($result['warnings'] as $warning) {
                echo "  ⚠ {$warning}\n";
            }
        }
    } else {
        echo "✗ Flattening failed\n";
        foreach ($result['errors'] as $error) {
            echo "  Error: {$error}\n";
        }
        exit(1);
    }
}

function cmdCheck($options) {
    global $flattener, $db;
    
    $domainName = $options['domain'] ?? null;
    
    if (!$domainName) {
        echo "Error: --domain is required\n";
        exit(1);
    }
    
    $stmt = $db->prepare("SELECT id FROM domains WHERE domain = ?");
    $stmt->execute([$domainName]);
    $domainId = $stmt->fetchColumn();
    
    if (!$domainId) {
        echo "Error: Domain '{$domainName}' not found\n";
        exit(1);
    }
    
    echo "Checking for SPF changes in {$domainName}...\n";
    
    $changes = $flattener->detectChanges($domainId);
    
    if ($changes['has_changes']) {
        echo "\n⚠ Changes detected!\n\n";
        
        if (!empty($changes['ips_added'])) {
            echo "IPs Added (" . count($changes['ips_added']) . "):\n";
            foreach ($changes['ips_added'] as $ip) {
                echo "  + {$ip}\n";
            }
            echo "\n";
        }
        
        if (!empty($changes['ips_removed'])) {
            echo "IPs Removed (" . count($changes['ips_removed']) . "):\n";
            foreach ($changes['ips_removed'] as $ip) {
                echo "  - {$ip}\n";
            }
            echo "\n";
        }
        
        echo "Run 'php cli.php flatten --domain={$domainName}' to update\n";
    } else {
        echo "\n✓ No changes detected\n";
    }
}

function cmdImport($options) {
    global $db, $dns;
    
    $domainName = $options['domain'] ?? null;
    $addIfMissing = isset($options['add']);
    
    if (!$domainName) {
        echo "Error: --domain is required\n";
        exit(1);
    }
    
    // Check if domain exists in database
    $stmt = $db->prepare("SELECT id FROM domains WHERE domain = ?");
    $stmt->execute([$domainName]);
    $domainId = $stmt->fetchColumn();
    
    if (!$domainId) {
        if ($addIfMissing) {
            echo "Domain not found. Adding {$domainName}...\n";
            $stmt = $db->prepare("INSERT INTO domains (domain, is_active) VALUES (?, 1)");
            $stmt->execute([$domainName]);
            $domainId = $db->lastInsertId();
            echo "✓ Domain added with ID {$domainId}\n";
        } else {
            echo "Error: Domain '{$domainName}' not found in database.\n";
            echo "Use --add to add it first, or add it via the web interface.\n";
            exit(1);
        }
    }
    
    echo "Importing SPF record for {$domainName} from DNS...\n\n";
    
    // Fetch SPF record from DNS
    $spfRecord = $dns->getSPFRecord($domainName);
    
    if (empty($spfRecord)) {
        echo "✗ No SPF record found for {$domainName}\n";
        echo "\nTXT records found:\n";
        $txtRecords = $dns->getTXTRecords($domainName);
        if (empty($txtRecords)) {
            echo "  (none)\n";
        } else {
            foreach ($txtRecords as $record) {
                echo "  " . substr($record, 0, 80) . (strlen($record) > 80 ? '...' : '') . "\n";
            }
        }
        exit(1);
    }
    
    echo "✓ Found SPF record:\n";
    echo str_repeat('-', 60) . "\n";
    echo $spfRecord . "\n";
    echo str_repeat('-', 60) . "\n\n";
    
    // Parse and import
    $result = $dns->importSPFForDomain($domainId);
    
    if ($result['success']) {
        echo "✓ Import successful!\n\n";
        echo "Senders added: {$result['senders_added']}\n";
        echo "Includes found: {$result['includes_found']}\n";
        
        if (!empty($result['mechanisms']['includes'])) {
            echo "\nImported include mechanisms:\n";
            foreach ($result['mechanisms']['includes'] as $include) {
                echo "  • include:{$include}\n";
            }
        }
        
        // Show direct IP entries
        if (!empty($result['direct_ips']['ip4'])) {
            echo "\nImported direct IPv4 addresses:\n";
            foreach ($result['direct_ips']['ip4'] as $ip4) {
                echo "  • ip4:{$ip4}\n";
            }
        }
        
        if (!empty($result['direct_ips']['ip6'])) {
            echo "\nImported direct IPv6 addresses:\n";
            foreach ($result['direct_ips']['ip6'] as $ip6) {
                echo "  • ip6:{$ip6}\n";
            }
        }
        
        // Warn about A/MX records that need manual attention
        if ($result['has_a_records']) {
            echo "\n⚠️  A record mechanisms found (these cause DNS lookups):\n";
            foreach ($result['a_records'] as $aRecord) {
                echo "  • {$aRecord}\n";
            }
            echo "   These will be resolved during flattening.\n";
        }
        
        if ($result['has_mx_records']) {
            echo "\n⚠️  MX record mechanisms found (these cause DNS lookups):\n";
            foreach ($result['mx_records'] as $mxRecord) {
                echo "  • {$mxRecord}\n";
            }
            echo "   These will be resolved during flattening.\n";
        }
        
        echo "\nYou can now run: php cli.php flatten --domain={$domainName}\n";
    } else {
        echo "✗ Import failed\n";
        foreach ($result['errors'] as $error) {
            echo "  Error: {$error}\n";
        }
        exit(1);
    }
}

function cmdDNSTest($options) {
    global $dns;
    
    $domainName = $options['domain'] ?? 'google.com';
    
    echo "Testing DNS lookup for {$domainName}...\n\n";
    
    $result = $dns->testDNS($domainName);
    
    if (!$result['success']) {
        echo "✗ DNS test failed\n";
        foreach ($result['errors'] as $error) {
            echo "  Error: {$error}\n";
        }
        exit(1);
    }
    
    echo "✓ DNS lookup successful\n\n";
    echo "TXT Records Found (" . count($result['txt_records']) . "):\n";
    foreach ($result['txt_records'] as $record) {
        echo "  " . substr($record, 0, 80) . (strlen($record) > 80 ? '...' : '') . "\n";
    }
    
    if (!empty($result['spf_record'])) {
        echo "\nSPF Record:\n";
        echo "  " . $result['spf_record'] . "\n";
        
        $mechanisms = $dns->parseSPFRecord($result['spf_record']);
        $lookupCount = $dns->countLookups($result['spf_record']);
        
        echo "\nLookup count: {$lookupCount}" . ($lookupCount > 10 ? " (OVER LIMIT!)" : "") . "\n";
        echo "Includes: " . count($mechanisms['includes']) . "\n";
        echo "IPv4 entries: " . count($mechanisms['ip4']) . "\n";
        echo "IPv6 entries: " . count($mechanisms['ip6']) . "\n";
    } else {
        echo "\nNo SPF record found in TXT records.\n";
    }
}

function cmdList() {
    global $db;
    
    $stmt = $db->query("
        SELECT d.*, 
               (SELECT COUNT(*) FROM sending_domains sd WHERE sd.domain_id = d.id) as sender_count,
               (SELECT COUNT(*) FROM flattened_ips fi WHERE fi.domain_id = d.id AND fi.is_active = 1) as ip_count
        FROM domains d 
        ORDER BY d.created_at DESC
    ");
    
    $domains = $stmt->fetchAll();
    
    if (empty($domains)) {
        echo "No domains configured.\n";
        return;
    }
    
    echo "\nConfigured Domains:\n";
    echo str_repeat('=', 80) . "\n";
    printf("%-30s %-10s %-10s %-12s %-15s\n", "Domain", "Senders", "IPs", "Lookups", "Last Flattened");
    echo str_repeat('-', 80) . "\n";
    
    foreach ($domains as $domain) {
        $lastFlattened = $domain['last_flattened_at'] 
            ? date('Y-m-d', strtotime($domain['last_flattened_at'])) 
            : 'Never';
        
        $lookupStatus = $domain['lookup_count_before'] > 10 
            ? $domain['lookup_count_before'] . '!' 
            : $domain['lookup_count_before'];
        
        printf("%-30s %-10s %-10s %-12s %-15s\n", 
            $domain['domain'],
            $domain['sender_count'],
            $domain['ip_count'],
            $lookupStatus,
            $lastFlattened
        );
    }
    
    echo str_repeat('=', 80) . "\n";
}

function cmdConfig($options) {
    global $db;
    
    if (!isset($options['set'])) {
        // Show current config
        $stmt = $db->query("SELECT config_key, config_value FROM config ORDER BY config_key");
        $configs = $stmt->fetchAll();
        
        echo "\nCurrent Configuration:\n";
        echo str_repeat('-', 50) . "\n";
        foreach ($configs as $config) {
            $value = strlen($config['config_value']) > 30 
                ? substr($config['config_value'], 0, 27) . '...' 
                : $config['config_value'];
            echo "{$config['config_key']}: {$value}\n";
        }
        echo str_repeat('-', 50) . "\n";
        return;
    }
    
    // Set config value
    $setting = $options['set'];
    $parts = explode('=', $setting, 2);
    
    if (count($parts) !== 2) {
        echo "Error: Invalid format. Use --set key=value\n";
        exit(1);
    }
    
    list($key, $value) = $parts;
    
    try {
        $stmt = $db->prepare("
            INSERT INTO config (config_key, config_value) 
            VALUES (?, ?)
            ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)
        ");
        $stmt->execute([$key, $value]);
        echo "✓ Configuration updated: {$key} = {$value}\n";
    } catch (Exception $e) {
        echo "Error: {$e->getMessage()}\n";
        exit(1);
    }
}

function showHelp() {
    echo "\n";
    echo "SPF Flattener CLI\n";
    echo str_repeat('=', 50) . "\n\n";
    echo "Usage:\n";
    echo "  php cli.php <command> [options]\n\n";
    echo "Commands:\n";
    echo "  flatten    Flatten SPF record for a domain\n";
    echo "  check      Check for SPF changes\n";
    echo "  list       List all configured domains\n";
    echo "  import     Import SPF record from DNS\n";
    echo "  dns-test   Test DNS lookup (debug)\n";
    echo "  config     View or set configuration\n";
    echo "  help       Show this help message\n\n";
    echo "Options:\n";
    echo "  --domain=DOMAIN    Target domain (required for flatten/check/import)\n";
    echo "  --add              Add domain if not found (for import command)\n";
    echo "  --force            Force update even if no changes\n";
    echo "  --no-email         Don't send notification emails\n";
    echo "  --set KEY=VALUE    Set configuration value\n\n";
    echo "Examples:\n";
    echo "  php cli.php list\n";
    echo "  php cli.py flatten --domain=example.com\n";
    echo "  php cli.php check --domain=example.com\n";
    echo "  php cli.php import --domain=example.com\n";
    echo "  php cli.php import --domain=newdomain.com --add\n";
    echo "  php cli.php dns-test --domain=google.com\n";
    echo "  php cli.php config --set cloudflare_api_email=user@example.com\n\n";
    echo str_repeat('=', 50) . "\n";
}
