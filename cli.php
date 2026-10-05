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
require_once __DIR__ . '/includes/Security.php';
require_once __DIR__ . '/includes/Auth.php';
require_once __DIR__ . '/includes/SPFFlattener.php';
require_once __DIR__ . '/includes/CloudflareAPI.php';
require_once __DIR__ . '/includes/DNSLookup.php';

$db = getDB();
$flattener = new SPFFlattener();
$dns = new DNSLookup();

// Parse command
$command = $argv[1] ?? 'help';

/**
 * Parse "command --flag --key=value" style arguments.
 * getopt() stops at the first non-option token, which breaks when the
 * command name precedes the flags, so parse manually.
 */
function parseOptions(array $argv) {
    $opts = [];
    foreach (array_slice($argv, 2) as $arg) {
        if (str_starts_with($arg, '--')) {
            $arg = substr($arg, 2);
            if (str_contains($arg, '=')) {
                [$k, $v] = explode('=', $arg, 2);
                $opts[$k] = $v;
            } else {
                $opts[$arg] = true;
            }
        }
    }
    return $opts;
}

$options = parseOptions($argv);

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

    case 'records':
        cmdRecords($options);
        break;
    
    case 'config':
        cmdConfig($options);
        break;

    case 'user:add':
        cmdUserAdd($options);
        break;

    case 'user:list':
        cmdUserList();
        break;

    case 'user:passwd':
        cmdUserPasswd($options);
        break;

    case 'audit':
        cmdAudit($options);
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
    $result = $dns->importSPFForDomain($domainId, 'cli', 'import');
    
    if ($result['success']) {
        echo "✓ Import successful!\n\n";
        echo "Senders added: {$result['senders_added']}\n";
        echo "Includes found: {$result['includes_found']}\n";
        if (!empty($result['snapshot_id'])) {
            echo "Snapshot saved: #{$result['snapshot_id']} (review with: php cli.php records --domain={$domainName})\n";
        }
        
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

/**
 * Show the stored original SPF record snapshots for a domain.
 */
function cmdRecords($options) {
    global $db, $dns;

    $domainName = $options['domain'] ?? null;
    if (!$domainName) {
        echo "Error: --domain is required\n";
        echo "Usage: php cli.php records --domain=example.com\n";
        exit(1);
    }

    $stmt = $db->prepare("SELECT id FROM domains WHERE domain = ?");
    $stmt->execute([$domainName]);
    $domainId = $stmt->fetchColumn();

    if (!$domainId) {
        echo "Error: Domain '{$domainName}' not found\n";
        exit(1);
    }

    $history = $dns->getRecordHistory($domainId, 100);

    if (empty($history)) {
        echo "No SPF records have been captured for {$domainName} yet.\n";
        echo "Run: php cli.php import --domain={$domainName}\n";
        return;
    }

    echo "\nOriginal SPF records captured for {$domainName} (" . count($history) . "):\n";
    echo str_repeat('=', 78) . "\n";

    foreach ($history as $i => $snap) {
        $when = date('Y-m-d H:i:s', strtotime($snap['created_at']));
        $who  = $snap['imported_by'] ?: 'automatic';
        $tag  = $i === 0 ? ' [most recent]' : ($i === count($history) - 1 && count($history) > 1 ? ' [original import]' : '');

        echo "\n{$when}{$tag}\n";
        echo "  source: {$snap['source']}   imported by: {$who}   lookups: {$snap['lookup_count']}\n";
        echo "  {$snap['spf_record']}\n";

        $mech = $snap['mechanisms_parsed'];
        $bits = [];
        foreach (['includes' => 'include', 'ip4' => 'ip4', 'ip6' => 'ip6'] as $k => $label) {
            if (!empty($mech[$k])) {
                $bits[] = count($mech[$k]) . " {$label}";
            }
        }
        if (!empty($bits)) {
            echo '  mechanisms: ' . implode(', ', $bits) . "\n";
        }
    }

    echo "\n" . str_repeat('=', 78) . "\n";
}

function cmdUserAdd($options) {
    $auth = new Auth();

    $username = $options['username'] ?? null;
    if (!$username) {
        echo "Error: --username is required\n";
        echo "Usage: php cli.php user:add --username=admin [--role=admin] [--email=a@b.c]\n";
        exit(1);
    }

    $role = $options['role'] ?? 'admin';
    $email = $options['email'] ?? null;
    $name = $options['name'] ?? null;

    // Prefer --password, otherwise prompt without echoing.
    if (!empty($options['password'])) {
        $password = $options['password'];
        $confirm = $password;
    } else {
        echo "Password for '{$username}': ";
        $password = readPassword();
        echo "\nConfirm password: ";
        $confirm = readPassword();
        echo "\n";
    }

    if ($password !== $confirm) {
        echo "Error: passwords do not match\n";
        exit(1);
    }

    $result = $auth->createUser($username, $password, $role, $email, $name);

    if ($result['success']) {
        echo "✓ Created user '{$username}' with role '{$role}'\n";
    } else {
        echo "✗ {$result['error']}\n";
        exit(1);
    }
}

function cmdUserList() {
    $auth = new Auth();
    $users = $auth->listUsers();

    if (empty($users)) {
        echo "No users configured. Create one with:\n";
        echo "  php cli.php user:add --username=admin --role=admin\n";
        return;
    }

    echo "\nUser Accounts:\n";
    echo str_repeat('=', 88) . "\n";
    printf("%-20s %-12s %-9s %-17s %-15s\n", "Username", "Role", "Status", "Last Login", "Last IP");
    echo str_repeat('-', 88) . "\n";

    foreach ($users as $u) {
        printf("%-20s %-12s %-9s %-17s %-15s\n",
            substr($u['username'], 0, 19),
            $u['role'],
            $u['is_active'] ? 'active' : 'disabled',
            $u['last_login_at'] ? date('Y-m-d H:i', strtotime($u['last_login_at'])) : 'never',
            $u['last_login_ip'] ?: '—'
        );
    }
    echo str_repeat('=', 88) . "\n";
}

function cmdUserPasswd($options) {
    $auth = new Auth();

    $username = $options['username'] ?? null;
    if (!$username) {
        echo "Error: --username is required\n";
        exit(1);
    }

    $stmt = getDB()->prepare("SELECT id FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $userId = $stmt->fetchColumn();

    if (!$userId) {
        echo "Error: user '{$username}' not found\n";
        exit(1);
    }

    if (!empty($options['password'])) {
        $password = $options['password'];
        $confirm = $password;
    } else {
        echo "New password for '{$username}': ";
        $password = readPassword();
        echo "\nConfirm password: ";
        $confirm = readPassword();
        echo "\n";
    }

    if ($password !== $confirm) {
        echo "Error: passwords do not match\n";
        exit(1);
    }

    $result = $auth->changePassword($userId, $password, null);

    if ($result['success']) {
        echo "✓ Password updated for '{$username}'\n";
    } else {
        echo "✗ {$result['error']}\n";
        exit(1);
    }
}

function cmdAudit($options) {
    $auth = new Auth();
    $limit = isset($options['id']) ? (int) $options['id'] : 40;
    $entries = $auth->listAuditLog($limit, 0);

    if (empty($entries)) {
        echo "No audit entries.\n";
        return;
    }

    echo "\nAudit Log (most recent {$limit}):\n";
    echo str_repeat('=', 110) . "\n";
    printf("%-20s %-16s %-22s %-18s %s\n", "Date/Time", "User", "Action", "IP", "Detail");
    echo str_repeat('-', 110) . "\n";

    foreach ($entries as $e) {
        printf("%-20s %-16s %-22s %-18s %s\n",
            date('Y-m-d H:i:s', strtotime($e['created_at'])),
            substr($e['username'] ?? '—', 0, 15),
            substr($e['action'], 0, 21),
            substr($e['ip_address'] ?? '—', 0, 17),
            substr(preg_replace('/\s+/', ' ', $e['detail'] ?? ''), 0, 44)
        );
    }
    echo str_repeat('=', 110) . "\n";
}

/**
 * Read a password from the terminal without echoing it.
 */
function readPassword() {
    if (!function_exists('shell_exec') || stripos(PHP_OS, 'WIN') === 0) {
        // Fall back to a visible read on platforms without stty.
        return trim(fgets(STDIN));
    }
    shell_exec('stty -echo');
    $password = trim(fgets(STDIN));
    shell_exec('stty echo');
    return $password;
}

function showHelp() {
    echo "\n";
    echo "SPF Flattener CLI\n";
    echo str_repeat('=', 50) . "\n\n";
    echo "Usage:\n";
    echo "  php cli.php <command> [options]\n\n";
    echo "Commands:\n";
    echo "  flatten      Flatten SPF record for a domain\n";
    echo "  check        Check for SPF changes\n";
    echo "  list         List all configured domains\n";
    echo "  import       Import SPF record from DNS\n";
    echo "  records      Show stored original SPF records\n";
    echo "  dns-test     Test DNS lookup (debug)\n";
    echo "  config       View or set application configuration\n";
    echo "  user:add     Create a user account\n";
    echo "  user:list    List user accounts\n";
    echo "  user:passwd  Change a user's password\n";
    echo "  audit        Show recent audit log entries\n";
    echo "  help         Show this help message\n\n";
    echo "Options:\n";
    echo "  --domain=DOMAIN    Target domain (required for flatten/check/import)\n";
    echo "  --add              Add domain if not found (for import command)\n";
    echo "  --force            Force update even if no changes\n";
    echo "  --no-email         Don't send notification emails\n";
    echo "  --set KEY=VALUE    Set configuration value\n";
    echo "  --username=NAME    Username (user:add, user:passwd)\n";
    echo "  --password=PASS    Password (omit to be prompted securely)\n";
    echo "  --role=ROLE        admin | operator | viewer  (user:add)\n";
    echo "  --email=ADDR       Email address (user:add)\n";
    echo "  --name=NAME        Display name (user:add)\n";
    echo "  --id=N             Number of audit rows to show\n\n";
    echo "Examples:\n";
    echo "  php cli.php user:add --username=admin --role=admin\n";
    echo "  php cli.php user:list\n";
    echo "  php cli.php user:passwd --username=admin\n";
    echo "  php cli.php audit --id=50\n";
    echo "  php cli.php list\n";
    echo "  php cli.php flatten --domain=example.com\n";
    echo "  php cli.php check --domain=example.com\n";
    echo "  php cli.php import --domain=example.com\n";
    echo "  php cli.php import --domain=newdomain.com --add\n";
    echo "  php cli.php dns-test --domain=google.com\n";
    echo "  php cli.php config --set cloudflare_api_token=your-token-here\n\n";
    echo str_repeat('=', 50) . "\n";
}
