#!/usr/bin/env php
<?php
/**
 * SPF Flattener - Automated Cron Job
 * 
 * Replicates cfspflat's automated update functionality
 * Run this script via cron to check for SPF changes and update automatically
 * 
 * Usage:
 *   php /path/to/spf-flattener/cron/auto-update.php [--no-email] [--force]
 */

// Change to script directory
chdir(__DIR__ . '/..');

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/Database.php';
require_once __DIR__ . '/../includes/SPFFlattener.php';
require_once __DIR__ . '/../includes/CloudflareAPI.php';
require_once __DIR__ . '/../includes/EmailNotifier.php';

// Parse command line options
$options = getopt('', ['no-email', 'force']);
$noEmail = isset($options['no-email']);
$forceUpdate = isset($options['force']);

$db = getDB();
$flattener = new SPFFlattener();
$notifier = new EmailNotifier();

echo "=== SPF Flattener Auto-Update ===\n";
echo "Started at: " . date('Y-m-d H:i:s') . "\n\n";

// Get all active domains
$stmt = $db->query("SELECT * FROM domains WHERE is_active = 1");
$domains = $stmt->fetchAll();

if (empty($domains)) {
    echo "No active domains configured.\n";
    exit(0);
}

echo "Processing " . count($domains) . " domain(s)...\n\n";

$processed = 0;
$updated = 0;
$errors = 0;

foreach ($domains as $domain) {
    echo "Domain: {$domain['domain']}\n";
    echo str_repeat('-', 50) . "\n";
    
    try {
        // Check for changes
        $changes = $flattener->detectChanges($domain['id']);
        
        if ($changes['has_changes'] || $forceUpdate) {
            echo "  Changes detected!\n";
            
            if (!empty($changes['ips_added'])) {
                echo "  IPs added: " . count($changes['ips_added']) . "\n";
                foreach ($changes['ips_added'] as $ip) {
                    echo "    + {$ip}\n";
                }
            }
            
            if (!empty($changes['ips_removed'])) {
                echo "  IPs removed: " . count($changes['ips_removed']) . "\n";
                foreach ($changes['ips_removed'] as $ip) {
                    echo "    - {$ip}\n";
                }
            }
            
            // Re-flatten the domain
            $result = $flattener->flattenDomain($domain['id']);
            
            if ($result['success']) {
                echo "  New flattened record: {$result['flattened_record']}\n";
                
                // Update Cloudflare if configured
                if (AUTO_UPDATE_ENABLED && !empty($domain['cloudflare_zone_id'])) {
                    try {
                        $cfApi = new CloudflareAPI();
                        $cfApi->updateDomainSPF($domain['domain'], $result['flattened_record']);
                        echo "  ✓ Cloudflare DNS updated\n";
                        
                        // Log the update
                        $logStmt = $db->prepare("
                            INSERT INTO change_log (domain_id, change_type, old_record, new_record, ips_added, ips_removed, cloudflare_updated)
                            VALUES (?, 'UPDATE', ?, ?, ?, ?, 1)
                        ");
                        $logStmt->execute([
                            $domain['id'],
                            $domain['flattened_spf_record'],
                            $result['flattened_record'],
                            count($changes['ips_added']),
                            count($changes['ips_removed'])
                        ]);
                        
                        // Send notification email
                        if (!$noEmail && ENABLE_EMAIL_NOTIFICATIONS) {
                            $notifier->sendUpdateNotification(
                                $domain['domain'],
                                $result['flattened_record'],
                                count($result['ips_collected'])
                            );
                            echo "  ✓ Notification email queued\n";
                        }
                        
                        $updated++;
                    } catch (Exception $cfError) {
                        echo "  ✗ Cloudflare update failed: {$cfError->getMessage()}\n";
                        $errors++;
                    }
                } else {
                    echo "  ⚠ Auto-update disabled or Cloudflare not configured\n";
                    echo "  Manual update required\n";
                    
                    // Log for manual review
                    $logStmt = $db->prepare("
                        INSERT INTO change_log (domain_id, change_type, old_record, new_record, ips_added, ips_removed, email_sent)
                        VALUES (?, 'UPDATE', ?, ?, ?, ?, ?)
                    ");
                    $logStmt->execute([
                        $domain['id'],
                        $domain['flattened_spf_record'],
                        $result['flattened_record'],
                        count($changes['ips_added']),
                        count($changes['ips_removed']),
                        !$noEmail ? 1 : 0
                    ]);
                    
                    // Send notification
                    if (!$noEmail && ENABLE_EMAIL_NOTIFICATIONS) {
                        $notifier->sendChangeNotification(
                            $domain['domain'],
                            $changes,
                            $result['flattened_record']
                        );
                        echo "  ✓ Change notification email queued\n";
                    }
                }
            } else {
                echo "  ✗ Flattening failed: " . implode(', ', $result['errors']) . "\n";
                $errors++;
            }
        } else {
            echo "  No changes detected\n";
            
            // Update last verified timestamp
            $stmt = $db->prepare("UPDATE flattened_ips SET last_verified = NOW() WHERE domain_id = ?");
            $stmt->execute([$domain['id']]);
        }
        
        $processed++;
        echo "\n";
        
    } catch (Exception $e) {
        echo "  ✗ Error: {$e->getMessage()}\n\n";
        $errors++;
    }
}

// Process email queue
if (ENABLE_EMAIL_NOTIFICATIONS && !$noEmail) {
    echo "Processing email queue...\n";
    $emailResult = $notifier->processQueue();
    echo "  Emails sent: {$emailResult['sent']}, Failed: {$emailResult['failed']}\n";
}

// Update last run timestamp
$db->exec("UPDATE config SET config_value = NOW() WHERE config_key = 'last_flatten_run'");

echo "\n=== Summary ===\n";
echo "Completed at: " . date('Y-m-d H:i:s') . "\n";
echo "Domains processed: {$processed}\n";
echo "Domains updated: {$updated}\n";
echo "Errors: {$errors}\n";

exit($errors > 0 ? 1 : 0);
