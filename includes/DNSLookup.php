<?php
/**
 * DNS Lookup Utility
 *
 * Fetches and parses TXT/SPF records for the import workflow.
 */

require_once __DIR__ . '/Security.php';

class DNSLookup {
    private $db;

    public function __construct() {
        $this->db = getDB();
    }

    /* ========================================================
     * Queries
     * ====================================================== */

    /**
     * Get all TXT records for a domain.
     *
     * @param string $domain
     * @return array List of TXT record strings
     */
    public function getTXTRecords($domain) {
        $sanitized = sanitizeDomainForShell($domain);
        if ($sanitized === false) {
            error_log("Invalid domain format: {$domain}");
            return [];
        }

        $cached = $this->getFromCache($domain, 'TXT');
        if ($cached !== null) {
            $decoded = json_decode($cached, true);
            if (is_array($decoded)) {
                return $decoded;
            }
        }

        $records = [];

        $output = shell_exec("dig +short TXT {$sanitized} 2>/dev/null");
        if (!$output) {
            $output = shell_exec("nslookup -q=TXT {$sanitized} 2>/dev/null");
        }

        if ($output) {
            foreach (preg_split('/\r?\n/', trim($output)) as $line) {
                $line = trim($line);
                if ($line === '') {
                    continue;
                }

                // A TXT record can be split across several quoted chunks;
                // concatenating them reconstructs the real string.
                if (preg_match_all('/"([^"]*)"/', $line, $chunks) && !empty($chunks[1])) {
                    $records[] = implode('', $chunks[1]);
                } else {
                    // Unquoted fallback (nslookup output style).
                    $clean = trim(str_replace(['TXT', '"', "'"], '', $line));
                    if ($clean !== '') {
                        $records[] = $clean;
                    }
                }
            }
        }

        $records = array_values(array_unique($records));

        if (!empty($records)) {
            $this->saveToCache($domain, 'TXT', json_encode($records));
        }

        return $records;
    }

    /**
     * Find the SPF record (v=spf1 …) among a domain's TXT records.
     *
     * @return string The SPF record, or '' when none is published
     */
    public function getSPFRecord($domain) {
        foreach ($this->getTXTRecords($domain) as $record) {
            if (stripos(trim($record), 'v=spf1') === 0) {
                return trim($record);
            }
        }
        return '';
    }

    /* ========================================================
     * Parsing
     * ====================================================== */

    /**
     * Parse an SPF record into its component mechanisms.
     */
    public function parseSPFRecord($spfRecord) {
        $mechanisms = [
            'includes'   => [],
            'a_records'  => [],
            'mx_records' => [],
            'ip4'        => [],
            'ip6'        => [],
            'ptr'        => [],
            'exists'     => [],
            'redirect'   => '',
            'all'        => '~all',
        ];

        if (empty($spfRecord)) {
            return $mechanisms;
        }

        $parts = preg_split('/\s+/', trim($spfRecord));
        array_shift($parts); // drop "v=spf1"

        foreach ($parts as $part) {
            $part = trim($part);
            if ($part === '') {
                continue;
            }

            // Strip an optional qualifier (+ - ~ ?) before matching.
            $bare = preg_replace('/^[+\-~?]/', '', $part);

            if (preg_match('/^include:(.+)$/i', $bare, $m)) {
                $mechanisms['includes'][] = trim($m[1]);
            } elseif (preg_match('/^ip4:(.+)$/i', $bare, $m)) {
                $mechanisms['ip4'][] = trim($m[1]);
            } elseif (preg_match('/^ip6:(.+)$/i', $bare, $m)) {
                $mechanisms['ip6'][] = trim($m[1]);
            } elseif (preg_match('/^a:(.+)$/i', $bare, $m)) {
                $mechanisms['a_records'][] = trim($m[1]);
            } elseif (preg_match('/^mx:(.+)$/i', $bare, $m)) {
                $mechanisms['mx_records'][] = trim($m[1]);
            } elseif (preg_match('/^a$/i', $bare)) {
                $mechanisms['a_records'][] = 'a';
            } elseif (preg_match('/^mx$/i', $bare)) {
                $mechanisms['mx_records'][] = 'mx';
            } elseif (preg_match('/^ptr(:.+)?$/i', $bare)) {
                $mechanisms['ptr'][] = $bare;
            } elseif (preg_match('/^exists:(.+)$/i', $bare, $m)) {
                $mechanisms['exists'][] = trim($m[1]);
            } elseif (preg_match('/^redirect=(.+)$/i', $bare, $m)) {
                $mechanisms['redirect'] = trim($m[1]);
            } elseif (preg_match('/^all$/i', $bare)) {
                $mechanisms['all'] = $part;
            }
        }

        return $mechanisms;
    }

    /**
     * Count DNS-lookup mechanisms in an SPF record (RFC 7208 §4.6.4).
     */
    public function countLookups($spfRecord) {
        if (empty($spfRecord)) {
            return 0;
        }

        $count = 0;
        foreach (preg_split('/\s+/', $spfRecord) as $part) {
            $bare = preg_replace('/^[+\-~?]/', '', trim($part));
            if (preg_match('/^(include:|a$|a:|mx$|mx:|ptr$|ptr:|exists:|redirect=)/i', $bare)) {
                $count++;
            }
        }
        return $count;
    }

    /* ========================================================
     * Import
     * ====================================================== */

    /**
     * Import a domain's live SPF record into the database.
     *
     * Creates the sending-domain row and one approved-sender row per
     * include: mechanism AND per direct ip4:/ip6: entry, so the flattener
     * reproduces the original authorisation set exactly.
     *
     * @param int $domainId
     * @return array
     */
    public function importSPFForDomain($domainId) {
        $result = [
            'success'        => false,
            'domain_id'      => $domainId,
            'spf_record'     => '',
            'mechanisms'     => [],
            'includes_found' => 0,
            'senders_added'  => 0,
            'direct_ips'     => ['ip4' => [], 'ip6' => []],
            'has_a_records'  => false,
            'has_mx_records' => false,
            'a_records'      => [],
            'mx_records'     => [],
            'errors'         => [],
        ];

        try {
            $stmt = $this->db->prepare("SELECT domain FROM domains WHERE id = ?");
            $stmt->execute([$domainId]);
            $domain = $stmt->fetchColumn();

            if (!$domain) {
                $result['errors'][] = 'Domain not found.';
                return $result;
            }

            $spfRecord = $this->getSPFRecord($domain);

            if (empty($spfRecord)) {
                $result['errors'][] = "No SPF record found for {$domain}.";
                return $result;
            }

            $result['spf_record'] = $spfRecord;

            $mechanisms = $this->parseSPFRecord($spfRecord);
            $result['mechanisms']     = $mechanisms;
            $result['includes_found'] = count($mechanisms['includes']);
            $result['has_a_records']  = !empty($mechanisms['a_records']);
            $result['has_mx_records'] = !empty($mechanisms['mx_records']);
            $result['a_records']      = $mechanisms['a_records'];
            $result['mx_records']     = $mechanisms['mx_records'];
            $result['direct_ips']     = [
                'ip4' => $mechanisms['ip4'],
                'ip6' => $mechanisms['ip6'],
            ];

            // Persist the original record and its lookup count.
            $stmt = $this->db->prepare("
                UPDATE domains
                   SET original_spf_record = ?,
                       lookup_count_before = ?
                 WHERE id = ?
            ");
            $stmt->execute([$spfRecord, $this->countLookups($spfRecord), $domainId]);

            // Ensure a sending-domain row exists for the apex.
            $stmt = $this->db->prepare("
                INSERT INTO sending_domains (domain_id, sending_domain, is_active)
                VALUES (?, ?, 1)
                ON DUPLICATE KEY UPDATE is_active = 1
            ");
            $stmt->execute([$domainId, $domain]);

            $stmt = $this->db->prepare("
                SELECT id FROM sending_domains WHERE domain_id = ? AND sending_domain = ?
            ");
            $stmt->execute([$domainId, $domain]);
            $sendingDomainId = (int) $stmt->fetchColumn();

            // Existing mechanisms, so repeat imports stay idempotent.
            $stmt = $this->db->prepare("
                SELECT include_domain FROM approved_senders WHERE sending_domain_id = ?
            ");
            $stmt->execute([$sendingDomainId]);
            $existing = $stmt->fetchAll(PDO::FETCH_COLUMN);

            $insert = $this->db->prepare("
                INSERT INTO approved_senders (sending_domain_id, sender_name, include_domain, is_active)
                VALUES (?, ?, ?, 1)
            ");

            $added = 0;

            // include: mechanisms
            foreach ($mechanisms['includes'] as $include) {
                if (in_array($include, $existing, true)) {
                    continue;
                }
                $insert->execute([$sendingDomainId, $this->generateSenderName($include), $include]);
                $existing[] = $include;
                $added++;
            }

            // Direct ip4: / ip6: entries — these are static authorisations
            // and must be carried across so nothing is lost on flattening.
            foreach ($mechanisms['ip4'] as $ip4) {
                $key = 'ip4:' . $ip4;
                if (in_array($key, $existing, true)) {
                    continue;
                }
                $insert->execute([$sendingDomainId, "Direct IPv4: {$ip4}", $key]);
                $existing[] = $key;
                $added++;
            }

            foreach ($mechanisms['ip6'] as $ip6) {
                $key = 'ip6:' . $ip6;
                if (in_array($key, $existing, true)) {
                    continue;
                }
                $insert->execute([$sendingDomainId, "Direct IPv6: {$ip6}", $key]);
                $existing[] = $key;
                $added++;
            }

            // a: / mx: mechanisms are dynamic, so they are recorded for the
            // flattener to resolve at run time rather than being dropped.
            foreach ($mechanisms['a_records'] as $a) {
                $key = ($a === 'a') ? 'a:' . $domain : 'a:' . $a;
                if (in_array($key, $existing, true)) {
                    continue;
                }
                $insert->execute([$sendingDomainId, "A record: {$a}", $key]);
                $existing[] = $key;
                $added++;
            }

            foreach ($mechanisms['mx_records'] as $mx) {
                $key = ($mx === 'mx') ? 'mx:' . $domain : 'mx:' . $mx;
                if (in_array($key, $existing, true)) {
                    continue;
                }
                $insert->execute([$sendingDomainId, "MX record: {$mx}", $key]);
                $existing[] = $key;
                $added++;
            }

            $result['senders_added'] = $added;
            $result['success'] = true;

        } catch (Throwable $e) {
            $result['errors'][] = $e->getMessage();
            error_log('SPF import error: ' . $e->getMessage());
        }

        return $result;
    }

    /**
     * Suggest a readable name for a known sending service.
     */
    private function generateSenderName($includeDomain) {
        $known = [
            '_spf.google.com'             => 'Google Workspace',
            'spf.protection.outlook.com'  => 'Microsoft 365',
            '_spf.microsoft.com'          => 'Microsoft',
            'sendgrid.net'                => 'SendGrid',
            'mailgun.org'                 => 'Mailgun',
            'amazonses.com'               => 'Amazon SES',
            'servers.mcsv.net'            => 'Mailchimp',
            'spf.mandrillapp.com'         => 'Mandrill',
            'spf.zendesk.com'             => 'Zendesk',
            'spf.salesforce.com'          => 'Salesforce',
            'spf.hubspot.com'             => 'HubSpot',
            'sendinblue.com'              => 'Brevo',
            'spf.mailjet.com'             => 'Mailjet',
            'spf.fastmail.com'            => 'Fastmail',
            'spf.protonmail.ch'           => 'Proton Mail',
            '_spf.qq.com'                 => 'QQ Mail',
            'spf.gappssmtp.com'           => 'Google (legacy)',
            'spf-a.outlook.com'           => 'Microsoft 365 (a)',
        ];

        foreach ($known as $needle => $label) {
            if ($includeDomain === $needle) {
                return $label;
            }
        }
        foreach ($known as $needle => $label) {
            if (str_contains($includeDomain, $needle)) {
                return $label;
            }
        }

        $parts = explode('.', $includeDomain);
        $name = ucfirst(preg_replace('/[^a-z0-9]/i', '', $parts[0]));
        return ($name !== '' && strlen($name) > 1) ? $name . " ({$includeDomain})" : $includeDomain;
    }

    /* ========================================================
     * Diagnostics
     * ====================================================== */

    /**
     * Verify that DNS lookups work on this host.
     */
    public function testDNS($domain = 'google.com') {
        $result = [
            'success'    => false,
            'domain'     => $domain,
            'txt_records' => [],
            'spf_record' => '',
            'errors'     => [],
        ];

        if (!isValidDomain($domain)) {
            $result['errors'][] = 'Invalid domain name.';
            return $result;
        }

        if (trim((string) shell_exec('command -v dig 2>/dev/null')) === '') {
            $result['errors'][] = "The 'dig' command was not found. Install dnsutils (Debian/Ubuntu) or bind-utils (RHEL).";
            return $result;
        }

        $records = $this->getTXTRecords($domain);
        $result['txt_records'] = $records;

        if (!empty($records)) {
            $result['spf_record'] = $this->getSPFRecord($domain);
            $result['success'] = true;
        } else {
            $result['errors'][] = 'No TXT records were returned.';
        }

        return $result;
    }

    /* ========================================================
     * Cache
     * ====================================================== */

    private function getFromCache($domain, $type) {
        try {
            $stmt = $this->db->prepare("
                SELECT result_data FROM dns_cache
                 WHERE query_domain = ? AND query_type = ? AND expires_at > NOW()
            ");
            $stmt->execute([$domain, $type]);
            $row = $stmt->fetchColumn();
            return ($row === false || $row === null) ? null : $row;
        } catch (Throwable $e) {
            return null;
        }
    }

    private function saveToCache($domain, $type, $data) {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO dns_cache (query_domain, query_type, result_data, expires_at)
                VALUES (?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE result_data = VALUES(result_data), expires_at = VALUES(expires_at)
            ");
            $stmt->execute([$domain, $type, $data, date('Y-m-d H:i:s', time() + DNS_CACHE_TTL)]);
        } catch (Throwable $e) {
            error_log('DNS cache save error: ' . $e->getMessage());
        }
    }
}
