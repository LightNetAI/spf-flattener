<?php
/**
 * SPF Flattener Core Class
 *
 * Replicates the functionality of cfspflat / sender-policy-flattener:
 * resolves include: chains down to concrete ip4:/ip6: entries, counts
 * DNS lookups per RFC 7208, and stores both the flattened record and the
 * individual addresses it was built from.
 */

require_once __DIR__ . '/Security.php';
require_once __DIR__ . '/IPUtil.php';

class SPFFlattener {
    private $db;
    private $lookupCount = 0;
    private $maxLookups = MAX_DNS_LOOKUPS;

    public function __construct() {
        $this->db = getDB();
    }

    /* ========================================================
     * Public API
     * ====================================================== */

    /**
     * Flatten the SPF record for a domain.
     *
     * @param int $domainId
     * @return array Result with the flattened record and statistics
     */
    public function flattenDomain($domainId) {
        $result = [
            'success'             => false,
            'domain_id'           => $domainId,
            'original_record'     => '',
            'flattened_record'    => '',
            'lookup_count_before' => 0,
            'lookup_count_after'  => 0,
            'ips_collected'       => [],
            'errors'              => [],
            'warnings'            => [],
        ];

        try {
            $stmt = $this->db->prepare("SELECT * FROM domains WHERE id = ?");
            $stmt->execute([$domainId]);
            $domain = $stmt->fetch();

            if (!$domain) {
                $result['errors'][] = 'Domain not found.';
                return $result;
            }

            // Sending domains configured for this zone.
            $stmt = $this->db->prepare("
                SELECT * FROM sending_domains
                 WHERE domain_id = ? AND is_active = 1
            ");
            $stmt->execute([$domainId]);
            $sendingDomains = $stmt->fetchAll();

            if (empty($sendingDomains)) {
                $result['errors'][] = 'No active sending domains configured.';
                return $result;
            }

            $allIps             = [];
            $totalLookupsBefore = 0;
            $senderCount        = 0;

            foreach ($sendingDomains as $sendingDomain) {
                // Count the lookups in the live record for this sending domain.
                $originalRecord = $this->getSPFRecordFromDns($sendingDomain['sending_domain']);
                $totalLookupsBefore += $this->countLookups($originalRecord);

                $stmt = $this->db->prepare("
                    SELECT * FROM approved_senders
                     WHERE sending_domain_id = ? AND is_active = 1
                ");
                $stmt->execute([$sendingDomain['id']]);
                $senders = $stmt->fetchAll();

                foreach ($senders as $sender) {
                    $senderCount++;
                    $ips = $this->resolveMechanism($sender['include_domain']);

                    if (empty($ips)) {
                        $result['warnings'][] = "No addresses resolved for '{$sender['include_domain']}'.";
                    }

                    foreach ($ips as $ipData) {
                        // $ipData is ['ip' => string, 'version' => '4'|'6']
                        $allIps[] = [
                            'ip'      => $ipData['ip'],
                            'version' => $ipData['version'],
                            'source'  => $sender['sender_name'],
                            'include' => $sender['include_domain'],
                        ];
                    }
                }
            }

            if ($senderCount === 0) {
                $result['errors'][] = 'No approved senders configured for this domain.';
                return $result;
            }

            $uniqueIps = $this->deduplicateIps($allIps);
            $result['ips_collected'] = $uniqueIps;

            if (empty($uniqueIps)) {
                $result['errors'][] = 'No IP addresses could be resolved from the configured senders.';
                return $result;
            }

            // ---- Build the record -------------------------------------
            // RFC 7208 limits a single TXT record to 255 characters, which
            // is far too small to hold every address. Like cfspflat, we
            // emit the root record plus a chain of sub-records so the
            // entire set can be published.
            $recordSet = $this->buildRecordSet(
                $uniqueIps,
                $domain['domain'],
                $domain['cloudflare_zone_name'] ?? '',
                $result['warnings']
            );

            $result['success']             = true;
            $result['original_record']     = $domain['original_spf_record'] ?? '';
            $result['flattened_record']    = $recordSet['root'];
            $result['record_set']          = $recordSet;
            $result['lookup_count_before'] = $totalLookupsBefore;
            $result['lookup_count_after']  = $recordSet['lookups'];

            $this->saveFlatteningResult($domainId, $recordSet['root'], count($uniqueIps));
            $this->storeFlattenedIps($domainId, $uniqueIps);
            $this->storeRecordChain($domainId, $recordSet['records']);

        } catch (Throwable $e) {
            $result['errors'][] = $e->getMessage();
            error_log('SPF flattening error: ' . $e->getMessage());
        }

        return $result;
    }

    /**
     * Detect whether the resolved IP set differs from what is stored.
     * Does not mutate the stored record.
     */
    public function detectChanges($domainId) {
        $changes = ['ips_added' => [], 'ips_removed' => [], 'has_changes' => false];

        // Currently stored addresses (ip => version).
        $stmt = $this->db->prepare("
            SELECT ip_address FROM flattened_ips
             WHERE domain_id = ? AND is_active = 1
        ");
        $stmt->execute([$domainId]);
        $stored = array_flip($stmt->fetchAll(PDO::FETCH_COLUMN));

        // Resolve fresh, without writing anything.
        $fresh = [];
        foreach ($this->resolveDomainSenders($domainId) as $ipData) {
            $fresh[$ipData['ip']] = true;
        }

        foreach (array_keys($fresh) as $ip) {
            if (!isset($stored[$ip])) {
                $changes['ips_added'][] = $ip;
                $changes['has_changes'] = true;
            }
        }
        foreach (array_keys($stored) as $ip) {
            if (!isset($fresh[$ip])) {
                $changes['ips_removed'][] = $ip;
                $changes['has_changes'] = true;
            }
        }

        return $changes;
    }

    /* ========================================================
     * Resolution
     * ====================================================== */

    /**
     * Resolve every approved sender of a domain to IP records
     * without persisting anything.
     *
     * @return array List of ['ip' => string, 'version' => '4'|'6']
     */
    private function resolveDomainSenders($domainId) {
        $stmt = $this->db->prepare("
            SELECT asp.include_domain
              FROM approved_senders asp
              JOIN sending_domains sd ON asp.sending_domain_id = sd.id
             WHERE sd.domain_id = ? AND sd.is_active = 1 AND asp.is_active = 1
        ");
        $stmt->execute([$domainId]);

        $ips = [];
        foreach ($stmt->fetchAll(PDO::FETCH_COLUMN) as $includeDomain) {
            foreach ($this->resolveMechanism($includeDomain) as $ipData) {
                $ips[] = $ipData;
            }
        }
        return $ips;
    }

    /**
     * Resolve a single configured mechanism to IP records.
     * Accepts a bare domain (include:), an "ip4:"/"ip6:" literal, or a
     * "a:"/"mx:" qualifier.
     *
     * @param string $mechanism
     * @param int    $depth
     * @return array List of ['ip' => string, 'version' => '4'|'6']
     */
    private function resolveMechanism($mechanism, $depth = 0) {
        $mechanism = trim($mechanism);

        if ($mechanism === '' || $depth > $this->maxLookups) {
            if ($depth > $this->maxLookups) {
                error_log("SPF recursion limit reached at {$mechanism}");
            }
            return [];
        }

        // Direct literal address or network — no lookup required.
        if (preg_match('/^ip4:(.+)$/i', $mechanism, $m)) {
            $net = trim($m[1]);
            return $this->isValidIpv4Network($net) ? [['ip' => $net, 'version' => '4']] : [];
        }
        if (preg_match('/^ip6:(.+)$/i', $mechanism, $m)) {
            $net = trim($m[1]);
            return $this->isValidIpv6Network($net) ? [['ip' => $net, 'version' => '6']] : [];
        }

        // a: / mx: qualifiers.
        if (preg_match('/^a:(.+)$/i', $mechanism, $m)) {
            return $this->getAddressRecords(trim($m[1]));
        }
        if (preg_match('/^mx:(.+)$/i', $mechanism, $m)) {
            return $this->resolveMxHosts(trim($m[1]));
        }

        // Otherwise treat it as an SPF include domain.
        return $this->resolveInclude($mechanism, $depth);
    }

    /**
     * Resolve an include: domain's SPF record recursively.
     */
    private function resolveInclude($includeDomain, $depth = 0) {
        if ($depth > $this->maxLookups) {
            error_log("Max lookup depth reached for {$includeDomain}");
            return [];
        }

        $this->lookupCount++;
        $ips = [];

        $spfRecord = $this->getSPFRecordFromDns($includeDomain);

        // No SPF record published: fall back to the host's A/AAAA records.
        if (empty($spfRecord)) {
            return $this->getAddressRecords($includeDomain);
        }

        foreach (preg_split('/\s+/', trim($spfRecord)) as $part) {
            if (preg_match('/^ip4:(.+)$/i', $part, $m)) {
                if ($this->isValidIpv4Network($m[1])) {
                    $ips[] = ['ip' => $m[1], 'version' => '4'];
                }
            } elseif (preg_match('/^ip6:(.+)$/i', $part, $m)) {
                if ($this->isValidIpv6Network($m[1])) {
                    $ips[] = ['ip' => $m[1], 'version' => '6'];
                }
            } elseif (preg_match('/^include:(.+)$/i', $part, $m)) {
                // Recursively resolve nested includes.
                foreach ($this->resolveInclude(trim($m[1]), $depth + 1) as $nested) {
                    $ips[] = $nested;
                }
            } elseif (preg_match('/^redirect=(.+)$/i', $part, $m)) {
                foreach ($this->resolveInclude(trim($m[1]), $depth + 1) as $nested) {
                    $ips[] = $nested;
                }
            } elseif (preg_match('/^a(?::(.+))?$/i', $part, $m)) {
                $target = !empty($m[1]) ? $m[1] : $includeDomain;
                foreach ($this->getAddressRecords($target) as $r) {
                    $ips[] = $r;
                }
            } elseif (preg_match('/^mx(?::(.+))?$/i', $part, $m)) {
                $target = !empty($m[1]) ? $m[1] : $includeDomain;
                foreach ($this->resolveMxHosts($target) as $r) {
                    $ips[] = $r;
                }
            }
            // ptr: and exists: are deprecated / cannot be flattened safely
            // to a static list, so they are intentionally ignored.
        }

        return $ips;
    }

    /**
     * Resolve a domain to its A and AAAA records.
     */
    private function getAddressRecords($domain) {
        return array_merge($this->getARecords($domain), $this->getAAAARecords($domain));
    }

    /**
     * Resolve a domain's MX hosts to their addresses.
     */
    private function resolveMxHosts($domain) {
        $ips = [];
        foreach ($this->getMXRecords($domain) as $host) {
            foreach ($this->getAddressRecords($host) as $r) {
                $ips[] = $r;
            }
        }
        return $ips;
    }

    /* ========================================================
     * DNS
     * ====================================================== */

    /**
     * Fetch and cache the SPF record for a domain (cache type 'SPF').
     */
    private function getSPFRecordFromDns($domain) {
        $sanitized = sanitizeDomainForShell($domain);
        if ($sanitized === false) {
            error_log("Invalid domain in getSPFRecordFromDns: {$domain}");
            return '';
        }

        $cached = $this->getFromCache($domain, 'SPF');
        if ($cached !== null) {
            return $cached;
        }

        $output = shell_exec("dig +short TXT {$sanitized} 2>/dev/null");
        $record = '';

        if ($output) {
            // A TXT record may be returned as several quoted chunks which
            // must be concatenated to reconstruct the SPF string.
            foreach (preg_split('/\r?\n/', trim($output)) as $line) {
                $line = trim($line);
                if ($line === '') {
                    continue;
                }
                $candidate = '';
                if (preg_match_all('/"([^"]*)"/', $line, $chunks) && !empty($chunks[1])) {
                    $candidate = implode('', $chunks[1]);
                } else {
                    $candidate = trim($line, '"');
                }
                if (stripos($candidate, 'v=spf1') === 0) {
                    $record = $candidate;
                    break;
                }
            }
        }

        $this->saveToCache($domain, 'SPF', $record);
        return $record;
    }

    private function getARecords($domain) {
        $sanitized = sanitizeDomainForShell($domain);
        if ($sanitized === false) {
            return [];
        }

        $cached = $this->getFromCache($domain, 'A');
        if ($cached !== null) {
            $decoded = json_decode($cached, true);
            if (is_array($decoded)) {
                return $decoded;
            }
        }

        $ips = [];
        $output = shell_exec("dig +short A {$sanitized} 2>/dev/null");
        if ($output) {
            foreach (preg_split('/\r?\n/', trim($output)) as $line) {
                $line = trim($line);
                if ($line !== '' && filter_var($line, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    // dig may return "1.2.3.4." for some zones.
                    $ips[] = ['ip' => rtrim($line, '.'), 'version' => '4'];
                }
            }
        }

        $this->saveToCache($domain, 'A', json_encode($ips));
        return $ips;
    }

    private function getAAAARecords($domain) {
        $sanitized = sanitizeDomainForShell($domain);
        if ($sanitized === false) {
            return [];
        }

        $cached = $this->getFromCache($domain, 'AAAA');
        if ($cached !== null) {
            $decoded = json_decode($cached, true);
            if (is_array($decoded)) {
                return $decoded;
            }
        }

        $ips = [];
        $output = shell_exec("dig +short AAAA {$sanitized} 2>/dev/null");
        if ($output) {
            foreach (preg_split('/\r?\n/', trim($output)) as $line) {
                $line = trim($line);
                if ($line !== '' && filter_var($line, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    $ips[] = ['ip' => $line, 'version' => '6'];
                }
            }
        }

        $this->saveToCache($domain, 'AAAA', json_encode($ips));
        return $ips;
    }

    private function getMXRecords($domain) {
        $sanitized = sanitizeDomainForShell($domain);
        if ($sanitized === false) {
            return [];
        }

        $hosts = [];
        $output = shell_exec("dig +short MX {$sanitized} 2>/dev/null");
        if ($output) {
            foreach (preg_split('/\r?\n/', trim($output)) as $line) {
                $parts = preg_split('/\s+/', trim($line));
                if (count($parts) >= 2) {
                    $hosts[] = rtrim($parts[1], '.');
                }
            }
        }
        return $hosts;
    }

    /* ========================================================
     * Helpers
     * ====================================================== */

    /**
     * Count DNS-lookup mechanisms in an SPF record (RFC 7208 §4.6.4).
     */
    public function countLookups($spfRecord) {
        if (empty($spfRecord)) {
            return 0;
        }

        $count = 0;
        foreach (preg_split('/\s+/', $spfRecord) as $part) {
            if (preg_match('/^(include:|a$|a:|mx$|mx:|ptr$|ptr:|exists:|redirect=)/i', $part)) {
                $count++;
            }
        }
        return $count;
    }

    private function isValidIpv4Network($value) {
        $value = trim($value);
        // Allow bare addresses and CIDR networks.
        if (strpos($value, '/') !== false) {
            [$addr, $bits] = array_pad(explode('/', $value, 2), 2, null);
            return filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false
                && ctype_digit((string) $bits) && (int) $bits >= 0 && (int) $bits <= 32;
        }
        return filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    private function isValidIpv6Network($value) {
        $value = trim($value);
        if (strpos($value, '/') !== false) {
            [$addr, $bits] = array_pad(explode('/', $value, 2), 2, null);
            return filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false
                && ctype_digit((string) $bits) && (int) $bits >= 0 && (int) $bits <= 128;
        }
        return filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }

    private function deduplicateIps($ips) {
        $unique = [];
        $seen   = [];

        foreach ($ips as $ipData) {
            if (empty($ipData['ip']) || !is_string($ipData['ip'])) {
                continue;
            }
            $key = strtolower($ipData['ip']);
            if (!isset($seen[$key])) {
                $seen[$key] = true;
                $unique[] = $ipData;
            }
        }

        return $unique;
    }

    /**
     * Build the record set the way cfspflat does.
     *
     * Records are packed to a byte budget (450 bytes, matching upstream's
     * fit_bytes), each one terminated with -all, and chained forward with
     * include:spf<N+1>.<domain> — the final record carries no include.
     *
     * @param array  $ips      Deduplicated ['ip','version',...] records
     * @param string $domain   Sending domain
     * @param array  $warnings Collected by reference
     * @return array{root:string,records:array,lookups:int,tokens:int}
     */
    private function buildRecordSet($ips, $sendingDomain, $zone, &$warnings) {
        // Collapse addresses to the minimal set of CIDRs, exactly as
        // netaddr.IPSet(...).iter_cidrs() does upstream.
        $tokens = [];
        foreach ($ips as $ipData) {
            $tokens[] = $ipData['ip'];
        }

        $collapsed = IPUtil::collapse($tokens);
        $spfTokens = $collapsed['spf'];

        // Where the chain lives. With a Cloudflare zone configured, records
        // are created under that zone: flattening flattenme.com into
        // the cloudflarezone.com zone yields
        // spf0.flattenme.com.cloudflarezone.com and so on.
        $base = $sendingDomain;
        if ($zone !== null && $zone !== '') {
            $base = $sendingDomain . '.' . $zone;
        }

        if (empty($spfTokens)) {
            $anchor = "v=spf1 include:spf0.{$base} -all";
            return [
                'root' => $anchor, 'records' => [], 'anchor' => $anchor,
                'lookups' => 0, 'tokens' => 0, 'base' => $base,
            ];
        }

        // Pack into records that stay within the character limit. The bound is
        // exclusive: no record may reach SPF_CHAR_LIMIT characters.
        $maxLen = defined('SPF_MAX_RECORD_LEN')
            ? SPF_MAX_RECORD_LEN
            : ((defined('SPF_CHAR_LIMIT') ? SPF_CHAR_LIMIT : 254) - 1);
        $blocks = $this->fitRecords($spfTokens, $base, $maxLen);

        $records = [];
        $lastIndex = count($blocks) - 1;

        foreach ($blocks as $i => $block) {
            $body = implode(' ', $block);
            if ($i === $lastIndex) {
                $record = "v=spf1 {$body} -all";
            } else {
                // Chain forward: spf0 -> spf1 -> spf2 …
                $record = 'v=spf1 ' . $body . ' include:spf' . ($i + 1) . ".{$base} -all";
            }
            $records[] = [
                'name'    => "spf{$i}.{$base}",
                'content' => $record,
            ];
        }

        // The apex anchor points at the first record in the chain. It is stored
        // first so it heads the set, and it is what the sending domain itself
        // publishes: v=spf1 include:spf0.example.com.zone -all
        $anchor = "v=spf1 include:spf0.{$base} -all";
        array_unshift($records, [
            'name'    => $sendingDomain,
            'content' => $anchor,
            'anchor'  => true,
        ]);

        // The root record is the anchor's target — the first link in the chain.
        $root = $anchor;

        // Every record must be strictly shorter than the limit. Anything at or
        // over it has to be published as several quoted strings instead.
        foreach ($records as $rec) {
            if (strlen($rec['content']) >= $maxLen) {
                $warnings[] = "Record {$rec['name']} is " . strlen($rec['content'])
                            . " characters, not under the {$maxLen}-character limit; "
                            . 'publish it as multiple quoted strings (BIND format).';
                break;
            }
        }

        return [
            'root'    => $root,
            'records' => $records,
            'lookups' => count($records),
            'tokens'  => count($spfTokens),
            'base'    => $base,
            'anchor'  => $anchor,
        ];
    }

    /**
     * Render a record as quoted strings, the format used in zone files and by
     * providers that expect the multi-string form.
     *
     * Mirrors sender_policy_flattener's format_rrecord_value_for_bind().
     *
     * @return string
     */
    public function formatForBind($record) {
        $tokens = preg_split('/\s+/', trim($record));
        $out = '( ';
        $line = '';
        $count = 0;

        foreach ($tokens as $token) {
            $line .= $token . ' ';
            $count++;
            if ($count === 4) {
                $out .= '"' . $line . '" ';
                $line = '';
                $count = 0;
            }
        }
        if ($line !== '') {
            $out .= '"' . $line . '"';
        }
        $out = rtrim($out) . ' )';

        return $out;
    }

    /**
     * Pack SPF tokens into records within the character limit.
     *
     * Room is reserved for the record's own include:spf<N>.<base> link, so a
     * record cannot overflow once its chain reference is appended.
     *
     * @param array  $tokens Address tokens in preference order
     * @param string $base   The chain's suffix
     * @param int    $limit  Character limit per record
     * @return array List of blocks, each a list of tokens
     */
    private function fitRecords(array $tokens, $base, $limit) {
        // Worst-case chain reference, so no block overflows.
        $overhead = strlen('v=spf1') + strlen(' include:spf99.' . $base . ' -all');

        $blocks  = [];
        $current = [];
        $used    = $overhead;

        foreach (array_values($tokens) as $token) {
            $cost = strlen($token) + 1; // one leading space

            if (!empty($current) && ($used + $cost) > $limit) {
                $blocks[] = $current;
                $current = [];
                $used = $overhead;
            }

            // A single token larger than the limit cannot be split further;
            // keep it and let the caller warn rather than silently dropping it.
            $current[] = $token;
            $used += $cost;
        }

        if (!empty($current)) {
            $blocks[] = $current;
        }

        return $blocks;
    }

    /* ========================================================
     * Persistence
     * ====================================================== */

    /**
     * Persist the whole generated record chain.
     *
     * All records must be stored: spf0 references spf1, so publishing or
     * displaying only the first one leaves the zone broken.
     */
    private function storeRecordChain($domainId, array $records) {
        if (empty($records)) {
            return;
        }

        // Supersede the previous set rather than deleting it, so a partly
        // published chain can still be inspected afterwards.
        $stmt = $this->db->prepare("UPDATE flattened_records SET is_active = 0 WHERE domain_id = ?");
        $stmt->execute([$domainId]);

        $stmt = $this->db->prepare("
            INSERT INTO flattened_records
                (domain_id, seq, record_name, content, char_length, is_last, is_active)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            ON DUPLICATE KEY UPDATE
                content = VALUES(content),
                char_length = VALUES(char_length),
                is_last = VALUES(is_last),
                is_active = 1
        ");

        $last = count($records) - 1;
        foreach (array_values($records) as $i => $rec) {
            $stmt->execute([
                $domainId,
                $i,
                $rec['name'],
                $rec['content'],
                strlen($rec['content']),
                $i === $last ? 1 : 0,
            ]);
        }
    }

    /**
     * The stored chain for a domain, in order.
     */
    public function getRecordChain($domainId) {
        $stmt = $this->db->prepare("
            SELECT * FROM flattened_records
             WHERE domain_id = ? AND is_active = 1
             ORDER BY seq
        ");
        $stmt->execute([$domainId]);
        return $stmt->fetchAll();
    }

    /**
     * Mark every record in a domain's chain as published.
     */
    public function markChainPublished($domainId) {
        $stmt = $this->db->prepare("
            UPDATE flattened_records SET published_at = NOW()
             WHERE domain_id = ? AND is_active = 1
        ");
        $stmt->execute([$domainId]);
    }

    private function saveFlatteningResult($domainId, $flattenedRecord, $ipCount) {
        $stmt = $this->db->prepare("
            UPDATE domains
               SET flattened_spf_record = ?,
                   lookup_count_after   = ?,
                   last_flattened_at    = NOW(),
                   last_updated_at      = NOW()
             WHERE id = ?
        ");
        $stmt->execute([$flattenedRecord, 0, $domainId]);
    }

    private function storeFlattenedIps($domainId, $ips) {
        // Mark everything stale, then reactivate/insert the current set.
        $stmt = $this->db->prepare("UPDATE flattened_ips SET is_active = 0 WHERE domain_id = ?");
        $stmt->execute([$domainId]);

        $stmt = $this->db->prepare("
            INSERT INTO flattened_ips (domain_id, ip_address, ip_version, source_include, is_active)
            VALUES (?, ?, ?, ?, 1)
            ON DUPLICATE KEY UPDATE is_active = 1, last_verified = NOW(), source_include = VALUES(source_include)
        ");

        foreach ($ips as $ipData) {
            $stmt->execute([
                $domainId,
                $ipData['ip'],
                $ipData['version'],
                $ipData['source'] ?? $ipData['include'] ?? 'direct',
            ]);
        }
    }

    /* ========================================================
     * Cache
     * ====================================================== */

    private function getFromCache($domain, $type) {
        $stmt = $this->db->prepare("
            SELECT result_data FROM dns_cache
             WHERE query_domain = ? AND query_type = ? AND expires_at > NOW()
        ");
        $stmt->execute([$domain, $type]);
        $result = $stmt->fetchColumn();
        return ($result === false || $result === null) ? null : $result;
    }

    private function saveToCache($domain, $type, $data) {
        $stmt = $this->db->prepare("
            INSERT INTO dns_cache (query_domain, query_type, result_data, expires_at)
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE result_data = VALUES(result_data), expires_at = VALUES(expires_at)
        ");
        $stmt->execute([$domain, $type, $data, date('Y-m-d H:i:s', time() + DNS_CACHE_TTL)]);
    }
}
