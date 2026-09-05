<?php
/**
 * SPF Flattener Core Class
 * 
 * Replicates the functionality of cfspflat/sender-policy-flattener
 * Handles SPF record parsing, DNS resolution, and IP flattening
 */

class SPFFlattener {
    private $db;
    private $dnsCache = [];
    private $lookupCount = 0;
    private $maxLookups = MAX_DNS_LOOKUPS;
    
    public function __construct() {
        $this->db = getDB();
    }
    
    /**
     * Flatten SPF record for a domain
     * 
     * @param int $domainId Domain ID from database
     * @return array Result with flattened record and statistics
     */
    public function flattenDomain($domainId) {
        $result = [
            'success' => false,
            'domain_id' => $domainId,
            'original_record' => '',
            'flattened_record' => '',
            'lookup_count_before' => 0,
            'lookup_count_after' => 0,
            'ips_collected' => [],
            'errors' => [],
            'warnings' => []
        ];
        
        try {
            // Get domain info
            $stmt = $this->db->prepare("SELECT * FROM domains WHERE id = ?");
            $stmt->execute([$domainId]);
            $domain = $stmt->fetch();
            
            if (!$domain) {
                $result['errors'][] = "Domain not found";
                return $result;
            }
            
            // Get sending domains and approved senders
            $stmt = $this->db->prepare("
                SELECT sd.*, d.domain as parent_domain 
                FROM sending_domains sd 
                JOIN domains d ON sd.domain_id = d.id 
                WHERE sd.domain_id = ? AND sd.is_active = 1
            ");
            $stmt->execute([$domainId]);
            $sendingDomains = $stmt->fetchAll();
            
            if (empty($sendingDomains)) {
                $result['errors'][] = "No active sending domains configured";
                return $result;
            }
            
            $allIps = [];
            $totalLookupsBefore = 0;
            
            foreach ($sendingDomains as $sendingDomain) {
                // Get approved senders for this sending domain
                $stmt = $this->db->prepare("
                    SELECT * FROM approved_senders 
                    WHERE sending_domain_id = ? AND is_active = 1
                ");
                $stmt->execute([$sendingDomain['id']]);
                $senders = $stmt->fetchAll();
                
                // Get original SPF record
                $originalRecord = $this->getOriginalSPF($sendingDomain['sending_domain']);
                $totalLookupsBefore += $this->countLookups($originalRecord);
                
                // Collect IPs from each sender
                foreach ($senders as $sender) {
                    $ips = $this->resolveInclude($sender['include_domain']);
                    foreach ($ips as $ip) {
                        $allIps[] = [
                            'ip' => $ip,
                            'source' => $sender['sender_name'],
                            'include' => $sender['include_domain']
                        ];
                    }
                }
            }
            
            // Deduplicate IPs
            $uniqueIps = $this->deduplicateIps($allIps);
            $result['ips_collected'] = $uniqueIps;
            
            // Build flattened SPF record
            $flattenedParts = ['v=spf1'];
            $currentLength = 7; // length of 'v=spf1 '
            
            // Sort IPs: IPv4 first, then IPv6
            $ipv4s = array_filter($uniqueIps, fn($ip) => $ip['version'] === '4');
            $ipv6s = array_filter($uniqueIps, fn($ip) => $ip['version'] === '6');
            
            foreach ($ipv4s as $ipData) {
                $part = 'ip4:' . $ipData['ip'];
                if ($currentLength + strlen($part) + 1 <= MAX_SPF_LENGTH) {
                    $flattenedParts[] = $part;
                    $currentLength += strlen($part) + 1;
                } else {
                    $result['warnings'][] = "IPv4 address {$ipData['ip']} exceeded record length limit";
                }
            }
            
            foreach ($ipv6s as $ipData) {
                $part = 'ip6:' . $ipData['ip'];
                if ($currentLength + strlen($part) + 1 <= MAX_SPF_LENGTH) {
                    $flattenedParts[] = $part;
                    $currentLength += strlen($part) + 1;
                } else {
                    $result['warnings'][] = "IPv6 address {$ipData['ip']} exceeded record length limit";
                }
            }
            
            // Add ~all or -all at the end
            $flattenedParts[] = '~all';
            
            $flattenedRecord = implode(' ', $flattenedParts);
            
            // If record is still too long, we need to split into multiple records
            if (strlen($flattenedRecord) > MAX_SPF_LENGTH) {
                $result['warnings'][] = "Record exceeds 255 characters - may need DNS chaining";
            }
            
            $result['success'] = true;
            $result['original_record'] = $domain['original_spf_record'] ?? '';
            $result['flattened_record'] = $flattenedRecord;
            $result['lookup_count_before'] = $totalLookupsBefore;
            $result['lookup_count_after'] = 0; // Flattened has zero lookups
            
            // Store results
            $this->saveFlatteningResult($domainId, $flattenedRecord, count($uniqueIps));
            $this->storeFlattenedIps($domainId, $uniqueIps);
            
        } catch (Exception $e) {
            $result['errors'][] = $e->getMessage();
            error_log("SPF flattening error: " . $e->getMessage());
        }
        
        return $result;
    }
    
    /**
     * Get original SPF record from DNS
     */
    private function getOriginalSPF($domain) {
        $cached = $this->getFromCache($domain, 'TXT');
        if ($cached !== null) {
            return $cached;
        }
        
        // Use dig or nslookup for DNS query
        $output = shell_exec("dig +short TXT {$domain} 2>/dev/null");
        if ($output) {
            $records = $this->parseTXTRecords($output);
            $spfRecord = $this->findSPFRecord($records);
            $this->saveToCache($domain, 'TXT', $spfRecord);
            return $spfRecord;
        }
        
        return '';
    }
    
    /**
     * Parse TXT records from dig output
     */
    private function parseTXTRecords($output) {
        $records = [];
        preg_match_all('/"([^"]*)"/', $output, $matches);
        if (!empty($matches[1])) {
            $records = $matches[1];
        }
        return $records;
    }
    
    /**
     * Find SPF record in TXT records
     */
    private function findSPFRecord($records) {
        foreach ($records as $record) {
            if (strpos($record, 'v=spf1') === 0) {
                return $record;
            }
        }
        return '';
    }
    
    /**
     * Count DNS lookups in an SPF record
     */
    private function countLookups($spfRecord) {
        if (empty($spfRecord)) return 0;
        
        $count = 0;
        $parts = explode(' ', $spfRecord);
        
        foreach ($parts as $part) {
            // These mechanisms cause DNS lookups
            if (preg_match('/^include:/i', $part)) {
                $count++;
            } elseif (preg_match('/^a$/i', $part) || preg_match('/^a:/i', $part)) {
                $count++;
            } elseif (preg_match('/^mx$/i', $part) || preg_match('/^mx:/i', $part)) {
                $count++;
            } elseif (preg_match('/^ptr$/i', $part) || preg_match('/^ptr:/i', $part)) {
                $count++;
            } elseif (preg_match('/^exists:/i', $part)) {
                $count++;
            } elseif (preg_match('/^redirect=/i', $part)) {
                $count++;
            }
        }
        
        return $count;
    }
    
    /**
     * Resolve an include domain to IP addresses
     */
    private function resolveInclude($includeDomain, $depth = 0) {
        if ($depth > $this->maxLookups) {
            error_log("Max lookup depth reached for {$includeDomain}");
            return [];
        }
        
        $this->lookupCount++;
        $ips = [];
        
        // Get SPF record for the include domain
        $spfRecord = $this->getOriginalSPF($includeDomain);
        
        if (empty($spfRecord)) {
            // Try to get A/AAAA records directly
            $aRecords = $this->getARecords($includeDomain);
            $aaaaRecords = $this->getAAAARecords($includeDomain);
            $ips = array_merge($aRecords, $aaaaRecords);
            return $ips;
        }
        
        // Parse the SPF record
        $parts = explode(' ', $spfRecord);
        
        foreach ($parts as $part) {
            if (preg_match('/^ip4:([\d\.\/]+)/i', $part, $matches)) {
                $ips[] = ['ip' => $matches[1], 'version' => '4'];
            } elseif (preg_match('/^ip6:([a-f0-9:\/]+)/i', $part, $matches)) {
                $ips[] = ['ip' => $matches[1], 'version' => '6'];
            } elseif (preg_match('/^include:([^ ]+)/i', $part, $matches)) {
                // Recursively resolve nested includes
                $nestedIps = $this->resolveInclude($matches[1], $depth + 1);
                $ips = array_merge($ips, $nestedIps);
            } elseif (preg_match('/^a:([^ ]+)?/i', $part, $matches)) {
                $aDomain = $matches[1] ?? $includeDomain;
                $aRecords = $this->getARecords($aDomain);
                $ips = array_merge($ips, $aRecords);
            } elseif (preg_match('/^mx:([^ ]+)?/i', $part, $matches)) {
                $mxDomain = $matches[1] ?? $includeDomain;
                $mxRecords = $this->getMXRecords($mxDomain);
                foreach ($mxRecords as $mx) {
                    $aRecords = $this->getARecords($mx);
                    $ips = array_merge($ips, $aRecords);
                }
            }
        }
        
        return $ips;
    }
    
    /**
     * Get A records for a domain
     */
    private function getARecords($domain) {
        $cached = $this->getFromCache($domain, 'A');
        if ($cached !== null) {
            return json_decode($cached, true) ?? [];
        }
        
        $ips = [];
        $output = shell_exec("dig +short A {$domain} 2>/dev/null");
        if ($output) {
            foreach (explode("\n", trim($output)) as $line) {
                if (filter_var(trim($line), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $ips[] = ['ip' => trim($line), 'version' => '4'];
                }
            }
            $this->saveToCache($domain, 'A', json_encode($ips));
        }
        
        return $ips;
    }
    
    /**
     * Get AAAA records for a domain
     */
    private function getAAAARecords($domain) {
        $cached = $this->getFromCache($domain, 'AAAA');
        if ($cached !== null) {
            return json_decode($cached, true) ?? [];
        }
        
        $ips = [];
        $output = shell_exec("dig +short AAAA {$domain} 2>/dev/null");
        if ($output) {
            foreach (explode("\n", trim($output)) as $line) {
                if (filter_var(trim($line), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    $ips[] = ['ip' => trim($line), 'version' => '6'];
                }
            }
            $this->saveToCache($domain, 'AAAA', json_encode($ips));
        }
        
        return $ips;
    }
    
    /**
     * Get MX records for a domain
     */
    private function getMXRecords($domain) {
        $mxHosts = [];
        $output = shell_exec("dig +short MX {$domain} 2>/dev/null");
        if ($output) {
            foreach (explode("\n", trim($output)) as $line) {
                $parts = preg_split('/\s+/', trim($line));
                if (count($parts) >= 2) {
                    $mxHosts[] = $parts[1];
                }
            }
        }
        return $mxHosts;
    }
    
    /**
     * Deduplicate IP addresses
     */
    private function deduplicateIps($ips) {
        $unique = [];
        $seen = [];
        
        foreach ($ips as $ipData) {
            $key = $ipData['ip'];
            if (!isset($seen[$key])) {
                $seen[$key] = true;
                $unique[] = $ipData;
            }
        }
        
        return $unique;
    }
    
    /**
     * Save flattening result to database
     */
    private function saveFlatteningResult($domainId, $flattenedRecord, $ipCount) {
        $stmt = $this->db->prepare("
            UPDATE domains 
            SET flattened_spf_record = ?, 
                lookup_count_after = 0,
                last_flattened_at = NOW(),
                last_updated_at = NOW()
            WHERE id = ?
        ");
        $stmt->execute([$flattenedRecord, $domainId]);
    }
    
    /**
     * Store flattened IPs in database
     */
    private function storeFlattenedIps($domainId, $ips) {
        // Deactivate existing IPs first
        $stmt = $this->db->prepare("UPDATE flattened_ips SET is_active = 0 WHERE domain_id = ?");
        $stmt->execute([$domainId]);
        
        // Insert/update new IPs
        $stmt = $this->db->prepare("
            INSERT INTO flattened_ips (domain_id, ip_address, ip_version, source_include, is_active)
            VALUES (?, ?, ?, ?, 1)
            ON DUPLICATE KEY UPDATE is_active = 1, last_verified = NOW()
        ");
        
        foreach ($ips as $ipData) {
            $stmt->execute([
                $domainId,
                $ipData['ip'],
                $ipData['version'],
                $ipData['source'] ?? $ipData['include'] ?? 'direct'
            ]);
        }
    }
    
    /**
     * Get DNS cache entry
     */
    private function getFromCache($domain, $type) {
        $stmt = $this->db->prepare("
            SELECT result_data FROM dns_cache 
            WHERE query_domain = ? AND query_type = ? AND expires_at > NOW()
        ");
        $stmt->execute([$domain, $type]);
        $result = $stmt->fetchColumn();
        return $result ?: null;
    }
    
    /**
     * Save DNS cache entry
     */
    private function saveToCache($domain, $type, $data) {
        $expires = date('Y-m-d H:i:s', time() + DNS_CACHE_TTL);
        $stmt = $this->db->prepare("
            INSERT INTO dns_cache (query_domain, query_type, result_data, expires_at)
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE result_data = VALUES(result_data), expires_at = VALUES(expires_at)
        ");
        $stmt->execute([$domain, $type, $data, $expires]);
    }
    
    /**
     * Compare current flattened IPs with stored ones to detect changes
     */
    public function detectChanges($domainId) {
        $changes = [
            'ips_added' => [],
            'ips_removed' => [],
            'has_changes' => false
        ];
        
        // Get currently stored active IPs
        $stmt = $this->db->prepare("
            SELECT ip_address, ip_version FROM flattened_ips 
            WHERE domain_id = ? AND is_active = 1
        ");
        $stmt->execute([$domainId]);
        $storedIps = $stmt->fetchAll(PDO::FETCH_COLUMN | PDO::FETCH_GROUP);
        
        // Flatten again to get current IPs
        $result = $this->flattenDomain($domainId);
        
        if ($result['success']) {
            $currentIps = [];
            foreach ($result['ips_collected'] as $ipData) {
                $currentIps[$ipData['ip']] = $ipData['version'];
            }
            
            // Find added IPs
            foreach ($currentIps as $ip => $version) {
                if (!isset($storedIps[$ip])) {
                    $changes['ips_added'][] = $ip;
                    $changes['has_changes'] = true;
                }
            }
            
            // Find removed IPs
            foreach ($storedIps as $ip => $version) {
                if (!isset($currentIps[$ip])) {
                    $changes['ips_removed'][] = $ip;
                    $changes['has_changes'] = true;
                }
            }
        }
        
        return $changes;
    }
}
