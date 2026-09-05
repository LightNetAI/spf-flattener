<?php
/**
 * DNS Lookup Utility Class
 * 
 * Handles DNS queries for SPF record discovery and parsing
 */

class DNSLookup {
    private $db;
    
    public function __construct() {
        $this->db = getDB();
    }
    
    /**
     * Get TXT records for a domain
     * 
     * @param string $domain Domain name to query
     * @return array Array of TXT record strings
     */
    public function getTXTRecords($domain) {
        // Check cache first
        $cached = $this->getFromCache($domain, 'TXT');
        if ($cached !== null) {
            return json_decode($cached, true);
        }
        
        $records = [];
        
        // Try dig first
        $output = shell_exec("dig +short TXT {$domain} 2>/dev/null");
        
        if (!$output) {
            // Fallback to nslookup
            $output = shell_exec("nslookup -q=TXT {$domain} 2>/dev/null");
        }
        
        if ($output) {
            // Parse TXT records - extract content between quotes
            preg_match_all('/"([^"]*)"/', $output, $matches);
            if (!empty($matches[1])) {
                $records = $matches[1];
            }
            
            // Also try to capture unquoted records
            if (empty($records)) {
                $lines = explode("\n", $output);
                foreach ($lines as $line) {
                    $line = trim($line);
                    if (stripos($line, 'v=spf1') !== false || stripos($line, 'txt') !== false) {
                        // Clean up the line
                        $line = str_replace(['"', '\'', 'TXT'], '', $line);
                        $line = trim($line);
                        if (!empty($line)) {
                            $records[] = $line;
                        }
                    }
                }
            }
        }
        
        // Cache the results
        if (!empty($records)) {
            $this->saveToCache($domain, 'TXT', json_encode($records));
        }
        
        return $records;
    }
    
    /**
     * Find SPF record in TXT records
     * 
     * @param string $domain Domain name
     * @return string SPF record (v=spf1...) or empty string if not found
     */
    public function getSPFRecord($domain) {
        $records = $this->getTXTRecords($domain);
        
        foreach ($records as $record) {
            // SPF records start with v=spf1
            if (stripos(trim($record), 'v=spf1') === 0) {
                return trim($record);
            }
        }
        
        return '';
    }
    
    /**
     * Parse SPF record and extract mechanisms
     * 
     * @param string $spfRecord SPF record string
     * @return array Parsed mechanisms with type and value
     */
    public function parseSPFRecord($spfRecord) {
        $mechanisms = [
            'includes' => [],
            'a_records' => [],
            'mx_records' => [],
            'ip4' => [],
            'ip6' => [],
            'ptr' => [],
            'exists' => [],
            'redirect' => '',
            'all' => '~all' // default
        ];
        
        if (empty($spfRecord)) {
            return $mechanisms;
        }
        
        // Remove 'v=spf1' prefix
        $parts = preg_split('/\s+/', trim($spfRecord));
        array_shift($parts); // Remove 'v=spf1'
        
        foreach ($parts as $part) {
            $part = trim($part);
            
            // Include mechanisms
            if (preg_match('/^include:([^ ]+)/i', $part, $matches)) {
                $mechanisms['includes'][] = $matches[1];
            }
            // A records
            elseif (preg_match('/^a$/i', $part)) {
                $mechanisms['a_records'][] = $part;
            }
            elseif (preg_match('/^a:([^ ]+)/i', $part, $matches)) {
                $mechanisms['a_records'][] = $matches[1];
            }
            // MX records
            elseif (preg_match('/^mx$/i', $part)) {
                $mechanisms['mx_records'][] = $part;
            }
            elseif (preg_match('/^mx:([^ ]+)/i', $part, $matches)) {
                $mechanisms['mx_records'][] = $matches[1];
            }
            // IPv4 addresses
            elseif (preg_match('/^ip4:([\d\.\/]+)/i', $part, $matches)) {
                $mechanisms['ip4'][] = $matches[1];
            }
            // IPv6 addresses
            elseif (preg_match('/^ip6:([a-f0-9:\/]+)/i', $part, $matches)) {
                $mechanisms['ip6'][] = $matches[1];
            }
            // PTR (deprecated but still seen)
            elseif (preg_match('/^ptr$/i', $part) || preg_match('/^ptr:([^ ]+)/i', $part, $matches)) {
                $mechanisms['ptr'][] = $part;
            }
            // EXISTS mechanism
            elseif (preg_match('/^exists:([^ ]+)/i', $part, $matches)) {
                $mechanisms['exists'][] = $matches[1];
            }
            // Redirect
            elseif (preg_match('/^redirect=([^ ]+)/i', $part, $matches)) {
                $mechanisms['redirect'] = $matches[1];
            }
            // All mechanism
            elseif (preg_match('/^[-+~]?all$/i', $part)) {
                $mechanisms['all'] = $part;
            }
        }
        
        return $mechanisms;
    }
    
    /**
     * Import SPF record for a domain
     * 
     * @param int $domainId Domain ID from database
     * @return array Result with imported data
     */
    public function importSPFForDomain($domainId) {
        $result = [
            'success' => false,
            'domain_id' => $domainId,
            'spf_record' => '',
            'mechanisms' => [],
            'includes_found' => 0,
            'senders_added' => 0,
            'errors' => []
        ];
        
        try {
            // Get domain name
            $stmt = $this->db->prepare("SELECT domain FROM domains WHERE id = ?");
            $stmt->execute([$domainId]);
            $domain = $stmt->fetchColumn();
            
            if (!$domain) {
                $result['errors'][] = "Domain not found";
                return $result;
            }
            
            // Query DNS for SPF record
            $spfRecord = $this->getSPFRecord($domain);
            
            if (empty($spfRecord)) {
                $result['errors'][] = "No SPF record found for {$domain}";
                return $result;
            }
            
            $result['spf_record'] = $spfRecord;
            
            // Parse the SPF record
            $mechanisms = $this->parseSPFRecord($spfRecord);
            $result['mechanisms'] = $mechanisms;
            $result['includes_found'] = count($mechanisms['includes']);
            
            // Update domain with original SPF record
            $stmt = $this->db->prepare("
                UPDATE domains 
                SET original_spf_record = ?,
                    lookup_count_before = ?
                WHERE id = ?
            ");
            $lookupCount = $this->countLookups($spfRecord);
            $stmt->execute([$spfRecord, $lookupCount, $domainId]);
            
            // Create sending domain entry for the apex domain
            $stmt = $this->db->prepare("
                INSERT INTO sending_domains (domain_id, sending_domain, is_active)
                VALUES (?, ?, 1)
                ON DUPLICATE KEY UPDATE is_active = 1
            ");
            $stmt->execute([$domainId, $domain]);
            $sendingDomainId = $this->db->lastInsertId();
            
            // Get existing senders to avoid duplicates
            $stmt = $this->db->prepare("
                SELECT include_domain FROM approved_senders 
                WHERE sending_domain_id = ?
            ");
            $stmt->execute([$sendingDomainId]);
            $existingIncludes = $stmt->fetchAll(PDO::FETCH_COLUMN);
            
            // Add each include as an approved sender
            $sendersAdded = 0;
            foreach ($mechanisms['includes'] as $include) {
                if (!in_array($include, $existingIncludes)) {
                    $stmt = $this->db->prepare("
                        INSERT INTO approved_senders 
                        (sending_domain_id, sender_name, include_domain, is_active)
                        VALUES (?, ?, ?, 1)
                    ");
                    
                    // Try to generate a friendly name for the sender
                    $senderName = $this->generateSenderName($include);
                    
                    $stmt->execute([$sendingDomainId, $senderName, $include]);
                    $sendersAdded++;
                }
            }
            
            $result['senders_added'] = $sendersAdded;
            $result['success'] = true;
            
        } catch (Exception $e) {
            $result['errors'][] = $e->getMessage();
            error_log("SPF import error: " . $e->getMessage());
        }
        
        return $result;
    }
    
    /**
     * Count DNS lookups in an SPF record
     */
    public function countLookups($spfRecord) {
        if (empty($spfRecord)) return 0;
        
        $count = 0;
        $parts = preg_split('/\s+/', $spfRecord);
        
        foreach ($parts as $part) {
            // These mechanisms cause DNS lookups per RFC 7208
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
     * Generate a friendly sender name from include domain
     */
    private function generateSenderName($includeDomain) {
        // Common SPF include patterns
        $knownSenders = [
            '_spf.google.com' => 'Google Workspace',
            'spf.protection.outlook.com' => 'Microsoft 365',
            '_spf.microsoft.com' => 'Microsoft',
            'include.sendgrid.net' => 'SendGrid',
            'include:mailgun.org' => 'Mailgun',
            'include:amazonses.com' => 'Amazon SES',
            'include:servers.mcsv.net' => 'Mailchimp',
            'include:spf.mandrillapp.com' => 'Mandrill',
            'include:spf.zendesk.com' => 'Zendesk',
            'include:spf.salesforce.com' => 'Salesforce',
            'include:spf.hubspot.com' => 'HubSpot',
            'include:sendinblue.com' => 'Sendinblue',
            'include:spf.mailjet.com' => 'Mailjet',
            'include:spf.smartmailcloud.com' => 'SmartMail',
            'include:spf.fastmail.com' => 'FastMail',
            'include:spf.protonmail.ch' => 'ProtonMail',
            '_spf.163.com' => '163.com',
            '_spf.qq.com' => 'QQ Mail',
        ];
        
        if (isset($knownSenders[$includeDomain])) {
            return $knownSenders[$includeDomain];
        }
        
        // Try to extract a name from the domain
        $parts = explode('.', $includeDomain);
        if (count($parts) >= 2) {
            $name = ucfirst(str_replace(['-', '_', 'spf'], '', $parts[0]));
            if (!empty($name) && strlen($name) > 1) {
                return $name . ' (' . $includeDomain . ')';
            }
        }
        
        return $includeDomain;
    }
    
    /**
     * Get DNS cache entry
     */
    private function getFromCache($domain, $type) {
        try {
            $stmt = $this->db->prepare("
                SELECT result_data FROM dns_cache 
                WHERE query_domain = ? AND query_type = ? AND expires_at > NOW()
            ");
            $stmt->execute([$domain, $type]);
            $result = $stmt->fetchColumn();
            return $result ?: null;
        } catch (Exception $e) {
            return null;
        }
    }
    
    /**
     * Save DNS cache entry
     */
    private function saveToCache($domain, $type, $data) {
        try {
            $expires = date('Y-m-d H:i:s', time() + DNS_CACHE_TTL);
            $stmt = $this->db->prepare("
                INSERT INTO dns_cache (query_domain, query_type, result_data, expires_at)
                VALUES (?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE result_data = VALUES(result_data), expires_at = VALUES(expires_at)
            ");
            $stmt->execute([$domain, $type, $data, $expires]);
        } catch (Exception $e) {
            error_log("DNS cache save error: " . $e->getMessage());
        }
    }
    
    /**
     * Test DNS lookup functionality
     */
    public function testDNS($domain = 'google.com') {
        $result = [
            'success' => false,
            'domain' => $domain,
            'txt_records' => [],
            'spf_record' => '',
            'errors' => []
        ];
        
        // Check if dig is available
        $digExists = shell_exec('which dig 2>/dev/null');
        if (empty($digExists)) {
            $result['errors'][] = "dig command not found. Please install dnsutils.";
            return $result;
        }
        
        $records = $this->getTXTRecords($domain);
        $result['txt_records'] = $records;
        
        if (!empty($records)) {
            $result['spf_record'] = $this->getSPFRecord($domain);
            $result['success'] = true;
        } else {
            $result['errors'][] = "No TXT records returned";
        }
        
        return $result;
    }
}
