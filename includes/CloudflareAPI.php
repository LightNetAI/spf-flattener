<?php
/**
 * Cloudflare API Integration
 * Handles automatic SPF record updates in Cloudflare DNS
 * Replicates cfspflat's --update-records functionality
 */

class CloudflareAPI {
    private $apiEmail;
    private $apiKey;
    private $baseUrl = 'https://api.cloudflare.com/v4';
    
    public function __construct() {
        // Try to get from config first, then database
        $this->apiEmail = CLOUDFLARE_API_EMAIL ?: $this->getConfig('cloudflare_api_email');
        $this->apiKey = CLOUDFLARE_API_KEY ?: $this->getConfig('cloudflare_api_key');
    }
    
    /**
     * Make API request to Cloudflare
     */
    private function request($method, $endpoint, $data = null) {
        $url = $this->baseUrl . $endpoint;
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'X-Auth-Email: ' . $this->apiEmail,
            'X-Auth-Key: ' . $this->apiKey,
            'Content-Type: application/json'
        ]);
        
        if ($data !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        }
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        // curl_close() is deprecated as of PHP 8.5 — the handle is freed
        // automatically when it goes out of scope.
        unset($ch);
        
        if ($error) {
            throw new Exception("Cloudflare API error: " . $error);
        }
        
        $result = json_decode($response, true);
        
        if (!is_array($result) || empty($result['success'])) {
            throw new Exception("Cloudflare API error: " . ($result['errors'][0]['message'] ?? 'Unknown error'));
        }
        
        return $result;
    }
    
    /**
     * Get zone ID by domain name
     */
    public function getZoneId($domain) {
        $response = $this->request('GET', '/zones?name=' . urlencode($domain));
        
        if (!empty($response['result'])) {
            return $response['result'][0]['id'];
        }
        
        throw new Exception("Zone not found for domain: {$domain}");
    }
    
    /**
     * Get existing SPF TXT record for a domain
     */
    public function getSPFRecord($zoneId, $domain) {
        $response = $this->request('GET', "/zones/{$zoneId}/dns_records?type=TXT&name=" . urlencode($domain));
        
        foreach ($response['result'] as $record) {
            $content = $record['content'];
            // Remove quotes from TXT record
            $content = trim($content, '"');
            if (strpos($content, 'v=spf1') === 0) {
                return [
                    'id' => $record['id'],
                    'content' => $content,
                    'proxied' => $record['proxied'] ?? false
                ];
            }
        }
        
        return null;
    }
    
    /**
     * Update SPF record in Cloudflare
     */
    public function updateSPFRecord($zoneId, $recordId, $spfContent, $proxied = false) {
        $data = [
            'content' => '"' . $spfContent . '"',
            'proxied' => $proxied
        ];
        
        $response = $this->request('PUT', "/zones/{$zoneId}/dns_records/{$recordId}", $data);
        return $response['result'];
    }
    
    /**
     * Create new SPF record in Cloudflare
     */
    public function createSPFRecord($zoneId, $domain, $spfContent, $proxied = false) {
        $data = [
            'type' => 'TXT',
            'name' => $domain,
            'content' => '"' . $spfContent . '"',
            'proxied' => $proxied,
            'ttl' => 1 // Auto TTL
        ];
        
        $response = $this->request('POST', "/zones/{$zoneId}/dns_records", $data);
        return $response['result'];
    }
    
    /**
     * Publish a complete SPF record chain to Cloudflare.
     *
     * spf0.<domain> references spf1.<domain> and so on, so every record must
     * exist or SPF evaluation fails with a PermError. Sub-records are written
     * first: that way the chain is already resolvable when the apex anchor is
     * updated to point at it.
     *
     * @param string $domain  Sending domain (the chain's suffix)
     * @param array  $records [['name' => 'spf0.example.com', 'content' => 'v=spf1 …'], …]
     * @return array{updated:array,failed:array}
     */
    public function publishChain($domain, array $records) {
        $updated = [];
        $failed  = [];

        if (empty($records)) {
            return ['updated' => $updated, 'failed' => $failed];
        }

        $zoneId = $this->getZoneId($domain);

        foreach ($records as $rec) {
            $name = $rec['name'];
            $value = $rec['content'];

            try {
                $existing = $this->getTxtRecord($zoneId, $name);

                if ($existing) {
                    $this->updateSPFRecord($zoneId, $existing['id'], $value, $existing['proxied']);
                } else {
                    $this->createSPFRecord($zoneId, $name, $value);
                }
                $updated[] = $name;
            } catch (Exception $e) {
                error_log("Cloudflare push failed for {$name}: " . $e->getMessage());
                $failed[] = ['name' => $name, 'error' => $e->getMessage()];
            }
        }

        return ['updated' => $updated, 'failed' => $failed];
    }

    /**
     * Find the SPF/authorisation TXT record for an exact name.
     *
     * getSPFRecord() above deliberately searches the apex for a v=spf1
     * record; sub-records also begin with v=spf1, so the same matching works
     * for any name in the chain.
     */
    public function getTxtRecord($zoneId, $name) {
        $response = $this->request(
            'GET',
            "/zones/{$zoneId}/dns_records?type=TXT&name=" . urlencode($name)
        );

        foreach ($response['result'] as $record) {
            $content = trim($record['content'], '"');
            if (strpos($content, 'v=spf1') === 0) {
                return [
                    'id'      => $record['id'],
                    'content' => $content,
                    'proxied' => $record['proxied'] ?? false,
                ];
            }
        }

        return null;
    }

    /**
     * Update SPF record for a domain (main method)
     */
    public function updateDomainSPF($domain, $spfContent) {
        try {
            $zoneId = $this->getZoneId($domain);
            $existingRecord = $this->getSPFRecord($zoneId, $domain);
            
            if ($existingRecord) {
                // Update existing record
                return $this->updateSPFRecord($zoneId, $existingRecord['id'], $spfContent);
            } else {
                // Create new record
                return $this->createSPFRecord($zoneId, $domain, $spfContent);
            }
        } catch (Exception $e) {
            error_log("Cloudflare update failed for {$domain}: " . $e->getMessage());
            throw $e;
        }
    }
    
    /**
     * Get config value from database
     */
    private function getConfig($key) {
        try {
            $db = getDB();
            $stmt = $db->prepare("SELECT config_value FROM config WHERE config_key = ?");
            $stmt->execute([$key]);
            return $stmt->fetchColumn();
        } catch (Exception $e) {
            return '';
        }
    }
}
