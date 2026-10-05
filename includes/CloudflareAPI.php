<?php
/**
 * Cloudflare API Integration
 * Handles automatic SPF record updates in Cloudflare DNS
 * Replicates cfspflat's --update-records functionality
 */

class CloudflareAPI {
    // Authentication is by scoped API token only. The legacy email + global
    // API key path has been removed: a global key grants access to every zone
    // in the account, so a leaked or over-scoped key risks far more than the
    // token needed for this job.
    private $apiToken;
    // Cached zone list for the current request; see listZones().
    private $zoneCache = null;
    // Cloudflare's API lives under /client/v4. Without the /client segment the
    // API returns {"code":10404,"message":"No route for that URI"}, which
    // surfaced as CLOUDFLARE_ZONE_LOOKUP_FAILED for every call.
    private $baseUrl = 'https://api.cloudflare.com/client/v4';

    public function __construct() {
        $this->apiToken = defined('CLOUDFLARE_API_TOKEN') && CLOUDFLARE_API_TOKEN
            ? CLOUDFLARE_API_TOKEN
            : $this->getConfig('cloudflare_api_token');
    }

    /**
     * Is an API token configured?
     *
     * Checking first turns an opaque 403 from Cloudflare into an actionable
     * message.
     */
    public function hasCredentials() {
        return !empty($this->apiToken);
    }
    
    /**
     * Make API request to Cloudflare
     */
    /**
     * Perform an API request.
     *
     * Protected so a test double can substitute canned responses without
     * reaching the network.
     */
    protected function request($method, $endpoint, $data = null) {
        if (!$this->hasCredentials()) {
            throw new Exception(
                'No Cloudflare API token is configured. Add one under Settings: '
              . 'create a token with Zone:Read and DNS:Edit for the zones you '
              . 'flatten, then paste it into the API Token field.'
            );
        }

        $url = $this->baseUrl . $endpoint;
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_TIMEOUT, 20);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);

        // API token authentication. The email + global key path was removed
        // deliberately — see the class comment.
        $headers = [
            'Authorization: *** ' . $this->apiToken,
            'Content-Type: application/json',
        ];
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        
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
            throw new Exception("Could not reach the Cloudflare API: " . $error);
        }

        $result = json_decode($response, true);

        if (!is_array($result) || empty($result['success'])) {
            // Surface the API's own code and message; a bare "Unknown error"
            // made a misconfigured URL look like an authentication problem.
            $msg  = $result['errors'][0]['message'] ?? null;
            $code = $result['errors'][0]['code'] ?? null;
            if ($msg === null) {
                $msg = 'HTTP ' . $httpCode . ' with an unparseable response';
            } elseif ($code !== null) {
                $msg = "{$msg} (code {$code})";
            }
            throw new Exception("Cloudflare API error: {$msg}");
        }
        
        return $result;
    }
    
    /**
     * Get zone ID by domain name
     */
    /**
     * Every zone this account can see, cached for the request.
     *
     * Zone lookups must be done once per request, not once per record: a chain
     * of six records would otherwise spend six API calls resolving zones.
     */
    private function listZones() {
        if ($this->zoneCache !== null) {
            return $this->zoneCache;
        }

        $zones = [];
        $page = 1;
        do {
            $response = $this->request('GET', '/zones?per_page=50&page=' . $page);
            foreach ($response['result'] as $zone) {
                $zones[] = ['id' => $zone['id'], 'name' => $zone['name']];
            }
            $totalPages = $response['result_info']['total_pages'] ?? 1;
            $page++;
        } while ($page <= $totalPages && $page <= 20);

        $this->zoneCache = $zones;
        return $zones;
    }

    /**
     * Resolve the zone that owns a record name.
     *
     * Cloudflare's /zones?name= filter matches a zone name EXACTLY, so asking
     * it for "spf0.flattenme.com.cloudflarezone.com" finds nothing.
     * The owning zone is the longest zone name that is a suffix of the record
     * name, which is what this finds.
     */
    public function resolveZoneId($name) {
        $name = strtolower(rtrim($name, '.'));
        $best = null;

        foreach ($this->listZones() as $zone) {
            $zname = strtolower($zone['name']);
            if ($name === $zname || str_ends_with($name, '.' . $zname)) {
                if ($best === null || strlen($zname) > strlen($best['name'])) {
                    $best = ['id' => $zone['id'], 'name' => $zname];
                }
            }
        }

        if ($best !== null) {
            return $best['id'];
        }

        throw new Exception(
            "No Cloudflare zone in this account matches '{$name}'. "
          . "The zone may belong to a different account, or the API token may "
          . "lack Zone:Read for it."
        );
    }

    public function getZoneId($domain) {
        return $this->resolveZoneId($domain);
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
    public function updateSPFRecord($zoneId, $recordId, $spfContent, $proxied = false, $name = null, $ttl = 1) {
        // A PUT replaces the whole record. Sending only content and proxied
        // would blank the name and TTL, so the full record is sent every time.
        $data = [
            'type' => 'TXT',
            'content' => '"' . $spfContent . '"',
            'proxied' => $proxied,
            'ttl' => $ttl,
        ];
        if ($name !== null) {
            $data['name'] = $name;
        }

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
     * spf0.<domain>.<zone> references spf1.<domain>.<zone> and so on, so every
     * record must exist or SPF evaluation fails with a PermError.
     *
     * The apex anchor (named for the sending domain itself) usually lives in a
     * different zone from the spfN records, so the zone is resolved per record
     * name rather than once for the whole set.
     *
     * The anchor is deliberately NOT published. Its live value is the
     * operator's to set: overwriting the apex of a domain that is already
     * sending could break its mail. It comes back in `skipped`.
     *
     * @param string $domain  Sending domain (the anchor's name and chain suffix)
     * @param array  $records [['name' => …, 'content' => …], …]
     * @return array{updated:array,failed:array,skipped:array}
     */
    public function publishChain($domain, array $records) {
        $updated = [];
        $failed  = [];
        $skipped = [];

        if (empty($records)) {
            return ['updated' => $updated, 'failed' => $failed, 'skipped' => $skipped];
        }

        // Fail fast if the account or token is unusable, so the operator gets
        // one clear reason instead of the same failure repeated per record.
        $this->listZones();

        foreach ($records as $rec) {
            $name = $rec['name'];
            $value = $rec['content'];

            // Never touch the apex anchor; see the method comment.
            if (strcasecmp($name, $domain) === 0) {
                $skipped[] = [
                    'name'   => $name,
                    'reason' => 'apex anchor — point this at the chain yourself',
                ];
                continue;
            }

            try {
                $zoneId  = $this->resolveZoneId($name);
                $existing = $this->getTxtRecord($zoneId, $name);

                if ($existing) {
                    $this->updateSPFRecord(
                        $zoneId, $existing['id'], $value,
                        $existing['proxied'], $name, $existing['ttl']
                    );
                } else {
                    $this->createSPFRecord($zoneId, $name, $value);
                }
                $updated[] = $name;
            } catch (Throwable $e) {
                error_log("Cloudflare push failed for {$name}: " . $e->getMessage());
                $failed[] = ['name' => $name, 'error' => $e->getMessage()];
            }
        }

        return ['updated' => $updated, 'failed' => $failed, 'skipped' => $skipped];
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
                    'ttl'     => $record['ttl'] ?? 1,
                    'name'    => $record['name'] ?? null,
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
