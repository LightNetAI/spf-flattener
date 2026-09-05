<?php
/**
 * Email Notification System
 * Sends change notifications similar to cfspflat's email alerts
 */

class EmailNotifier {
    private $db;
    
    public function __construct() {
        $this->db = getDB();
    }
    
    /**
     * Queue an email notification
     */
    public function queueEmail($recipient, $subject, $body) {
        if (!ENABLE_EMAIL_NOTIFICATIONS) {
            error_log("Email notifications disabled");
            return false;
        }
        
        $stmt = $this->db->prepare("
            INSERT INTO email_queue (recipient_email, subject, body, status)
            VALUES (?, ?, ?, 'PENDING')
        ");
        
        return $stmt->execute([$recipient, $subject, $body]);
    }
    
    /**
     * Send notification about SPF changes
     */
    public function sendChangeNotification($domain, $changes, $flattenedRecord) {
        $recipient = $this->getConfig('smtp_from_email');
        
        $subject = "[SPF Flattener] Changes detected for {$domain}";
        
        $body = $this->buildChangeEmail($domain, $changes, $flattenedRecord);
        
        return $this->queueEmail($recipient, $subject, $body);
    }
    
    /**
     * Send notification about successful SPF update
     */
    public function sendUpdateNotification($domain, $flattenedRecord, $ipsCount) {
        $recipient = $this->getConfig('smtp_from_email');
        
        $subject = $this->getConfig('update_subject') ?: "[SPF Flattener] SPF record updated for {$domain}";
        
        $body = $this->buildUpdateEmail($domain, $flattenedRecord, $ipsCount);
        
        return $this->queueEmail($recipient, $subject, $body);
    }
    
    /**
     * Build change notification email body
     */
    private function buildChangeEmail($domain, $changes, $flattenedRecord) {
        $html = "<html><body style='font-family: Arial, sans-serif;'>";
        $html .= "<h2>SPF Record Changes Detected</h2>";
        $html .= "<p>Domain: <strong>{$domain}</strong></p>";
        $html .= "<p>Date: " . date('Y-m-d H:i:s') . "</p>";
        
        if (!empty($changes['ips_added'])) {
            $html .= "<h3>IPs Added (" . count($changes['ips_added']) . ")</h3>";
            $html .= "<ul>";
            foreach ($changes['ips_added'] as $ip) {
                $html .= "<li>{$ip}</li>";
            }
            $html .= "</ul>";
        }
        
        if (!empty($changes['ips_removed'])) {
            $html .= "<h3>IPs Removed (" . count($changes['ips_removed']) . ")</h3>";
            $html .= "<ul>";
            foreach ($changes['ips_removed'] as $ip) {
                $html .= "<li>{$ip}</li>";
            }
            $html .= "</ul>";
        }
        
        $html .= "<h3>New Flattened SPF Record</h3>";
        $html .= "<code style='background: #f4f4f4; padding: 10px; display: block; word-break: break-all;'>";
        $html .= htmlspecialchars($flattenedRecord);
        $html .= "</code>";
        
        $html .= "<p><strong>Action Required:</strong> Please review and update your DNS records.</p>";
        $html .= "</body></html>";
        
        return $body;
    }
    
    /**
     * Build update notification email body
     */
    private function buildUpdateEmail($domain, $flattenedRecord, $ipsCount) {
        $html = "<html><body style='font-family: Arial, sans-serif;'>";
        $html .= "<h2>SPF Record Updated Successfully</h2>";
        $html .= "<p>Domain: <strong>{$domain}</strong></p>";
        $html .= "<p>Date: " . date('Y-m-d H:i:s') . "</p>";
        $html .= "<p>Total IPs in flattened record: <strong>{$ipsCount}</strong></p>";
        
        $html .= "<h3>Updated SPF Record</h3>";
        $html .= "<code style='background: #f4f4f4; padding: 10px; display: block; word-break: break-all;'>";
        $html .= htmlspecialchars($flattenedRecord);
        $html .= "</code>";
        
        $html .= "<p>Your Cloudflare DNS has been automatically updated.</p>";
        $html .= "</body></html>";
        
        return $html;
    }
    
    /**
     * Process pending emails in queue
     */
    public function processQueue() {
        $stmt = $this->db->query("
            SELECT * FROM email_queue WHERE status = 'PENDING' 
            ORDER BY created_at ASC LIMIT 50
        ");
        
        $emails = $stmt->fetchAll();
        $sent = 0;
        $failed = 0;
        
        foreach ($emails as $email) {
            if ($this->sendEmail($email)) {
                $sent++;
            } else {
                $failed++;
            }
        }
        
        return ['sent' => $sent, 'failed' => $failed];
    }
    
    /**
     * Send a single email
     */
    private function sendEmail($email) {
        $smtpServer = $this->getConfig('smtp_server');
        $smtpPort = $this->getConfig('smtp_port') ?: 587;
        $fromEmail = $this->getConfig('smtp_from_email');
        $fromName = $this->getConfig('smtp_from_name') ?: 'SPF Flattener';
        $smtpUsername = $this->getConfig('smtp_username');
        $smtpPassword = $this->getConfig('smtp_password');
        
        if (empty($smtpServer) || empty($fromEmail)) {
            error_log("SMTP not configured");
            $this->markEmailFailed($email['id'], 'SMTP not configured');
            return false;
        }
        
        // Use PHP's mail() or a library like PHPMailer
        // For now, using simple mail() - in production, use PHPMailer
        $headers = [
            'From: ' . $fromName . ' <' . $fromEmail . '>',
            'Reply-To: ' . $fromEmail,
            'MIME-Version: 1.0',
            'Content-Type: text/html; charset=UTF-8'
        ];
        
        $result = mail(
            $email['recipient_email'],
            $email['subject'],
            $email['body'],
            implode("\r\n", $headers)
        );
        
        if ($result) {
            $this->markEmailSent($email['id']);
            return true;
        } else {
            $this->markEmailFailed($email['id'], 'mail() failed');
            return false;
        }
    }
    
    /**
     * Mark email as sent
     */
    private function markEmailSent($id) {
        $stmt = $this->db->prepare("
            UPDATE email_queue SET status = 'SENT', sent_at = NOW() WHERE id = ?
        ");
        $stmt->execute([$id]);
    }
    
    /**
     * Mark email as failed
     */
    private function markEmailFailed($id, $error) {
        $stmt = $this->db->prepare("
            UPDATE email_queue SET status = 'FAILED', error_message = ? WHERE id = ?
        ");
        $stmt->execute([$error, $id]);
    }
    
    /**
     * Get config value
     */
    private function getConfig($key) {
        try {
            $stmt = $this->db->prepare("SELECT config_value FROM config WHERE config_key = ?");
            $stmt->execute([$key]);
            return $stmt->fetchColumn();
        } catch (Exception $e) {
            return '';
        }
    }
}
