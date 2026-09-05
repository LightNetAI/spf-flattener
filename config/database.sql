-- SPF Flattener Database Schema
-- Run this to create the required tables

CREATE DATABASE IF NOT EXISTS spf_flattener CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE spf_flattener;

-- Configuration table for global settings
CREATE TABLE IF NOT EXISTS config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Insert default config values
INSERT INTO config (config_key, config_value) VALUES
    ('cloudflare_api_email', ''),
    ('cloudflare_api_key', ''),
    ('smtp_server', ''),
    ('smtp_port', '587'),
    ('smtp_from_email', ''),
    ('smtp_from_name', 'SPF Flattener'),
    ('smtp_username', ''),
    ('smtp_password', ''),
    ('enable_email_notifications', '1'),
    ('auto_update_enabled', '0'),
    ('last_flatten_run', NULL)
ON DUPLICATE KEY UPDATE config_value=config_value;

-- Domains table - stores domains to flatten
CREATE TABLE IF NOT EXISTS domains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    cloudflare_zone_id VARCHAR(100),
    original_spf_record TEXT,
    flattened_spf_record TEXT,
    lookup_count_before INT DEFAULT 0,
    lookup_count_after INT DEFAULT 0,
    is_active TINYINT(1) DEFAULT 1,
    last_flattened_at TIMESTAMP NULL,
    last_updated_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_domain (domain),
    INDEX idx_active (is_active)
);

-- Sending domains (the domains that send email)
CREATE TABLE IF NOT EXISTS sending_domains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    sending_domain VARCHAR(255) NOT NULL,
    record_type ENUM('TXT', 'A', 'AAAA') DEFAULT 'TXT',
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    UNIQUE KEY unique_sending (domain_id, sending_domain)
);

-- Approved senders (include mechanisms)
CREATE TABLE IF NOT EXISTS approved_senders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sending_domain_id INT NOT NULL,
    sender_name VARCHAR(255) NOT NULL,
    include_domain VARCHAR(255) NOT NULL,
    description TEXT,
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sending_domain_id) REFERENCES sending_domains(id) ON DELETE CASCADE,
    INDEX idx_sender (sender_name)
);

-- Flattened IP records
CREATE TABLE IF NOT EXISTS flattened_ips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    ip_version ENUM('4', '6') NOT NULL,
    source_include VARCHAR(255),
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_verified TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active TINYINT(1) DEFAULT 1,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    INDEX idx_domain_ip (domain_id, ip_address),
    INDEX idx_version (ip_version)
);

-- Change log for tracking SPF record changes
CREATE TABLE IF NOT EXISTS change_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    change_type ENUM('INITIAL', 'UPDATE', 'REPAIR', 'IP_ADDED', 'IP_REMOVED') NOT NULL,
    old_record TEXT,
    new_record TEXT,
    ips_added INT DEFAULT 0,
    ips_removed INT DEFAULT 0,
    email_sent TINYINT(1) DEFAULT 0,
    cloudflare_updated TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    INDEX idx_domain (domain_id),
    INDEX idx_created (created_at)
);

-- Email queue for notifications
CREATE TABLE IF NOT EXISTS email_queue (
    id INT AUTO_INCREMENT PRIMARY KEY,
    recipient_email VARCHAR(255) NOT NULL,
    subject VARCHAR(500) NOT NULL,
    body TEXT NOT NULL,
    status ENUM('PENDING', 'SENT', 'FAILED') DEFAULT 'PENDING',
    sent_at TIMESTAMP NULL,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_status (status)
);

-- DNS lookup cache (to reduce repeated lookups)
CREATE TABLE IF NOT EXISTS dns_cache (
    id INT AUTO_INCREMENT PRIMARY KEY,
    query_domain VARCHAR(255) NOT NULL,
    query_type ENUM('TXT', 'A', 'AAAA', 'MX') NOT NULL,
    result_data TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_query (query_domain, query_type),
    INDEX idx_expires (expires_at)
);
