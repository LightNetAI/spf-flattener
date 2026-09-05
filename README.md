# SPF Flattener

A PHP/MySQL web application for flattening SPF records, replicating the functionality of [cfspflat](https://github.com/Glocktober/cfspflat) with a full GUI interface.

## Features

- **Web-based GUI** - No CLI required, manage everything from your browser
- **DNS SPF Import** - Automatically fetch and parse existing SPF records from DNS
- **Automatic SPF Flattening** - Resolves `include:` mechanisms to direct `ip4:` and `ip6:` entries
- **DNS Lookup Counter** - Shows how many lookups your SPF record uses (RFC 7208 limit: 10)
- **Cloudflare Integration** - Automatically update SPF records in Cloudflare DNS
- **Change Detection** - Monitors sender IPs and alerts when they change
- **Email Notifications** - Get notified when SPF records need updating
- **DNS Caching** - Reduces repeated DNS queries with configurable TTL
- **Automated Updates** - Cron job for scheduled re-flattening (like cfspflat's `--update-records`)
- **Multi-domain Support** - Manage SPF flattening for multiple domains from one interface
- **CLI Interface** - Full command-line alternative to the web GUI

## Requirements

- PHP 7.4+ (8.0+ recommended)
- MySQL 5.7+ or MariaDB 10.3+
- `dig` command (for DNS lookups) - install with `apt install dnsutils` or `yum install bind-utils`
- Web server (Apache, Nginx, etc.)
- Optional: Cloudflare API credentials for auto-updates

## Installation

### 1. Clone or Download

```bash
cd /var/www/html
git clone https://github.com/yourusername/spf-flattener.git
# Or download and extract the zip file
```

### 2. Run Installation Script

```bash
cd spf-flattener
chmod +x install.sh
./install.sh
```

The installer will:
- Create the MySQL database and tables
- Generate a configuration file
- Set up directory permissions
- Optionally configure a cron job

### 3. Web Access

Open your browser and navigate to:
```
http://your-server/spf-flattener
```

### 4. Configure

1. Add your domains (with optional SPF import from DNS)
2. Configure approved senders (or let DNS import do it automatically)
3. (Optional) Add Cloudflare API credentials for automatic updates
4. Click **Flatten** to generate your flattened SPF record
5. Copy the flattened record to your DNS

## Usage

### Quick Start - Import Existing SPF

The easiest way to get started:

1. Go to **Add Domain** tab
2. Enter your domain (e.g., `example.com`)
3. Click **📡 Fetch SPF Record**
4. Review the parsed SPF record and detected includes
5. Click **➕ Import & Add Domain**
6. Click **⚡ Flatten** to generate your flattened record

This automatically:
- Queries DNS for your SPF TXT record
- Parses all `include:` mechanisms
- Creates sender entries for each include
- Counts DNS lookups

### Dashboard

The main dashboard shows:
- All configured domains
- Number of DNS lookups before flattening
- Number of IPs after flattening
- Last flattening timestamp
- Quick actions (Flatten, View, Delete)

### Adding a Domain

#### Option 1: Import from DNS (Recommended)

1. Go to **Add Domain** tab
2. Under "Import from DNS":
   - Enter your domain name
   - Click **🔍 Test DNS Lookup** (optional, verifies DNS works)
   - Click **📡 Fetch SPF Record**
   - Review the parsed record
   - Click **➕ Import & Add Domain**

#### Option 2: Manual Add with Import

1. Go to **Add Domain** tab
2. Under "Add Manually":
   - Enter domain name
   - Check "Import SPF record from DNS after adding"
   - Click **➕ Add Domain**

#### Option 3: Manual Add Only

1. Go to **Add Domain** tab
2. Enter domain and optional Cloudflare Zone ID
3. Click **➕ Add Domain**
4. Manually add senders in the **Approved Senders** tab

### Adding Approved Senders

1. Go to **Approved Senders** tab
2. Select a domain
3. Enter:
   - **Sending Domain**: The domain that sends email (e.g., `mail.example.com`)
   - **Sender Name**: Friendly name (e.g., `Google Workspace`)
   - **Include Domain**: The SPF include mechanism (e.g., `_spf.google.com`)
4. Click **Add Sender**

### Flattening SPF Records

1. On the **Domains** tab, click **⚡ Flatten** for your domain
2. The tool will:
   - Query DNS for all `include:` domains
   - Recursively resolve nested includes
   - Collect all `ip4:` and `ip6:` entries
   - Deduplicate and build a flattened record
3. Click **📋 View** to see the flattened SPF record
4. Copy the record to your DNS provider

### Automatic Updates (Cron)

The cron job (`cron/auto-update.php`) replicates cfspflat's automated functionality:

```bash
# Check every hour, no email notifications
php /path/to/spf-flattener/cron/auto-update.php --no-email

# Force update even if no changes detected
php /path/to/spf-flattener/cron/auto-update.php --force

# With email notifications
php /path/to/spf-flattener/cron/auto-update.php
```

To enable auto-updates in Cloudflare:
1. Go to **Configuration** tab
2. Add your Cloudflare API email and key
3. Set `AUTO_UPDATE_ENABLED` to `true` in `config/config.local.php`

## CLI Usage

The command-line interface provides full functionality without the web GUI:

```bash
# List all domains
php cli.php list

# Import SPF record from DNS
php cli.php import --domain=example.com

# Import and add domain if it doesn't exist
php cli.php import --domain=newdomain.com --add

# Flatten SPF record
php cli.php flatten --domain=example.com

# Check for changes
php cli.php check --domain=example.com

# Test DNS lookup (debug)
php cli.php dns-test --domain=google.com

# Set configuration
php cli.php config --set cloudflare_api_email=user@example.com

# Show help
php cli.php help
```

## How It Works

### SPF Import Process

1. **DNS Query**: Uses `dig` to fetch TXT records for the domain
2. **SPF Detection**: Finds the record starting with `v=spf1`
3. **Parsing**: Extracts all mechanisms:
   - `include:` domains
   - `a:` and `mx:` mechanisms
   - `ip4:` and `ip6:` entries
   - `redirect=` targets
4. **Database Entry**: Creates sending domain and approved sender records
5. **Lookup Count**: Calculates total DNS lookups (must be ≤10)

### SPF Flattening Process

1. **Parse Original SPF**: Extract all mechanisms from your SPF record
2. **Count Lookups**: Identify `include:`, `a:`, `mx:`, `ptr:`, `exists:`, and `redirect=` mechanisms
3. **Resolve Includes**: For each `include:` domain:
   - Fetch its SPF record
   - Extract `ip4:` and `ip6:` entries
   - Recursively resolve nested includes
4. **Collect A/MX Records**: Resolve `a:` and `mx:` mechanisms to IPs
5. **Deduplicate**: Remove duplicate IP addresses
6. **Build Record**: Create new SPF record with only `ip4:` and `ip6:` entries
7. **Validate**: Ensure record is under 255 characters (or split if needed)

### DNS Caching

To reduce DNS query load:
- Results are cached in the database
- Default TTL: 1 hour (configurable via `DNS_CACHE_TTL`)
- Cache is checked before each DNS query

### Change Detection

The cron job detects changes by:
1. Re-flattening the domain
2. Comparing new IPs with stored IPs
3. Identifying added/removed IPs
4. Notifying if changes are found

## Database Schema

### Tables

- **domains**: Main domains being managed
- **sending_domains**: Subdomains that send email
- **approved_senders**: SPF include mechanisms to flatten
- **flattened_ips**: Resolved IP addresses
- **change_log**: History of SPF record changes
- **email_queue**: Pending email notifications
- **dns_cache**: DNS query cache
- **config**: Application configuration

## Configuration

### config/config.php

Main configuration file. Do not edit directly - use `config/config.local.php` for overrides.

### config/config.local.php

Local overrides (created by installer):

```php
// Database
define('DB_HOST', 'localhost');
define('DB_NAME', 'spf_flattener');
define('DB_USER', 'your_user');
define('DB_PASS', 'your_password');

// Cloudflare (optional)
define('CLOUDFLARE_API_EMAIL', 'your@email.com');
define('CLOUDFLARE_API_KEY', 'your_api_key');

// Email (optional)
define('SMTP_SERVER', 'smtp.example.com');
define('SMTP_PORT', 587);
define('SMTP_FROM_EMAIL', 'noreply@example.com');

// Auto-update
define('AUTO_UPDATE_ENABLED', true);
define('AUTO_UPDATE_INTERVAL', 3600);
```

## Comparison with cfspflat

| Feature | cfspflat | SPF Flattener |
|---------|----------|---------------|
| Interface | CLI only | Web GUI + CLI |
| SPF Import | Manual config | DNS auto-import |
| Configuration | JSON file | Database + Web UI |
| DNS Provider | Cloudflare only | Any (manual) + Cloudflare (auto) |
| Automation | Cron + script | Built-in cron job |
| Notifications | Email | Email + Dashboard |
| Multi-domain | Config file | Web UI |
| Change Detection | Email alert | Email + Dashboard + Log |
| DNS Cache | File-based | Database |

## Troubleshooting

### "dig command not found"

Install DNS utilities:
```bash
# Debian/Ubuntu
apt install dnsutils

# RHEL/CentOS
yum install bind-utils

# Alpine
apk add bind-tools
```

### "Database connection failed"

- Check MySQL is running
- Verify credentials in `config/config.local.php`
- Ensure database user has permissions

### "No SPF record found"

- Verify the domain has a TXT record with SPF
- Check DNS propagation: `dig TXT example.com`
- Some domains use `redirect=` instead of includes

### "Record exceeds 255 characters"

- SPF records have a 255-character limit per TXT record
- Options:
  1. Remove unnecessary senders
  2. Use DNS chaining (multiple TXT records)
  3. Use a hosted SPF service

### Cloudflare update fails

- Verify API email and key are correct
- Ensure Zone ID is set for the domain
- Check Cloudflare API permissions (Zone:DNS:Edit)

## Security

- **Never commit** `config/config.local.php` to version control
- Use HTTPS in production
- Restrict access to the web interface
- Keep PHP and MySQL updated
- Use strong passwords for database and Cloudflare API

## API Endpoints

### import_spf.php

AJAX endpoints for DNS import:

- `POST action=test_dns` - Test DNS lookup
- `POST action=fetch_spf&domain=example.com` - Fetch SPF record
- `POST action=import&domain_id=1` - Import for existing domain
- `POST action=add_and_import&domain=example.com` - Add and import

## License

MIT License - See LICENSE file for details

## Credits

This tool replicates the functionality of:
- [cfspflat](https://github.com/Glocktober/cfspflat) by Glocktober
- [sender-policy-flattener](https://github.com/cetanu/sender_policy_flattener) by cetanu

Inspired by their excellent work on automated SPF flattening.

## Support

For issues, feature requests, or questions, please open an issue on GitHub.
