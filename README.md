# ATS Solutions — SPF Flattener

A PHP / MySQL web application for flattening SPF records, replicating the
functionality of [cfspflat](https://github.com/Glocktober/cfspflat) behind a
branded web GUI with username / password authentication.

---

## Features

**SPF flattening (cfspflat parity)**
- Resolves `include:` chains recursively to concrete `ip4:` / `ip6:` entries
- Handles `a:`, `mx:` and `redirect=` mechanisms
- Counts DNS lookups per RFC 7208 (10-lookup limit)
- Deduplicates addresses and sorts IPv4 before IPv6
- Emits the root record plus chained `spf<n>.<domain>` sub-records when the
  address set will not fit inside the 255-character TXT limit

**DNS import**
- Fetches the live SPF record over DNS (`dig`, with `nslookup` fallback)
- Parses every mechanism and reports the lookup count before you publish
- Imports `include:` **and** direct `ip4:` / `ip6:` entries as senders, so
  nothing is dropped when the record is rebuilt
- Reconstructs multi-chunk TXT records correctly
- Recognises common senders (Google, Microsoft 365, SendGrid, Mailchimp…)

**Authentication & accountability**
- Username / password sign-in with Argon2id (bcrypt fallback) hashing
- Brute-force lockout after 5 failed attempts (15 minutes)
- Hardened sessions: ID regeneration, idle timeout, UA+IP fingerprint binding,
  `HttpOnly` / `SameSite=Lax` cookies
- Three roles — `admin`, `operator`, `viewer`
- Password policy: 10+ chars with upper, lower, digit and symbol
- Audit log recording **date/time, username, action, IP address and detail**
  for every sign-in, change and SPF operation
- CSRF tokens on every state-changing request

**Operations**
- Cloudflare DNS publishing (`--update-records` equivalent)
- Change detection with email notifications
- Cron job for scheduled re-flattening
- DNS result caching
- Full CLI for headless use

**Design**
- ATS Solutions branding: `#0079b8` primary, `#00d4ff` accent, `#0a1520` dark
- Inter typeface
- The dark hero/login surfaces carry the ATS isometric cube lattice, drawn
  on canvas exactly as on dev.ats.solutions

---

## Requirements

- PHP 7.4+ (8.x recommended) with `pdo_mysql`
- MySQL 5.7+ or MariaDB 10.3+
- `dig` — `apt install dnsutils` or `yum install bind-utils`
- A web server (Apache / Nginx / PHP-FPM), or `php -S` for local use

---

## Installation

```bash
cd /var/www/html
git clone https://github.com/LightNetAI/spf-flattener.git
cd spf-flattener
chmod +x install.sh
./install.sh
```

The installer:

1. Verifies PHP, `pdo_mysql`, the MySQL client and `dig`
2. Creates the database and imports the schema (including the `users` and
   `audit_log` tables)
3. Writes `config/config.local.php` (mode 640) with your credentials
4. **Creates the first administrator account** — you are prompted for the
   username and password
5. Optionally installs the cron job

Then open the app and sign in with the account you just created.

### Manual installation

```bash
mysql -u root -p < config/database.sql
cp config/config.php config/config.local.php   # then edit it
php cli.php user:add --username=admin --role=admin
php -S 127.0.0.1:8080                          # or point your web server here
```

---

## Signing in

Access to every page requires authentication. Unauthenticated requests are
redirected to `login.php`; unauthenticated AJAX calls receive `401`.

If no users exist yet, the login page tells you to create one from the CLI.

### Creating users

```bash
# Interactive (password typed without echo)
php cli.php user:add --username=admin --role=admin

# Non-interactive
php cli.php user:add --username=jane --role=operator --password='Str0ng!Passw0rd'

php cli.php user:list
php cli.php user:passwd --username=jane
php cli.php audit --id=50
```

Administrators can also create users and reset passwords from **Users** in
the web interface. Users change their own password under **Account**.

### Roles

| Role       | View | Flatten / import / delete | Settings | Users |
|------------|:----:|:-------------------------:|:--------:|:-----:|
| `admin`    |  ✓   |            ✓              |    ✓     |   ✓   |
| `operator` |  ✓   |            ✓              |          |       |
| `viewer`   |  ✓   |                           |          |       |

---

## CLI reference

```
php cli.php flatten --domain=example.com     Flatten a domain
php cli.php check   --domain=example.com     Report IP additions/removals
php cli.php import  --domain=example.com     Import SPF from DNS
php cli.php import  --domain=new.com --add   Import, creating the domain first
php cli.php list                             List configured domains
php cli.php dns-test --domain=google.com     Diagnose DNS lookups
php cli.php config  --set key=value          Read or write settings
php cli.php user:add --username=admin        Create an account
php cli.php user:list                        List accounts
php cli.php user:passwd --username=admin     Change a password
php cli.php audit   --id=50                  Recent audit entries
```

---

## The audit log

Every entry records the timestamp, username, action, source IP, user agent and
a human-readable detail:

| Date / Time         | User  | Action        | Detail                                  | IP        |
|---------------------|-------|---------------|-----------------------------------------|-----------|
| 2026-10-01 10:53:24 | admin | SPF_FLATTENED | Flattened github.com: 51 IP(s), 8 → 0.  | 127.0.0.1 |
| 2026-10-01 10:52:09 | jane  | LOGIN_FAIL    | Account locked                          | 127.0.0.1 |

Actions include `LOGIN_SUCCESS`, `LOGIN_FAIL`, `LOGOUT`, `SESSION_TIMEOUT`,
`SESSION_INVALID`, `ACCESS_DENIED`, `DOMAIN_ADDED`, `DOMAIN_DELETED`,
`SENDER_ADDED`, `SENDER_DELETED`, `SPF_FETCHED`, `SPF_IMPORTED`,
`SPF_FLATTENED`, `FLATTEN_FAILED`, `CLOUDFLARE_PUSHED`,
`CLOUDFLARE_PUSH_FAILED`, `CHANGE_DETECTED`, `CONFIG_UPDATED`,
`USER_CREATED`, `USER_ENABLED`, `USER_DISABLED`, `PASSWORD_CHANGED` and
`PASSWORD_RESET`.

Scheduled runs are attributed to `system@cron`.

---

## How flattening works

1. Read the configured senders for the domain
2. For each sender, resolve to addresses:
   - `include:` → fetch that domain's SPF record and recurse
   - `ip4:` / `ip6:` → used directly, no lookup
   - `a:` / `mx:` → resolve A/AAAA or MX hosts
   - no SPF record on the include target → fall back to its A/AAAA records
3. Deduplicate and order (IPv4 first)
4. Pack into 255-character TXT records; if more than one chunk is needed,
   publish `spf0.<domain>`, `spf1.<domain>`… and chain them from the root
5. Store the record and individual addresses

`ptr:` and `exists:` cannot be flattened to a static list and are ignored.

> **Note:** flattening freezes a snapshot of each provider's ranges. Re-run
> on a schedule (the cron job does this) whenever a provider changes
> infrastructure.

---

## Configuration

Defaults live in `config/config.php`. Machine-specific values belong in
`config/config.local.php`, which is loaded first, is git-ignored, and
overrides the defaults.

```php
define('DB_HOST', '127.0.0.1');
define('DB_NAME', 'spf_flattener');
define('DB_USER', 'spf');
define('DB_PASS', '…');

define('APP_URL', 'https://spf.example.com');
define('APP_DEBUG', false);          // never true in production

define('AUTO_UPDATE_ENABLED', true); // publish to Cloudflare automatically
```

Cloudflare credentials and SMTP settings are managed in the web UI under
**Settings** (admin only) and stored in the `config` table.

---

## Scheduled runs

```bash
php cron/auto-update.php --no-email   # detect changes, do not email
php cron/auto-update.php --force      # re-flatten regardless
php cron/auto-update.php              # full run with notifications
```

Detected changes are written to the audit log and, when
`AUTO_UPDATE_ENABLED` is set, published to Cloudflare automatically.

---

## Security

- All database access uses PDO prepared statements
- All output is HTML-escaped
- Domain input is validated against a strict character class before being
  passed to `dig`, and arguments are additionally escaped with
  `escapeshellarg()` — command injection is not possible
- Passwords are hashed with Argon2id / bcrypt
- CSRF tokens protect every state-changing request
- Responses carry `Content-Security-Policy`, `X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy` and `Permissions-Policy`;
  `X-Powered-By` is removed
- `config/config.local.php` is excluded from version control

See `SECURITY_AUDIT.md` for the full assessment.

---

## Database schema

| Table             | Purpose                                        |
|-------------------|------------------------------------------------|
| `users`           | Accounts, hashes, roles, lockout state          |
| `audit_log`       | Timestamp / user / action / IP / detail         |
| `config`          | Application settings                            |
| `domains`         | Zones being managed and their flattened records |
| `sending_domains` | Envelope domains per zone                       |
| `approved_senders`| `include:` and `ip4:`/`ip6:` authorisations     |
| `flattened_ips`   | Resolved addresses                              |
| `change_log`      | Detected IP additions / removals                |
| `email_queue`     | Pending notifications                           |
| `dns_cache`       | Cached DNS answers                              |

---

## Credits

- [cfspflat](https://github.com/Glocktober/cfspflat) by Glocktober
- [sender-policy-flattener](https://github.com/cetanu/sender_policy_flattener)
  by cetanu

## Licence

MIT
