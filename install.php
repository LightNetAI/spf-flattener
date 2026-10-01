<?php

// Read a line without echoing (for passwords).
function promptPassword($label) {
    echo $label;

    $isTty = function_exists('stream_isatty') && defined('STDIN') && @stream_isatty(STDIN);

    if (stripos(PHP_OS, 'WIN') === 0 || !$isTty) {
        // Not a terminal (piped input, cron, CI): read normally.
        return trim((string) fgets(STDIN));
    }

    shell_exec('stty -echo 2>/dev/null');
    $value = trim((string) fgets(STDIN));
    shell_exec('stty echo 2>/dev/null');
    echo "\n";
    return $value;
}

// Validate a password against the application policy (kept in step with
// Auth::validatePasswordPolicy).
function validatePolicy($password) {
    if (strlen($password) < 10) return 'must be at least 10 characters long';
    if (!preg_match('/[A-Z]/', $password)) return 'must contain an uppercase letter';
    if (!preg_match('/[a-z]/', $password)) return 'must contain a lowercase letter';
    if (!preg_match('/[0-9]/', $password)) return 'must contain a number';
    if (!preg_match('/[^A-Za-z0-9]/', $password)) return 'must contain a symbol';
    return null;
}

echo "\n";
echo "==============================================\n";
echo "   ATS Solutions - SPF Flattener installer\n";
echo "==============================================\n\n";

$root = __DIR__;

// ---- Preflight -------------------------------------------------
echo "Checking prerequisites...\n";

$phpOk = version_compare(PHP_VERSION, '7.4.0', '>=');
printf("  %s PHP %s\n", $phpOk ? '[ok]' : '[!!]', PHP_VERSION);
if (!$phpOk) {
    fwrite(STDERR, "PHP 7.4 or newer is required.\n");
    exit(1);
}

$hasPdo = extension_loaded('pdo_mysql');
printf("  %s pdo_mysql extension\n", $hasPdo ? '[ok]' : '[!!]');
if (!$hasPdo) {
    fwrite(STDERR, "The pdo_mysql extension is required.\n");
    exit(1);
}

$hasDig = trim((string) @shell_exec('command -v dig 2>/dev/null')) !== '';
printf("  %s dig (DNS lookups)\n", $hasDig ? '[ok]' : '[--]');
if (!$hasDig) {
    echo "       Install dnsutils (Debian/Ubuntu) or bind-utils (RHEL); DNS lookups will fail without it.\n";
}
echo "\n";

// ---- Database --------------------------------------------------
echo "Database connection\n";

$defaultHost = 'localhost';
$defaultPort = '3306';
$defaultName = 'spf_flattener';

echo "  Host [{$defaultHost}]: ";
$host = trim(fgets(STDIN));
if ($host === '') $host = $defaultHost;

echo "  Port [{$defaultPort}]: ";
$port = trim(fgets(STDIN));
if ($port === '') $port = $defaultPort;

echo "  Username [root]: ";
$user = trim(fgets(STDIN));
if ($user === '') $user = 'root';

$pass = promptPassword('  Password: ');

echo "  Database name [{$defaultName}]: ";
$name = trim(fgets(STDIN));
if ($name === '') $name = $defaultName;

if (!preg_match('/^[A-Za-z0-9_]{1,64}$/', $name)) {
    fwrite(STDERR, "\nThe database name may only contain letters, numbers and underscores.\n");
    exit(1);
}

// Connect
echo "\n  Connecting... ";
try {
    $dsn = "mysql:host={$host};port={$port};charset=utf8mb4";
    $pdo = new PDO($dsn, $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_TIMEOUT => 10,
    ]);
    echo "connected to " . $pdo->query('SELECT VERSION()')->fetchColumn() . "\n";
} catch (Throwable $e) {
    fwrite(STDERR, "failed\n\n{$e->getMessage()}\n");
    exit(1);
}

// Create the database if needed
$stmt = $pdo->prepare("SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name = ?");
$stmt->execute([$name]);
if ((int) $stmt->fetchColumn() === 0) {
    $pdo->exec("CREATE DATABASE `{$name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    echo "  Created database '{$name}'\n";
} else {
    echo "  Database '{$name}' already exists\n";
}

// Import the schema
$schemaFile = $root . '/config/database.sql';
if (!is_readable($schemaFile)) {
    fwrite(STDERR, "config/database.sql is missing.\n");
    exit(1);
}

echo "  Importing schema... ";
try {
    $pdo = new PDO("mysql:host={$host};port={$port};dbname={$name};charset=utf8mb4", $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_TIMEOUT => 10,
    ]);

    // Strip comments and split on semicolons at end of line.
    $sql = file_get_contents($schemaFile);
    $sql = preg_replace('/^\s*--.*$/m', '', $sql);

    foreach (explode(";\n", $sql) as $statement) {
        $statement = trim($statement);
        if ($statement === '') continue;

        // The dump contains "USE <name>", and "CREATE DATABASE IF NOT EXISTS
        // <name>". Both would redirect the import into the shipped default
        // database instead of the one the operator chose.
        if (preg_match('/^\s*USE\s+/i', $statement)) {
            continue;
        }
        $statement = preg_replace(
            '/^\s*CREATE\s+DATABASE\s+IF\s+NOT\s+EXISTS\s+`?[A-Za-z0-9_]+`?/i',
            'CREATE DATABASE IF NOT EXISTS `' . $name . '`',
            $statement
        );

        try {
            $pdo->exec($statement);
        } catch (PDOException $e) {
            $msg = $e->getMessage();
            if (stripos($msg, 'already exists') === false && stripos($msg, 'Duplicate') === false) {
                throw $e;
            }
        }
    }
    echo "done\n";
} catch (Throwable $e) {
    fwrite(STDERR, "failed\n\n{$e->getMessage()}\n");
    exit(1);
}

// ---- Configuration file ---------------------------------------
$configDir = $root . '/config';
if (!is_writable($configDir)) {
    fwrite(STDERR, "\nThe config/ directory is not writable. Run: chmod 775 config\n");
    exit(1);
}

$quote = fn($v) => "'" . str_replace(["\\", "'"], ["\\\\", "\\'"], (string) $v) . "'";

$config = "<?php\n"
    . "/**\n"
    . " * Local configuration - generated by install.sh on " . gmdate('Y-m-d H:i:s') . " UTC\n"
    . " *\n"
    . " * Excluded from version control. Do not commit this file.\n"
    . " */\n\n"
    . "define('SETUP_COMPLETE', true);\n\n"
    . "define('DB_HOST', " . $quote($host) . ");\n"
    . "define('DB_PORT', " . (int) $port . ");\n"
    . "define('DB_NAME', " . $quote($name) . ");\n"
    . "define('DB_USER', " . $quote($user) . ");\n"
    . "define('DB_PASS', " . $quote($pass) . ");\n"
    . "define('DB_CHARSET', 'utf8mb4');\n\n"
    . "// Set APP_DEBUG to false once the installation is verified.\n"
    . "define('APP_DEBUG', false);\n\n"
    . "define('AUTO_UPDATE_ENABLED', false);\n";

file_put_contents($configDir . '/config.local.php', $config, LOCK_EX);
@chmod($configDir . '/config.local.php', 0640);
echo "  Wrote config/config.local.php (mode 640)\n";

// ---- Administrator account ------------------------------------
echo "\nAdministrator account\n";
echo "  The web interface requires a username and password.\n\n";

require_once $root . '/config/config.php';
require_once $root . '/includes/Database.php';
require_once $root . '/includes/Security.php';
require_once $root . '/includes/Auth.php';

$auth = new Auth();

for ($attempt = 1; $attempt <= 3; $attempt++) {
    echo "  Username [admin]: ";
    $adminUser = trim(fgets(STDIN));
    if ($adminUser === '') $adminUser = 'admin';

    echo "  Display name [Administrator]: ";
    $adminName = trim(fgets(STDIN));
    if ($adminName === '') $adminName = 'Administrator';

    echo "  Email (optional): ";
    $adminEmail = trim(fgets(STDIN));

    $adminPass  = promptPassword('  Password: ');
    $adminPass2 = promptPassword('  Confirm password: ');

    if ($adminPass !== $adminPass2) {
        echo "  [!!] The passwords do not match. Try again.\n\n";
        continue;
    }

    $problem = validatePolicy($adminPass);
    if ($problem !== null) {
        echo "  [!!] Password {$problem}. Try again.\n\n";
        continue;
    }

    $check = $auth->createUser($adminUser, $adminPass, 'admin', $adminEmail ?: null, $adminName);
    if (!$check['success']) {
        echo "  [!!] {$check['error']}\n\n";
        continue;
    }

    $auth->audit(null, $adminUser, 'INSTALL_COMPLETE', 'Initial administrator created by install.sh');
    echo "  [ok] Created administrator '{$adminUser}'\n";
    break;
}

if (!isset($check) || !$check['success']) {
    echo "\nThe administrator account was not created.\n";
    echo "Create one later with:\n";
    echo "  php cli.php user:add --username=admin --role=admin\n\n";
}

// ---- Directories ----------------------------------------------
if (!is_dir($root . '/logs')) {
    @mkdir($root . '/logs', 0755, true);
}
echo "  Log directory ready\n";

// ---- Cron -----------------------------------------------------
echo "\nScheduled flattening\n";
echo "  Install the auto-update cron job? (y/N): ";
$wantCron = trim(fgets(STDIN));

if (strtolower($wantCron) === 'y') {
    echo "  Interval in minutes [60]: ";
    $interval = trim(fgets(STDIN));
    if ($interval === '' || !ctype_digit($interval)) $interval = '60';

    $cronLine = "*/{$interval} * * * * php {$root}/cron/auto-update.php --no-email >> {$root}/logs/cron.log 2>&1";
    $existing = shell_exec('crontab -l 2>/dev/null');
    $existing = is_string($existing) ? preg_replace('/.*auto-update\.php.*\n?/', '', $existing) : '';
    $tmp = tempnam(sys_get_temp_dir(), 'cron');
    file_put_contents($tmp, $existing . $cronLine . "\n");
    shell_exec('crontab ' . escapeshellarg($tmp));
    @unlink($tmp);

    echo "  [ok] Cron installed (every {$interval} minutes)\n";
} else {
    echo "  Skipped. Add manually:\n";
    echo "    */60 * * * * php {$root}/cron/auto-update.php --no-email\n";
}

echo "\n==============================================\n";
echo "   Installation complete\n";
echo "==============================================\n\n";
echo "Open the application in a browser and sign in with the account above.\n\n";
echo "Useful commands:\n";
echo "  php cli.php user:list\n";
echo "  php cli.php user:add    --username=name --role=operator\n";
echo "  php cli.php user:passwd --username=name\n";
echo "  php cli.php audit --id=50\n\n";
