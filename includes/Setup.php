<?php
/**
 * Installation helper
 *
 * Used by setup.php to verify database credentials, import the schema and
 * write config/config.local.php — the same work install.sh does, but from
 * the browser so no shell access is required.
 */

require_once __DIR__ . '/Security.php';

class Setup {

    /** @var array Collected errors */
    public $errors = [];

    /** @var array Informational messages */
    public $notes = [];

    /* --------------------------------------------------------
     * Environment checks
     * ------------------------------------------------------ */

    /**
     * Is the local configuration file present?
     */
    public static function localConfigExists() {
        return is_readable(__DIR__ . '/../config/config.local.php');
    }

    /**
     * Has the installer been completed?
     *
     * Installation is only finished once the database is reachable, the
     * schema is present AND at least one user exists. Without the user
     * check, setup.php would redirect away before the administrator could
     * be created, leaving the application with no way to sign in.
     */
    public static function isInstalled() {
        if (!self::localConfigExists()) {
            return false;
        }
        if (!defined('SETUP_COMPLETE') || !SETUP_COMPLETE) {
            return false;
        }

        try {
            $pdo = new PDO(
                self::dsnFromConfig(),
                DB_USER,
                DB_PASS,
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 5]
            );
            if (!self::schemaPresent($pdo)) {
                return false;
            }
            // A user must exist, otherwise nobody can sign in.
            return ((int) $pdo->query("SELECT COUNT(*) FROM users WHERE is_active = 1")->fetchColumn()) > 0;
        } catch (Throwable $e) {
            return false;
        }
    }

    /**
     * The database is connected and its schema is present, but no
     * administrator account has been created yet.
     */
    public static function needsAdminUser() {
        if (!self::localConfigExists() || !defined('SETUP_COMPLETE')) {
            return false;
        }
        try {
            $pdo = new PDO(
                self::dsnFromConfig(),
                DB_USER,
                DB_PASS,
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 5]
            );
            if (!self::schemaPresent($pdo)) {
                return false;
            }
            return ((int) $pdo->query("SELECT COUNT(*) FROM users")->fetchColumn()) === 0;
        } catch (Throwable $e) {
            return false;
        }
    }

    /**
     * Is the schema installed? Requires a live connection.
     *
     * Checks against the database the connection is actually using, rather
     * than a name read from configuration — during installation the config
     * file may not yet reflect the database being created.
     *
     * @param PDO         $pdo
     * @param string|null $dbName Defaults to the connection's current database
     */
    public static function schemaPresent(PDO $pdo, $dbName = null) {
        try {
            if ($dbName === null) {
                $dbName = (string) $pdo->query('SELECT DATABASE()')->fetchColumn();
            }
            if ($dbName === '') {
                return false;
            }

            $stmt = $pdo->prepare("
                SELECT COUNT(*) FROM information_schema.tables
                 WHERE table_schema = ? AND table_name IN ('users', 'domains', 'audit_log', 'spf_records')
            ");
            $stmt->execute([$dbName]);
            return ((int) $stmt->fetchColumn()) === 4;
        } catch (Throwable $e) {
            return false;
        }
    }

    /**
     * Are we running with the shipped placeholder credentials?
     */
    public static function isPlaceholderConfig() {
        return (defined('DB_USER') && DB_USER === 'root' && defined('DB_PASS') && DB_PASS === '')
            || !self::localConfigExists();
    }

    /* --------------------------------------------------------
     * Actions
     * ------------------------------------------------------ */

    /**
     * Try to connect with the supplied settings.
     *
     * @return array{success:bool,error?:string,server_version?:string,db_exists?:bool,schema?:bool}
     */
    public function testConnection($host, $port, $user, $pass, $name) {
        // First connect without a database, so we can report whether it exists.
        try {
            $pdo = new PDO(
                $this->dsn($host, $port, null),
                $user,
                $pass,
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 5]
            );
        } catch (Throwable $e) {
            return ['success' => false, 'error' => 'Could not connect to the database server: ' . $e->getMessage()];
        }

        $version = 'unknown';
        try {
            $version = (string) $pdo->query('SELECT VERSION()')->fetchColumn();
        } catch (Throwable $e) {
            // not fatal
        }

        // Does the target database exist?
        $dbExists = false;
        try {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name = ?");
            $stmt->execute([$name]);
            $dbExists = ((int) $stmt->fetchColumn()) > 0;
        } catch (Throwable $e) {
            // ignore
        }

        $schema = false;
        if ($dbExists) {
            try {
                $pdo2 = new PDO(
                    $this->dsn($host, $port, $name),
                    $user,
                    $pass,
                    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 5]
                );
                $schema = self::schemaPresent($pdo2, $name);
            } catch (Throwable $e) {
                // ignore
            }
        }

        return [
            'success'         => true,
            'server_version'  => $version,
            'db_exists'       => $dbExists,
            'schema'          => $schema,
        ];
    }

    /**
     * Run the full installation.
     *
     * @return array{success:bool,error?:string,created_db?:bool,created_schema?:bool}
     */
    public function install($host, $port, $user, $pass, $name) {
        if (!preg_match('/^[A-Za-z0-9_]{1,64}$/', $name)) {
            return ['success' => false, 'error' => 'The database name may only contain letters, numbers and underscores.'];
        }
        if (!is_writable(dirname(__DIR__) . '/config')) {
            return ['success' => false, 'error' => 'The config/ directory is not writable. Run: chmod 775 config'];
        }

        // 1. Connect to the server.
        try {
            $pdo = new PDO(
                $this->dsn($host, $port, null),
                $user,
                $pass,
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 10]
            );
        } catch (Throwable $e) {
            return ['success' => false, 'error' => 'Could not connect to the database server: ' . $e->getMessage()];
        }

        // 2. Create the database if needed.
        $createdDb = false;
        try {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name = ?");
            $stmt->execute([$name]);
            if ((int) $stmt->fetchColumn() === 0) {
                $pdo->exec("CREATE DATABASE `{$name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
                $createdDb = true;
            }
        } catch (Throwable $e) {
            return ['success' => false, 'error' => 'Could not create the database: ' . $e->getMessage()];
        }

        // 3. Import the schema.
        try {
            $pdo = new PDO(
                $this->dsn($host, $port, $name),
                $user,
                $pass,
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 10]
            );
        } catch (Throwable $e) {
            return ['success' => false, 'error' => 'Could not open the database: ' . $e->getMessage()];
        }

        $schemaFile = dirname(__DIR__) . '/config/database.sql';
        if (!is_readable($schemaFile)) {
            return ['success' => false, 'error' => 'config/database.sql is missing or unreadable.'];
        }

        try {
            $createdSchema = $this->runSqlFile($pdo, $schemaFile, $name);
        } catch (Throwable $e) {
            return ['success' => false, 'error' => 'Failed to import the schema: ' . $e->getMessage()];
        }

        // 4. Write the configuration file.
        try {
            $this->writeLocalConfig($host, $port, $user, $pass, $name);
        } catch (Throwable $e) {
            return ['success' => false, 'error' => 'Failed to write config/config.local.php: ' . $e->getMessage()
                . ' — check that config/ is writable.'];
        }

        // 5. Confirm the tables are reachable.
        if (!self::schemaPresent($pdo, $name)) {
            return ['success' => false, 'error' => 'The schema was applied but the expected tables are missing.'];
        }

        return ['success' => true, 'created_db' => $createdDb, 'created_schema' => $createdSchema];
    }

    /**
     * Execute a .sql file statement by statement.
     *
     * Deliberately avoids shelling out to the mysql client so the web
     * installer works on hosts without CLI database access.
     *
     * @return bool Whether any table was created or an INSERT/ALTER ran
     */
    private function runSqlFile(PDO $pdo, $file, $dbName) {
        $sql = file_get_contents($file);
        if ($sql === false) {
            throw new RuntimeException('Could not read the schema file.');
        }

        $statements = $this->splitSql($sql);
        $created = false;

        foreach ($statements as $statement) {
            $trimmed = trim($statement);
            if ($trimmed === '') {
                continue;
            }

            // The dump contains "USE <name>". Executing it would redirect the
            // import into the shipped default database rather than the one the
            // operator chose, so drop it.
            if (preg_match('/^\s*USE\s+/i', $trimmed)) {
                continue;
            }

            try {
                $pdo->exec($trimmed);
            } catch (PDOException $e) {
                // "already exists" is expected on a re-run and is harmless.
                $code = $e->errorInfo[1] ?? 0;
                $msg  = $e->getMessage();
                $benign = in_array($code, [1050, 1061, 1062, 1826], true)
                    || stripos($msg, 'already exists') !== false
                    || stripos($msg, 'Duplicate') !== false;

                if (!$benign) {
                    throw new RuntimeException($msg);
                }
            }
        }

        return $created;
    }

    /**
     * Split a SQL dump into individual statements, honouring quotes and
     * comments. Good enough for the bundled schema.
     */
    private function splitSql($sql) {
        $statements = [];
        $current = '';
        $len = strlen($sql);
        $inSingle = false;
        $inDouble = false;
        $inBacktick = false;
        $inLineComment = false;
        $inBlockComment = false;

        for ($i = 0; $i < $len; $i++) {
            $ch   = $sql[$i];
            $next = ($i + 1 < $len) ? $sql[$i + 1] : '';

            if ($inLineComment) {
                if ($ch === "\n") {
                    $inLineComment = false;
                    $current .= $ch;
                }
                continue;
            }
            if ($inBlockComment) {
                if ($ch === '*' && $next === '/') {
                    $inBlockComment = false;
                    $i++;
                }
                continue;
            }

            if (!$inSingle && !$inDouble && !$inBacktick) {
                if ($ch === '-' && $next === '-') {
                    $inLineComment = true;
                    $i++;
                    continue;
                }
                if ($ch === '#') {
                    $inLineComment = true;
                    continue;
                }
                if ($ch === '/' && $next === '*') {
                    $inBlockComment = true;
                    $i++;
                    continue;
                }
            }

            if ($ch === "'" && !$inDouble && !$inBacktick) {
                $inSingle = !$inSingle;
            } elseif ($ch === '"' && !$inSingle && !$inBacktick) {
                $inDouble = !$inDouble;
            } elseif ($ch === '`' && !$inSingle && !$inDouble) {
                $inBacktick = !$inBacktick;
            }

            if ($ch === ';' && !$inSingle && !$inDouble && !$inBacktick) {
                $statements[] = $current;
                $current = '';
                continue;
            }

            $current .= $ch;
        }

        if (trim($current) !== '') {
            $statements[] = $current;
        }

        return $statements;
    }

    /**
     * Write config/config.local.php.
     */
    private function writeLocalConfig($host, $port, $user, $pass, $name) {
        $configDir = dirname(__DIR__) . '/config';
        $target = $configDir . '/config.local.php';

        // Refuse to clobber an existing working configuration.
        if (file_exists($target) && !self::isPlaceholderConfig()) {
            throw new RuntimeException('config/config.local.php already exists and appears to be configured.');
        }

        $q = fn($v) => "'" . str_replace(["\\", "'"], ["\\\\", "\\'"], (string) $v) . "'";

        $template = "<?php\n"
            . "/**\n"
            . " * Local configuration — generated by the web installer on %s\n"
            . " *\n"
            . " * This file is excluded from version control.\n"
            . " */\n\n"
            . "define('SETUP_COMPLETE', true);\n\n"
            . "define('DB_HOST', %s);\n"
            . "define('DB_PORT', %d);\n"
            . "define('DB_NAME', %s);\n"
            . "define('DB_USER', %s);\n"
            . "define('DB_PASS', %s);\n"
            . "define('DB_CHARSET', 'utf8mb4');\n\n"
            . "// Set APP_DEBUG to false once the installation is verified.\n"
            . "define('APP_DEBUG', false);\n\n"
            . "define('AUTO_UPDATE_ENABLED', false);\n";

        $contents = sprintf(
            $template,
            gmdate('Y-m-d H:i:s') . ' UTC',
            $q($host),
            (int) $port,
            $q($name),
            $q($user),
            $q($pass)
        );

        if (file_put_contents($target, $contents, LOCK_EX) === false) {
            throw new RuntimeException('Could not write the file.');
        }
        @chmod($target, 0640);
    }

    /* --------------------------------------------------------
     * DSN helpers
     * ------------------------------------------------------ */

    private function dsn($host, $port, $dbName) {
        $hostPart = $host;
        if ($port) {
            $hostPart .= ';port=' . (int) $port;
        }
        $dsn = 'mysql:host=' . $hostPart;
        if ($dbName !== null) {
            $dsn .= ';dbname=' . $dbName;
        }
        return $dsn . ';charset=utf8mb4';
    }

    private static function dsnFromConfig() {
        $host = defined('DB_HOST') ? DB_HOST : 'localhost';
        if (defined('DB_SOCKET') && DB_SOCKET !== '') {
            return 'mysql:unix_socket=' . DB_SOCKET . ';dbname=' . DB_NAME . ';charset=utf8mb4';
        }
        if (defined('DB_PORT') && DB_PORT) {
            $host .= ';port=' . (int) DB_PORT;
        }
        return 'mysql:host=' . $host . ';dbname=' . DB_NAME . ';charset=utf8mb4';
    }

    private static function databaseFromConfig() {
        return defined('DB_NAME') ? DB_NAME : '';
    }
}
