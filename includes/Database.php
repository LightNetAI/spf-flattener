<?php
/**
 * Database Connection Class
 * Singleton pattern for database connections
 */

class Database {
    private static $instance = null;
    private $connection;
    
    private function __construct() {
        try {
            // Allow a socket or non-default port for local/test deployments.
            // When a unix socket is configured, omit the host entirely —
            // supplying an IP alongside a socket makes mysqlnd use TCP.
            if (defined('DB_SOCKET') && DB_SOCKET !== '') {
                $dsn = "mysql:unix_socket=" . DB_SOCKET . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
            } else {
                $host = DB_HOST;
                if (defined('DB_PORT') && DB_PORT) {
                    $host .= ';port=' . DB_PORT;
                }
                $dsn = "mysql:host=" . $host . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
            }
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ];
            
            $this->connection = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            throw new Exception("Database connection failed. Please check your configuration.");
        }
    }
    
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    public function getConnection() {
        return $this->connection;
    }
    
    // Prevent cloning
    private function __clone() {}
    
    // Prevent unserialization
    public function __wakeup() {
        throw new Exception("Cannot unserialize singleton");
    }
}

/**
 * Get database connection
 */
function getDB() {
    return Database::getInstance()->getConnection();
}
