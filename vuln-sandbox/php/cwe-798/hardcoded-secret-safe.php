<?php
// CWE-798: Hardcoded Credentials - Safe Pattern
// Rule: php-hardcoded-secret
// Expected: TrueNegative

// SAFE: Credentials loaded from environment variables
$password = getenv('DB_PASSWORD');

// SAFE: Using $_ENV superglobal
$api_key = $_ENV['API_KEY'];

// SAFE: Using a configuration file outside web root
$config = parse_ini_file('/etc/app/config.ini');
$secret_key = $config['secret_key'];

class DatabaseConfig {
    // SAFE: Reading from environment
    private $token;

    public function __construct() {
        $this->token = getenv('AUTH_TOKEN');
    }
}
?>
