<?php
// CWE-798: Hardcoded Credentials in PHP
// Rule: php-hardcoded-secret
// Expected: TruePositive

// VULNERABLE: Hardcoded database password
$password = "db_password_hardcoded_123";

// VULNERABLE: Hardcoded API key
$api_key = "sk-prod-1234567890abcdef";

// VULNERABLE: Hardcoded JWT secret
$secret_key = "super_secret_jwt_signing_key";

class DatabaseConfig {
    // VULNERABLE: Hardcoded credentials in class
    private $token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
}
?>
