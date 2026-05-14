<?php
// CWE-89: SQL Injection via String Concatenation in PHP
// Rule: php-sql-string-concat
// Expected: TruePositive

$conn = new mysqli("localhost", "user", "pass", "db");

// VULNERABLE: User input concatenated into SQL query
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $id;
$result = $conn->query($query);

// VULNERABLE: String concatenation with POST data
$username = $_POST['username'];
$sql = "SELECT * FROM accounts WHERE username = '" . $username . "'";
$conn->query($sql);
?>
