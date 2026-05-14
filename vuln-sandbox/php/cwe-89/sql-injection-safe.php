<?php
// CWE-89: SQL Injection - Safe Pattern
// Rule: php-sql-string-concat
// Expected: TrueNegative

$pdo = new PDO("mysql:host=localhost;dbname=db", "user", "pass");

// SAFE: Using PDO prepared statements with bound parameters
$id = $_GET['id'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
$result = $stmt->fetchAll();

// SAFE: Named parameters
$username = $_POST['username'];
$stmt2 = $pdo->prepare("SELECT * FROM accounts WHERE username = :username");
$stmt2->execute([':username' => $username]);
?>
