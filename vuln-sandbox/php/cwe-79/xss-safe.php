<?php
// CWE-79: Cross-Site Scripting - Safe Pattern
// Rule: php-xss-echo-user-input
// Expected: TrueNegative

// SAFE: HTML-encode user input before output
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');

// SAFE: Using htmlentities for full encoding
echo htmlentities($_POST['message'], ENT_QUOTES, 'UTF-8');

// SAFE: Static content, no user input
echo "Welcome to our application!";
?>
