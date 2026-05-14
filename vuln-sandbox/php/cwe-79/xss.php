<?php
// CWE-79: Cross-Site Scripting via echo with unescaped user input
// Rule: php-xss-echo-user-input
// Expected: TruePositive

// VULNERABLE: Echoing GET parameter without encoding
echo $_GET['name'];

// VULNERABLE: Echoing POST data directly
echo $_POST['message'];

// VULNERABLE: Echoing REQUEST data
echo $_REQUEST['search'];
?>
