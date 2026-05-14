<?php
// CWE-78: OS Command Injection - Safe Pattern
// Rule: php-command-injection-exec
// Expected: TrueNegative

// SAFE: Using escapeshellarg() to sanitize user input
$filename = escapeshellarg($_GET['filename']);
exec("convert " . $filename . " output.png");

// SAFE: Validate input against allowlist before use
$allowed_sizes = ['800x600', '1024x768', '1920x1080'];
$size = $_POST['size'];
if (in_array($size, $allowed_sizes)) {
    exec("mogrify -resize " . escapeshellarg($size) . " image.jpg");
}

// SAFE: Static command, no user input
$output = shell_exec("ls /var/log");
echo htmlspecialchars($output);
?>
