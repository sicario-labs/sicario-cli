<?php
// CWE-22: Path Traversal - Safe Pattern
// Rule: php-path-traversal-file-get-contents
// Expected: TrueNegative

define('UPLOAD_DIR', '/uploads/');

// SAFE: Validate path stays within allowed directory
$filename = basename($_GET['file']);
$safe_path = realpath(UPLOAD_DIR . $filename);
if ($safe_path && strpos($safe_path, realpath(UPLOAD_DIR)) === 0) {
    $content = file_get_contents($safe_path);
    echo htmlspecialchars($content);
} else {
    http_response_code(403);
    echo "Access denied";
}

// SAFE: Static path, no user input
$log = file_get_contents('/var/log/app.log');
echo htmlspecialchars($log);
?>
