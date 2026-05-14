<?php
// CWE-918: Server-Side Request Forgery - Safe Pattern
// Rule: php-ssrf-curl-user-url
// Expected: TrueNegative

$allowed_hosts = ['api.example.com', 'api.trusted.com'];

// SAFE: Validate URL against allowlist before making request
$url = $_GET['url'];
$parsed = parse_url($url);
if (!in_array($parsed['host'] ?? '', $allowed_hosts)) {
    http_response_code(403);
    exit("Unauthorized host");
}

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "https://api.example.com/data");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($ch);
curl_close($ch);
echo htmlspecialchars($response);
?>
