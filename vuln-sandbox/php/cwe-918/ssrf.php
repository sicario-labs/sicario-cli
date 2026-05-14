<?php
// CWE-918: Server-Side Request Forgery via curl in PHP
// Rule: php-ssrf-curl-user-url
// Expected: TruePositive

// VULNERABLE: User-controlled URL in curl request
$url = $_GET['url'];
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "https://api.example.com/$url");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($ch);
curl_close($ch);
echo $response;

// VULNERABLE: User input as full URL
$target = $_POST['target'];
$ch2 = curl_init();
curl_setopt($ch2, CURLOPT_URL, "http://$target/api/data");
curl_setopt($ch2, CURLOPT_RETURNTRANSFER, true);
$data = curl_exec($ch2);
curl_close($ch2);
?>
