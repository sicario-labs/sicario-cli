<?php
// CWE-22: Path Traversal via include/file_get_contents in PHP
// Rule: php-path-traversal-file-get-contents
// Expected: TruePositive

// VULNERABLE: User-controlled filename in file_get_contents
$filename = $_GET['file'];
$content = file_get_contents("/uploads/$filename");
echo $content;

// VULNERABLE: User input in fopen
$path = $_REQUEST['path'];
$handle = fopen("/data/$path", 'r');
if ($handle) {
    echo fread($handle, filesize("/data/$path"));
    fclose($handle);
}
?>
