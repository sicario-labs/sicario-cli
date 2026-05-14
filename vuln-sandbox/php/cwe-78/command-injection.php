<?php
// CWE-78: OS Command Injection via exec() in PHP
// Rule: php-command-injection-exec
// Expected: TruePositive

// VULNERABLE: User input passed directly to exec()
$filename = $_GET['filename'];
exec("convert $filename output.png");

// VULNERABLE: User input in system()
$size = $_POST['size'];
system("mogrify -resize $size image.jpg");

// VULNERABLE: User input in shell_exec()
$cmd = $_REQUEST['cmd'];
$output = shell_exec("ls $cmd");
echo $output;
?>
