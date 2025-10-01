<?php
$baseDir = __DIR__ . '/public_files';
$raw = isset($_GET['file']) ? $_GET['file'] : '';
$safe = preg_replace('/[^A-Za-z0-9._-]/', '', $raw);
$safe = basename($safe);
$allowed = ['readme.txt', 'terms.txt', 'howto.pdf', 'license.txt'];
if (!in_array($safe, $allowed, true)) {
    error_log("Blocked suspicious file request: " . $raw . " from IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    http_response_code(400);
    echo "Invalid request";
    exit;
}
$file_path = realpath($baseDir . DIRECTORY_SEPARATOR . $safe);
$base_real = realpath($baseDir);
if ($file_path === false || strpos($file_path, $base_real) !== 0) {
    error_log("Blocked path escape attempt: " . $file_path . " raw=" . $raw);
    http_response_code(403);
    echo "Forbidden";
    exit;
}
$content = file_get_contents($file_path);
if ($content === false) {
    error_log("Failed to read allowed file: " . $file_path);
    http_response_code(500);
    echo "Internal error";
    exit;
}
?>
