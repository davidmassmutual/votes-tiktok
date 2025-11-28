<?php
// Simple cron job to keep Render awake
// Access this file via cron job or monitoring service
// Add at top of cron.php
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');
header('Content-Type: application/json');

// Log the ping
file_put_contents(__DIR__ . '/cron.log', date('Y-m-d H:i:s') . ' - Cron ping received' . PHP_EOL, FILE_APPEND);

// Simple response to confirm service is awake
echo json_encode([
    'status' => 'awake',
    'timestamp' => date('Y-m-d H:i:s'),
    'message' => 'Render service is active'
]);
?>
