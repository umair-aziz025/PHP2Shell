<?php
declare(strict_types=1);

header('X-Powered-By: PHP/' . PHP_VERSION);
header('X-PHP2Shell-Lab: docker-php-runtime');
header('Content-Type: text/html; charset=UTF-8');
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>PHP2Shell Lab Fixture</title></head>
<body>
<h1>PHP2Shell runtime fingerprint fixture</h1>
<p>PHP Version: <?= htmlspecialchars(PHP_VERSION, ENT_QUOTES, 'UTF-8') ?></p>
<p>SAPI: <?= htmlspecialchars(PHP_SAPI, ENT_QUOTES, 'UTF-8') ?></p>
<p>This page provides version evidence; it is not proof of exploitability.</p>
</body>
</html>
