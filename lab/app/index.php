<?php
declare(strict_types=1);

// This fixture reports the PHP runtime actually serving the request.
// Do not hard-code a version: multiple Docker lab containers mount this file.
header('X-Powered-By: PHP/' . PHP_VERSION);
header('X-PHP2Shell-Lab: docker-php-runtime');
header('Content-Type: text/html; charset=UTF-8');
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>PHP2Shell Lab Fixture</title></head>
<body>
<h1>PHP2Shell runtime fingerprinting fixture</h1>
<p>PHP Version: <?= htmlspecialchars(PHP_VERSION, ENT_QUOTES, 'UTF-8') ?></p>
<p>SAPI: <?= htmlspecialchars(PHP_SAPI, ENT_QUOTES, 'UTF-8') ?></p>
<p>This page is for version/reporting tests. It is not an exploit success indicator.</p>
</body>
</html>
