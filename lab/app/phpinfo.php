<?php
declare(strict_types=1);

// Minimal synthetic version page. Never expose full phpinfo() in production.
header('X-Powered-By: PHP/' . PHP_VERSION);
header('Content-Type: text/html; charset=UTF-8');
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>PHP Version Fixture</title></head>
<body>
<h1>PHP Version</h1>
<p><?= htmlspecialchars(PHP_VERSION, ENT_QUOTES, 'UTF-8') ?></p>
<p>This is a minimal version fixture; it does not expose phpinfo() configuration.</p>
</body>
</html>
