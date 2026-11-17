<?php

declare(strict_types=1);

// Read which tool form was submitted (defaults to empty string on initial GET request)
$tool = $_POST['tool'] ?? '';
$out  = [];

// --- TOOL 1: CRYPTOGRAPHIC HASH, BCRYPT & TOKEN GENERATOR ---
if ($tool === 'hash') {
  $in  = $_POST['text'] ?? '';
  $rng = new \Random\Randomizer();

  // Fast cryptographic digest (for file/data integrity, NOT passwords)
  $out['sha256'] = hash('sha256', $in);

  // Slow, automatically salted password hash (equivalent to Werkzeug generate_password_hash)
  $out['bcrypt'] = password_hash($in, PASSWORD_DEFAULT);

  // PHP 8.3 Randomizer method: generates an unambiguous 12-character token
  $out['token']  = $rng->getBytesFromString('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', 12);
}

// --- TOOL 2: JSON VALIDATOR & FORMATTER (PHP 8.3) ---
if ($tool === 'json') {
  $raw = $_POST['payload'] ?? '';

  // json_validate() is new in PHP 8.3: checks syntax without allocating object memory
  $isValid = json_validate($raw);
  $out['status'] = $isValid ? 'Valid JSON syntax' : 'Invalid JSON syntax';
  $out['pretty'] = $isValid
    ? json_encode(json_decode($raw), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
    : 'Correct the JSON syntax errors above to format this payload.';
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PHP 8.3 Developer Utility Hub</title>
  <style>
    :root {
      --bg: #0f172a;
      --card: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --badge-bg: #1e1b4b;
      --badge-text: #fbbf24;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 32px 24px;
      max-width: 1200px;
      margin: 0 auto;
      line-height: 1.5;
    }

    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 28px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }

    h1 {
      font-size: 1.75rem;
      color: var(--text);
    }

    .badge {
      background: var(--badge-bg);
      color: var(--badge-text);
      border: 1px solid #4f46e5;
      padding: 6px 12px;
      border-radius: 999px;
      font-size: 0.85rem;
      font-weight: 600;
      font-family: ui-monospace, monospace;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
      gap: 20px;
    }

    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .card h2 {
      font-size: 1.1rem;
      color: var(--accent);
    }

    .card p.desc {
      font-size: 0.85rem;
      color: var(--muted);
    }

    input[type="text"],
    textarea,
    select {
      width: 100%;
      background: var(--bg);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 10px 12px;
      border-radius: 6px;
      font-family: ui-monospace, monospace;
      font-size: 0.9rem;
    }

    button {
      background: var(--accent);
      color: #0f172a;
      border: none;
      padding: 9px 14px;
      border-radius: 6px;
      font-weight: 700;
      cursor: pointer;
    }

    button:hover {
      opacity: 0.9;
    }

    pre {
      background: #020617;
      border: 1px solid var(--border);
      padding: 12px;
      border-radius: 6px;
      font-size: 0.82rem;
      overflow-x: auto;
      color: #a7f3d0;
      white-space: pre-wrap;
      word-break: break-all;
    }
  </style>
</head>

<body>

  <header>
    <h1>PHP 8.3 Developer Utility Hub</h1>
    <span class="badge">PHP <?= PHP_VERSION ?> | Host: <?= htmlspecialchars($_SERVER['SERVER_NAME'] ?? 'doc.gold.ac.uk', ENT_QUOTES, 'UTF-8') ?> | RAM: <?= round(memory_get_peak_usage(true) / 1024) ?> KB</span>
  </header>

  <div class="grid">

    <!-- CARD 1: HASH, BCRYPT & TOKEN GENERATOR -->
    <div class="card">
      <h2>1. Hash, Bcrypt &amp; Token Generator</h2>
      <p class="desc">Compares fast SHA-256 digests against salted bcrypt password hashes.</p>
      <form method="POST">
        <input type="hidden" name="tool" value="hash">
        <input type="text" name="text" placeholder="Enter string or password..." value="<?= htmlspecialchars($_POST['text'] ?? '', ENT_QUOTES, 'UTF-8') ?>" required>
        <button type="submit" style="margin-top:8px;">Generate Hashes</button>
      </form>
      <?php if ($tool === 'hash'): ?>
        <pre>SHA-256: <?= htmlspecialchars($out['sha256'], ENT_QUOTES, 'UTF-8') ?>

Bcrypt:  <?= htmlspecialchars($out['bcrypt'], ENT_QUOTES, 'UTF-8') ?>

Token:   <?= htmlspecialchars($out['token'], ENT_QUOTES, 'UTF-8') ?></pre>
      <?php endif; ?>
    </div>

    <!-- CARD 2: JSON VALIDATOR & FORMATTER -->
    <div class="card">
      <h2>2. JSON Validator &amp; Formatter (PHP 8.3)</h2>
      <p class="desc">Validates raw JSON syntax using <code>json_validate()</code> and pretty-prints it.</p>
      <form method="POST">
        <input type="hidden" name="tool" value="json">
        <textarea name="payload" rows="3" placeholder='{"user":"ada","roles":["admin","editor"]}' required><?= htmlspecialchars($_POST['payload'] ?? '', ENT_QUOTES, 'UTF-8') ?></textarea>
        <button type="submit" style="margin-top:8px;">Validate &amp; Format</button>
      </form>
      <?php if ($tool === 'json'): ?>
        <pre>Status: <?= htmlspecialchars($out['status'], ENT_QUOTES, 'UTF-8') ?>

<?= htmlspecialchars($out['pretty'], ENT_QUOTES, 'UTF-8') ?></pre>
      <?php endif; ?>
    </div>

  </div>
</body>

</html>