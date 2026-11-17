<?php

declare(strict_types=1);

session_start();
if (!isset($_SESSION['history'])) {
  $_SESSION['history'] = [];
}

// Read which tool form was submitted (defaults to empty string on initial GET request)
$tool = $_POST['tool'] ?? '';
if ($tool !== '') {
  array_unshift($_SESSION['history'], strtoupper($tool) . ' executed at ' . date('H:i:s'));
  $_SESSION['history'] = array_slice($_SESSION['history'], 0, 5);
}
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

// --- TOOL 3: BASE64 & URL CODEC (Paste in top PHP block) ---
if ($tool === 'codec') {
  $s = $_POST['str'] ?? '';
  $out['b64_enc'] = base64_encode($s);
  $decoded = base64_decode($s, strict: true);
  $out['b64_dec'] = ($decoded !== false && mb_check_encoding($decoded, 'UTF-8'))
    ? $decoded
    : '(Input is not valid UTF-8 Base64)';
  $out['url_enc'] = rawurlencode($s);
}

// --- TOOL 4: NATURAL-LANGUAGE DATE & UNIX EPOCH CONVERTER (Paste in top PHP block) ---
if ($tool === 'date') {
  $expr = trim($_POST['expr'] ?? 'now');
  // If input is purely numeric, treat it as a Unix epoch timestamp; otherwise parse English text
  $ts = is_numeric($expr) ? (int) $expr : strtotime($expr);
  if ($ts !== false) {
    $out['unix']  = (string) $ts;
    $out['human'] = date('l, jS F Y H:i:s T', $ts);
    $out['iso']   = date('c', $ts);
  } else {
    $out['error'] = 'Could not parse date expression.';
  }
}

// --- TOOL 5: SAFE DNS & IP INSPECTOR (Paste in top PHP block) ---
if ($tool === 'net') {
  // Sanitize hostname to allow only valid DNS characters
  $host = preg_replace('/[^a-zA-Z0-9.-]/', '', $_POST['host'] ?? '');
  $ip   = gethostbyname($host);

  // Validate that the resolved IPv4 address is strictly public
  $safe = filter_var(
    $ip,
    FILTER_VALIDATE_IP,
    FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
  );

  if ($safe !== false) {
    $rdns = gethostbyaddr($safe);
    $out['res'] = "Host: $host\nIPv4: $safe\nrDNS: $rdns";
  } else {
    $out['res'] = "Blocked: Private, loopback, reserved, or unresolvable address ($ip).";
  }
}

// --- TOOL 6: MULTIBYTE TEXT ANALYZER & SLUGIFIER (Paste in top PHP block) ---
if ($tool === 'text') {
  $txt = $_POST['body'] ?? '';
  $out['words'] = str_word_count($txt);
  $out['bytes'] = strlen($txt);
  $out['chars'] = mb_strlen($txt, 'UTF-8');
  $out['slug']  = trim(preg_replace('/[^a-z0-9]+/', '-', strtolower($txt)), '-');
}

// ---- TOOL 7: Fuzzy Keyword Spellchecker
if ($tool === 'spell') {
  $term = strtolower(trim($_POST['term'] ?? ''));
  $dictionary = [
    'authentication',
    'authorization',
    'bytecode',
    'cookie',
    'cryptography',
    'database',
    'decorator',
    'equirectangular',
    'framework',
    'gateway',
    'idempotent',
    'middleware',
    'opcache',
    'parameterized',
    'sqlite',
    'webhook'
  ];

  $shortest = -1;
  $closest  = '';

  foreach ($dictionary as $word) {
    $dist = levenshtein($term, $word);
    if ($dist === 0) {
      $closest  = $word;
      $shortest = 0;
      break; // Exact match found
    }
    if ($shortest < 0 || $dist < $shortest) {
      $closest  = $word;
      $shortest = $dist;
    }
  }

  $out['spell_result'] = ($shortest === 0)
    ? "Exact match: '$closest'"
    : "Did you mean '$closest'? (Edit distance: $shortest)";
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

  <div class="card" style="margin-bottom: 20px;">
    <form method="POST">
      <input type="hidden" name="tool" value="clear_history">
      <button type="submit">Clear History</button>
    </form>
    <?php if ($tool === 'clear_history'): ?>
      <?php $_SESSION['history'] = []; ?>
    <?php endif; ?>
    <?php foreach ($_SESSION['history'] as $item): ?>
      <div><?= htmlspecialchars($item, ENT_QUOTES, 'UTF-8') ?></div>
    <?php endforeach; ?>
  </div>

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

    <!-- CARD 3: BASE64 & URL CODEC (Paste inside <div class="grid">) -->
    <div class="card">
      <h2>3. Base64 &amp; URL Codec</h2>
      <p class="desc">Encodes and strictly decodes Base64 payloads and RFC 3986 URL strings.</p>
      <form method="POST">
        <input type="hidden" name="tool" value="codec">
        <input type="text" name="str" placeholder="Enter text or Base64 payload..." value="<?= htmlspecialchars($_POST['str'] ?? '', ENT_QUOTES, 'UTF-8') ?>" required>
        <button type="submit" style="margin-top:8px;">Encode / Decode</button>
      </form>
      <?php if ($tool === 'codec'): ?>
        <pre>Base64 Enc: <?= htmlspecialchars($out['b64_enc'], ENT_QUOTES, 'UTF-8') ?>

Base64 Dec: <?= htmlspecialchars($out['b64_dec'], ENT_QUOTES, 'UTF-8') ?>

URL Enc:    <?= htmlspecialchars($out['url_enc'], ENT_QUOTES, 'UTF-8') ?></pre>
      <?php endif; ?>
    </div>

    <!-- CARD 4: DATE & UNIX EPOCH CONVERTER (Paste inside <div class="grid">) -->
    <div class="card">
      <h2>4. Date &amp; Unix Epoch Converter</h2>
      <p class="desc">Converts relative English phrases or Unix timestamps into ISO-8601 dates.</p>
      <form method="POST">
        <input type="hidden" name="tool" value="date">
        <input type="text" name="expr" placeholder="e.g. next Tuesday, +3 weeks, or 1794825600" value="<?= htmlspecialchars($_POST['expr'] ?? '', ENT_QUOTES, 'UTF-8') ?>" required>
        <button type="submit" style="margin-top:8px;">Convert Timestamp</button>
      </form>
      <?php if ($tool === 'date'): ?>
        <pre><?= isset($out['error'])
                ? htmlspecialchars($out['error'], ENT_QUOTES, 'UTF-8')
                : htmlspecialchars("Unix:  {$out['unix']}\nHuman: {$out['human']}\nISO:   {$out['iso']}", ENT_QUOTES, 'UTF-8') ?></pre>
      <?php endif; ?>
    </div>

    <!-- CARD 5: SAFE DNS & IP INSPECTOR (Paste inside <div class="grid">) -->
    <div class="card">
      <h2>5. Safe DNS &amp; IP Inspector</h2>
      <p class="desc">Resolves hostnames and blocks private/loopback ranges using <code>filter_var()</code>.</p>
      <form method="POST">
        <input type="hidden" name="tool" value="net">
        <input type="text" name="host" placeholder="e.g. gold.ac.uk, 8.8.8.8, or 127.0.0.1" value="<?= htmlspecialchars($_POST['host'] ?? '', ENT_QUOTES, 'UTF-8') ?>" required>
        <button type="submit" style="margin-top:8px;">Inspect Host</button>
      </form>
      <?php if ($tool === 'net'): ?>
        <pre><?= htmlspecialchars($out['res'], ENT_QUOTES, 'UTF-8') ?></pre>
      <?php endif; ?>
    </div>
    <!-- CARD 6: TEXT ANALYZER & SLUGIFIER (Paste inside <div class="grid">) -->
    <div class="card">
      <h2>6. Text Analyzer &amp; URL Slugifier</h2>
      <p class="desc">Compares byte length vs UTF-8 character count and generates clean URL slugs.</p>
      <form method="POST">
        <input type="hidden" name="tool" value="text">
        <textarea name="body" rows="3" placeholder="e.g. Café Price: £4.50 — Special Offer!" required><?= htmlspecialchars($_POST['body'] ?? '', ENT_QUOTES, 'UTF-8') ?></textarea>
        <button type="submit" style="margin-top:8px;">Analyze Text</button>
      </form>
      <?php if ($tool === 'text'): ?>
        <pre>Words: <?= $out['words'] ?> | UTF-8 Chars: <?= $out['chars'] ?> | Raw Bytes: <?= $out['bytes'] ?>

Slug:  <?= htmlspecialchars($out['slug'], ENT_QUOTES, 'UTF-8') ?></pre>
      <?php endif; ?>
    </div>
    <!-- CARD 7 -->
    <div class="card">
      <h2>7. Fuzzy Keyword Spellchecker</h2>
      <form method="POST">
        <input type="hidden" name="tool" value="spell">
        <input type="text" name="term">
        <button type="submit" style="margin-top:8px;">Check Spelling</button>
      </form>
      <?php if ($tool === 'spell'): ?>
        <pre><?= htmlspecialchars($out['spell_result'], ENT_QUOTES, 'UTF-8') ?></pre>
      <?php endif; ?>
    </div>

  </div>
</body>

</html>