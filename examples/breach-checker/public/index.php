<?php

declare(strict_types=1);

session_start();

$baseDir = dirname(__DIR__);
$storageDir = $baseDir . '/storage';
$config = require $baseDir . '/config/breaches.php';

if (!is_dir($storageDir)) {
    mkdir($storageDir, 0700, true);
}

function securityHeaders(): void
{
    header("Content-Security-Policy: default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none';");
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    header('Cross-Origin-Resource-Policy: same-origin');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Embedder-Policy: require-corp');
}

function handleCors(): void
{
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin === '') {
        return;
    }

    $allowed = array_filter(array_map('trim', explode(',', getenv('CORS_ALLOWED_ORIGINS') ?: '')));
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? '';
    $sameOrigin = $host !== '' ? sprintf('%s://%s', $scheme, $host) : '';

    if (in_array($origin, $allowed, true) || $origin === $sameOrigin) {
        header('Access-Control-Allow-Origin: ' . $origin);
        header('Vary: Origin');
        header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, X-CSRF-Token');
    }
}

function jsonResponse(array $payload, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
}

function htmlResponse(string $body, string $title = 'Breach Check'): void
{
    $csrfToken = getCsrfToken();
    $titleSafe = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
    $bodySafe = $body;
    echo "<!DOCTYPE html>\n";
    echo "<html lang=\"en\">\n";
    echo "<head>\n";
    echo "  <meta charset=\"utf-8\">\n";
    echo "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
    echo "  <meta name=\"csrf-token\" content=\"{$csrfToken}\">\n";
    echo "  <title>{$titleSafe}</title>\n";
    echo "  <link rel=\"stylesheet\" href=\"/assets/style.css\">\n";
    echo "</head>\n";
    echo "<body>\n";
    echo $bodySafe;
    echo "  <script src=\"/assets/app.js\"></script>\n";
    echo "</body>\n";
    echo "</html>\n";
}

function getCsrfToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
}

function requireCsrf(): ?array
{
    $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if ($token === '' || !hash_equals(getCsrfToken(), $token)) {
        return ['error' => 'Invalid CSRF token. Refresh the page and try again.'];
    }

    return null;
}

function readJson(string $path): array
{
    if (!file_exists($path)) {
        return [];
    }

    $data = file_get_contents($path);
    if ($data === false) {
        return [];
    }

    $decoded = json_decode($data, true);
    return is_array($decoded) ? $decoded : [];
}

function writeJson(string $path, array $data): void
{
    file_put_contents($path, json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT), LOCK_EX);
}

function hashIdentifier(string $value): string
{
    $salt = getenv('LOG_HASH_SALT') ?: 'local-dev-pepper';
    return hash_hmac('sha256', strtolower($value), $salt);
}

function logEvent(string $event, ?string $email, string $storageDir): void
{
    $record = [
        'event' => $event,
        'timestamp' => gmdate('c'),
        'emailHash' => $email ? hashIdentifier($email) : null,
        'ipHash' => hashIdentifier($_SERVER['REMOTE_ADDR'] ?? 'unknown'),
    ];
    $logPath = $storageDir . '/audit.log';
    file_put_contents($logPath, json_encode($record) . PHP_EOL, FILE_APPEND | LOCK_EX);
}

function enforceRateLimit(string $ip, string $storageDir, int $limit = 10, int $windowSeconds = 600): ?array
{
    $path = $storageDir . '/rate_limit.json';
    $now = time();
    $data = readJson($path);

    $timestamps = $data[$ip] ?? [];
    $timestamps = array_values(array_filter($timestamps, static fn ($ts) => ($now - $ts) < $windowSeconds));

    if (count($timestamps) >= $limit) {
        return ['error' => 'Too many requests. Please wait and try again.'];
    }

    $timestamps[] = $now;
    $data[$ip] = $timestamps;
    writeJson($path, $data);

    return null;
}

function parseJsonBody(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '') {
        return [];
    }

    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

function validateEmail(?string $email): ?string
{
    $email = trim((string) $email);
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return null;
    }

    return strtolower($email);
}

function handleCheck(array $config, string $storageDir): void
{
    $rateLimitError = enforceRateLimit($_SERVER['REMOTE_ADDR'] ?? 'unknown', $storageDir);
    if ($rateLimitError) {
        jsonResponse(['found' => false, 'breaches' => [], 'message' => $rateLimitError['error']], 429);
        return;
    }

    $csrfError = requireCsrf();
    if ($csrfError) {
        jsonResponse(['found' => false, 'breaches' => [], 'message' => $csrfError['error']], 403);
        return;
    }

    $payload = parseJsonBody();
    $email = validateEmail($payload['email'] ?? null);

    if (!$email) {
        jsonResponse(['found' => false, 'breaches' => [], 'message' => 'Enter a valid email address.'], 422);
        return;
    }

    $hash = hashIdentifier($email);
    $found = in_array($hash, $config['demoHashes'], true);
    $breaches = $found ? $config['breaches'] : [];

    logEvent('check', $email, $storageDir);

    jsonResponse([
        'found' => $found,
        'breaches' => $breaches,
        'message' => $found ? 'We found matches in public breach data.' : 'No matches found in the demo data set.',
    ]);
}

function handleNotifyRequest(string $storageDir): void
{
    $rateLimitError = enforceRateLimit($_SERVER['REMOTE_ADDR'] ?? 'unknown', $storageDir, 5, 900);
    if ($rateLimitError) {
        jsonResponse(['message' => $rateLimitError['error']], 429);
        return;
    }

    $csrfError = requireCsrf();
    if ($csrfError) {
        jsonResponse(['message' => $csrfError['error']], 403);
        return;
    }

    $payload = parseJsonBody();
    $email = validateEmail($payload['email'] ?? null);
    if (!$email) {
        jsonResponse(['message' => 'Enter a valid email address.'], 422);
        return;
    }

    $preferences = [
        'breachAlerts' => true,
    ];

    $token = bin2hex(random_bytes(32));
    $pendingPath = $storageDir . '/notify_pending.json';
    $pending = readJson($pendingPath);
    $pending[$token] = [
        'emailHash' => hashIdentifier($email),
        'preferences' => $preferences,
        'expiresAt' => time() + 3600,
    ];
    writeJson($pendingPath, $pending);

    $verifyUrl = getBaseUrl() . '/notify/verify?token=' . urlencode($token);
    $subject = 'Verify your breach alert notification';
    $message = "Use this one-time link to verify your email and enable breach alerts: {$verifyUrl}\n\nIf you did not request this, you can ignore this message.";
    @mail($email, $subject, $message);

    logEvent('notify_requested', $email, $storageDir);

    jsonResponse(['message' => 'Verification link sent if the email exists.']);
}

function handleNotifyVerify(string $storageDir): void
{
    $token = $_GET['token'] ?? '';
    $pendingPath = $storageDir . '/notify_pending.json';
    $pending = readJson($pendingPath);

    if ($token === '' || !isset($pending[$token])) {
        renderMessagePage('Verification link is invalid or expired.', 'Verification');
        return;
    }

    $entry = $pending[$token];
    if (($entry['expiresAt'] ?? 0) < time()) {
        unset($pending[$token]);
        writeJson($pendingPath, $pending);
        renderMessagePage('Verification link has expired. Please request a new one.', 'Verification');
        return;
    }

    $subscriptionsPath = $storageDir . '/notify_subscriptions.json';
    $subscriptions = readJson($subscriptionsPath);
    $subscriptions[$entry['emailHash']] = [
        'preferences' => $entry['preferences'] ?? ['breachAlerts' => true],
        'verifiedAt' => gmdate('c'),
    ];
    writeJson($subscriptionsPath, $subscriptions);

    unset($pending[$token]);
    writeJson($pendingPath, $pending);

    renderMessagePage('Email verified. Notifications are now enabled for this address.', 'Verification');
}

function renderHome(): void
{
    $body = <<<HTML
<main class="shell">
  <header class="hero">
    <div>
      <p class="eyebrow">Privacy-first breach checker</p>
      <h1>Check if your email appears in public breach data.</h1>
      <p class="lead">We never ask for passwords. Emails are processed in-memory, never stored, and only hashed for minimal logs.</p>
    </div>
  </header>

  <section class="card">
    <form id="check-form">
      <label for="email">Email address</label>
      <input id="email" name="email" type="email" autocomplete="email" placeholder="you@example.com" required>
      <p class="consent">By checking, you agree that we will query public breach data and process your email for this request only.</p>
      <button type="submit" class="primary">Check</button>
      <p id="status" class="status" aria-live="polite"></p>
    </form>
    <div id="results" class="results" hidden></div>
  </section>

  <section class="card">
    <h2>Optional: Notify me about future breaches</h2>
    <p>Verify ownership with a one-time link. We only store a hashed email and your alert preference.</p>
    <button id="notify-button" class="secondary">Send verification link</button>
    <p id="notify-status" class="status" aria-live="polite"></p>
  </section>

  <footer class="footer">
    <a href="/privacy">Privacy policy</a>
    <a href="/security">Security</a>
  </footer>
</main>
HTML;

    htmlResponse($body, 'Breach Check');
}

function renderPrivacy(): void
{
    $body = <<<HTML
<main class="shell">
  <header class="hero small">
    <h1>Privacy policy</h1>
    <p class="lead">We designed this service to minimize data collection and storage.</p>
  </header>

  <section class="card">
    <h2>What we collect</h2>
    <ul>
      <li>Your email address is processed in-memory for the lookup request.</li>
      <li>We do not store full emails in a database.</li>
      <li>Minimal logs contain only salted hashes of emails and IP addresses.</li>
    </ul>
  </section>

  <section class="card">
    <h2>Notifications</h2>
    <ul>
      <li>If you opt-in, we store only a hashed email and your alert preference.</li>
      <li>You can disable alerts by contacting the operator.</li>
    </ul>
  </section>

  <section class="card">
    <h2>Your choices</h2>
    <ul>
      <li>You can use the checker without enabling notifications.</li>
      <li>We never request passwords or other sensitive credentials.</li>
    </ul>
  </section>

  <footer class="footer">
    <a href="/">Back to checker</a>
  </footer>
</main>
HTML;

    htmlResponse($body, 'Privacy policy');
}

function renderSecurity(): void
{
    $body = <<<HTML
<main class="shell">
  <header class="hero small">
    <h1>Security overview</h1>
    <p class="lead">What we check, what we do not check, and how we protect requests.</p>
  </header>

  <section class="card">
    <h2>What is checked</h2>
    <ul>
      <li>Public breach data that includes email addresses.</li>
      <li>Only the email you submit for the current request.</li>
    </ul>
  </section>

  <section class="card">
    <h2>What is NOT checked</h2>
    <ul>
      <li>Passwords, secrets, or private inbox content.</li>
      <li>Hidden or private breach data without authorization.</li>
      <li>Any other accounts tied to your email unless you explicitly check them.</li>
    </ul>
  </section>

  <section class="card">
    <h2>Protections</h2>
    <ul>
      <li>CSRF protection for POST requests and strict Content Security Policy.</li>
      <li>Rate limiting by IP to prevent abuse.</li>
      <li>Minimal logging with salted hashes instead of raw emails.</li>
    </ul>
  </section>

  <footer class="footer">
    <a href="/">Back to checker</a>
  </footer>
</main>
HTML;

    htmlResponse($body, 'Security');
}

function renderMessagePage(string $message, string $title): void
{
    $messageSafe = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
    $body = <<<HTML
<main class="shell">
  <section class="card">
    <h1>{$title}</h1>
    <p>{$messageSafe}</p>
    <a href="/">Return home</a>
  </section>
</main>
HTML;

    htmlResponse($body, $title);
}

function getBaseUrl(): string
{
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    return sprintf('%s://%s', $scheme, $host);
}

securityHeaders();
handleCors();

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

if ($method === 'OPTIONS') {
    http_response_code(204);
    exit;
}

switch ($path) {
    case '/':
        renderHome();
        break;
    case '/privacy':
        renderPrivacy();
        break;
    case '/security':
        renderSecurity();
        break;
    case '/notify/verify':
        handleNotifyVerify($storageDir);
        break;
    case '/api/check':
        if ($method !== 'POST') {
            jsonResponse(['message' => 'Method not allowed.'], 405);
            break;
        }
        handleCheck($config, $storageDir);
        break;
    case '/api/notify/request':
        if ($method !== 'POST') {
            jsonResponse(['message' => 'Method not allowed.'], 405);
            break;
        }
        handleNotifyRequest($storageDir);
        break;
    default:
        http_response_code(404);
        renderMessagePage('Page not found.', 'Not found');
        break;
}
