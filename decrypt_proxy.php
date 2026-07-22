<?php
/*
 * 解密代理服务器
 * - POST /decrypt_proxy.php          → App上传加密数据，解密后转发到任务服务器
 * - GET  /decrypt_proxy.php?act=view → 查看转发日志前端页面
 * - GET  /decrypt_proxy.php?act=logs → JSON格式返回日志
 * - GET  /decrypt_proxy.php?act=clear→ 清空日志
 */

$AES_KEY  = '25d9a1907ab38e273c4f57c476e64377';
$AUTH_HASH_FILE = __DIR__ . '/.auth_hash';
$LOG_FILE = __DIR__ . '/decrypt_proxy_logs.jsonl';
$DEVICE_FILE = __DIR__ . '/device_controls.json';
$ANDROID_SESSION_FILE = __DIR__ . '/android_sessions.json';
$UPDATE_FILE = __DIR__ . '/app_update.json';
$PLUGIN_UPDATE_FILE = __DIR__ . '/plugin_update.json';
$VERSION_CTRL_FILE = __DIR__ . '/version_controls.json';
$APK_DIR = __DIR__ . '/app_updates';
$PLUGIN_UPDATE_DIR = __DIR__ . '/plugin_updates';
$STATS_DIR = __DIR__ . '/daily_stats';
$FP_ENV_STATS_DIR = __DIR__ . '/fingerprint_env_stats';
$API1_TOKEN_FILE = __DIR__ . '/api1_token.json';
$API1_TOKEN_MAP_FILE = __DIR__ . '/api1_token_map.json';
$API1_ACCOUNTS_FILE = __DIR__ . '/api1_allowed_accounts.json';
$API2_NUMBERS_FILE = __DIR__ . '/api2_number_remarks.json';
$API2_FIXED_USERNAME = '米乐米乐';
$MAX_LOGS = 500;
$FORWARD_TIMEOUT = 8;
$FORWARD_CONNECT_TIMEOUT = 6;
$LOGIN_TIMEOUT = 8;
$LOGIN_CONNECT_TIMEOUT = 6;
$HEARTBEAT_WRITE_INTERVAL = 20;
$SAVE_SUCCESS_DECRYPT_DUMPS = false;
$SAVE_SUCCESS_UPLOAD_DUMPS = true;
$ENABLE_UPLOAD_DETAIL_DUMPS = true;
$ENABLE_SUBMIT_STATS = false;
$MAX_STAT_RECORDS_PER_DEVICE = 50;
$MAX_LOG_RESPONSE_BYTES = 1200;
$API1_PARSE_TIMEOUT_MAX_ATTEMPTS = 2;
$API1_PARSE_TIMEOUT_RETRY_DELAY_US = 150000;
$API1_TAKE_URL = 'https://zb1.eqwofaygdsjko.uk:443/api/task/take';
$DECODED_EXTENSION_TASK_QUEUE_FILE = __DIR__ . '/decoded_extension_tasks.json';
$DECODED_EXTENSION_SUBMIT_LOG_FILE = __DIR__ . '/decoded_extension_submits.jsonl';
$DECODED_EXTENSION_ACCOUNTS_FILE = __DIR__ . '/.decoded_extension_accounts.json';
$DECODED_EXTENSION_STATE_FILE = __DIR__ . '/.decoded_extension_state.json';
$DECODED_EXTENSION_SQLITE_FILE = __DIR__ . '/runtime.sqlite';
$DECODED_EXTENSION_QUEUE_TTL = 600;
$DECODED_EXTENSION_LEASE_TTL = 1800;
$PARALLEL_CONTROL_BASE_URL = getenv('GEJIE_PARALLEL_CONTROL_BASE_URL') ?: '';
$PARALLEL_CONTROL_BASE_URL_FILE = __DIR__ . '/parallel_control_base_url.local.php';
$CACHE_DEVICE_RETENTION_DAYS = 7;
$CACHE_FP_STATS_RETENTION_DAYS = 30;
$CACHE_DECRYPT_DUMP_KEEP = 20;

$API1_AUTH = [
    'login_url' => 'https://zb1.eqwofaygdsjko.uk:443/api/user/login',
    'username'  => 'xixi677',
    'password'  => '$7dudfafqewddHJl2af',
];

$WEB_PLUGIN_AUTH = [
    'username' => getenv('GEJIE_WEB_USERNAME') ?: '',
    'password' => getenv('GEJIE_WEB_PASSWORD') ?: '',
];
$WEB_PLUGIN_AUTH_FILE = __DIR__ . '/web_plugin_auth.local.php';
if (is_file($WEB_PLUGIN_AUTH_FILE)) {
    $webPluginLocalAuth = include $WEB_PLUGIN_AUTH_FILE;
    if (is_array($webPluginLocalAuth)) {
        $WEB_PLUGIN_AUTH = array_merge($WEB_PLUGIN_AUTH, array_intersect_key($webPluginLocalAuth, $WEB_PLUGIN_AUTH));
    }
}
if (is_file($PARALLEL_CONTROL_BASE_URL_FILE)) {
    $parallelControlLocalBase = include $PARALLEL_CONTROL_BASE_URL_FILE;
    if (is_string($parallelControlLocalBase)) {
        $PARALLEL_CONTROL_BASE_URL = trim($parallelControlLocalBase);
    } elseif (is_array($parallelControlLocalBase)) {
        $PARALLEL_CONTROL_BASE_URL = trim((string)($parallelControlLocalBase['base_url'] ?? $PARALLEL_CONTROL_BASE_URL));
    }
}

$STATIC_DNS_RESOLVE = [
    'zb1.eqwofaygdsjko.uk:443:104.21.65.145',
    'zb1.eqwofaygdsjko.uk:443:172.67.164.25',
];

$TARGETS = [
    1 => [
        'url'  => 'https://zb1.eqwofaygdsjko.uk:443/api/task/submit/v2',
        'gzip' => false,
    ],
    2 => [
        'url'  => 'http://103.143.80.158:2000/up',
        'gzip' => true,
    ],
];

@ini_set('upload_max_filesize', '200M');
@ini_set('post_max_size', '220M');
@ini_set('max_execution_time', '180');

// ===== 工具函数 =====
function verifyAuthKey(string $input): bool {
    global $AUTH_HASH_FILE;
    if ($input === '') return false;
    if (!is_file($AUTH_HASH_FILE)) {
        @file_put_contents($AUTH_HASH_FILE, password_hash($input, PASSWORD_BCRYPT), LOCK_EX);
        return true;
    }
    return password_verify($input, trim((string)@file_get_contents($AUTH_HASH_FILE)));
}

function changeAuthPassword(string $currentPassword, string $newPassword, string $confirmPassword): array {
    global $AUTH_HASH_FILE;
    $currentPassword = trim($currentPassword);
    $newPassword = trim($newPassword);
    $confirmPassword = trim($confirmPassword);

    if ($currentPassword === '' || $newPassword === '' || $confirmPassword === '') {
        return ['ok' => false, 'msg' => '请填写当前密码和新密码'];
    }
    if (!verifyAuthKey($currentPassword)) {
        return ['ok' => false, 'msg' => '当前密码错误'];
    }
    if ($newPassword !== $confirmPassword) {
        return ['ok' => false, 'msg' => '两次输入的新密码不一致'];
    }
    if (strlen($newPassword) < 6) {
        return ['ok' => false, 'msg' => '新密码至少需要6位'];
    }
    if (hash_equals($currentPassword, $newPassword)) {
        return ['ok' => false, 'msg' => '新密码不能和当前密码相同'];
    }

    $hash = password_hash($newPassword, PASSWORD_BCRYPT);
    if (!is_string($hash) || $hash === '') {
        return ['ok' => false, 'msg' => '密码哈希生成失败'];
    }
    if (!atomicWrite($AUTH_HASH_FILE, $hash)) {
        return ['ok' => false, 'msg' => '密码保存失败，请检查文件权限'];
    }

    return ['ok' => true, 'msg' => '密码已修改'];
}

function getAuthKeyFromRequest(): string {
    $h = $_SERVER['HTTP_X_AUTH_KEY'] ?? '';
    if ($h !== '') return (string)$h;
    return (string)($_REQUEST['key'] ?? '');
}

function aesDecrypt(string $encrypted, string $key): ?string {
    $decoded = base64_decode($encrypted, true);
    if ($decoded === false) return null;
    $plain = openssl_decrypt($decoded, 'aes-256-ecb', $key, OPENSSL_RAW_DATA);
    return $plain === false ? null : $plain;
}

function forwardToServer(string $url, string $body, bool $gzip, array $extraHeaders = []): array {
    global $FORWARD_TIMEOUT, $FORWARD_CONNECT_TIMEOUT, $STATIC_DNS_RESOLVE;
    $headers = ['Content-Type: application/json; charset=utf-8', 'Accept: application/json'];
    foreach ($extraHeaders as $header) {
        if (is_string($header) && $header !== '') $headers[] = $header;
    }
    $postData = $body;
    if ($gzip) {
        $postData = gzencode($body);
        $headers[] = 'Content-Encoding: gzip';
    }
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST => true, CURLOPT_POSTFIELDS => $postData,
        CURLOPT_HTTPHEADER => $headers, CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $FORWARD_TIMEOUT, CURLOPT_CONNECTTIMEOUT => $FORWARD_CONNECT_TIMEOUT,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4,
        CURLOPT_DNS_CACHE_TIMEOUT => 300,
        CURLOPT_RESOLVE => $STATIC_DNS_RESOLVE,
        CURLOPT_TCP_KEEPALIVE => 1,
        CURLOPT_TCP_NODELAY => 1,
        CURLOPT_FORBID_REUSE => 0,
    ]);
    $response = curl_exec($ch);
    $error = curl_error($ch);
    $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $totalTime = (float)curl_getinfo($ch, CURLINFO_TOTAL_TIME);
    curl_close($ch);
    return [
        'response' => $response,
        'error' => $error,
        'http_code' => $httpCode,
        'headers' => $headers,
        'curl_total_ms' => (int)round($totalTime * 1000),
    ];
}

function forwardGetToServer(string $url, array $extraHeaders = []): array {
    global $FORWARD_TIMEOUT, $FORWARD_CONNECT_TIMEOUT, $STATIC_DNS_RESOLVE;
    $headers = ['Accept: application/json, text/plain, */*', 'Content-Type: application/json'];
    foreach ($extraHeaders as $header) {
        if (is_string($header) && $header !== '') $headers[] = $header;
    }
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_HTTPGET => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $FORWARD_TIMEOUT,
        CURLOPT_CONNECTTIMEOUT => $FORWARD_CONNECT_TIMEOUT,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4,
        CURLOPT_DNS_CACHE_TIMEOUT => 300,
        CURLOPT_RESOLVE => $STATIC_DNS_RESOLVE,
        CURLOPT_TCP_KEEPALIVE => 1,
        CURLOPT_TCP_NODELAY => 1,
        CURLOPT_FORBID_REUSE => 0,
    ]);
    $response = curl_exec($ch);
    $error = curl_error($ch);
    $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $totalTime = (float)curl_getinfo($ch, CURLINFO_TOTAL_TIME);
    curl_close($ch);
    return [
        'response' => $response,
        'error' => $error,
        'http_code' => $httpCode,
        'headers' => $headers,
        'curl_total_ms' => (int)round($totalTime * 1000),
    ];
}

function androidSessionAllowedTaskUrl(string $url): bool {
    $parts = parse_url($url);
    if (!is_array($parts)) return false;
    $scheme = strtolower((string)($parts['scheme'] ?? ''));
    $host = strtolower((string)($parts['host'] ?? ''));
    if (!in_array($scheme, ['http', 'https'], true) || $host === '') return false;
    if (preg_match('/(^|\.)shopee\./i', $host)) return true;
    if (preg_match('/(^|\.)shopee\.tw$/i', $host)) return true;
    return false;
}

function androidFetchUrlWithSession(string $url, string $cookies, string $userAgent = '', array $extraHeaders = []): array {
    global $FORWARD_TIMEOUT, $FORWARD_CONNECT_TIMEOUT, $STATIC_DNS_RESOLVE;
    $headers = [
        'Accept: application/json, text/plain, */*',
        'Accept-Language: zh-TW,zh;q=0.9,en;q=0.8',
        'X-Requested-With: XMLHttpRequest',
        'Referer: https://shopee.tw/',
    ];
    $userAgent = trim($userAgent);
    if ($userAgent === '') {
        $userAgent = 'Mozilla/5.0 (Linux; Android 15; Mobile) AppleWebKit/537.36 Chrome/150.0.0.0 Mobile Safari/537.36';
    }
    $headers[] = 'User-Agent: ' . $userAgent;
    $cookies = trim($cookies);
    if ($cookies !== '') $headers[] = 'Cookie: ' . $cookies;
    foreach ($extraHeaders as $header) {
        if (is_string($header) && trim($header) !== '') $headers[] = trim($header);
    }

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_HTTPGET => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => false,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_TIMEOUT => max(20, (int)$FORWARD_TIMEOUT),
        CURLOPT_CONNECTTIMEOUT => $FORWARD_CONNECT_TIMEOUT,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4,
        CURLOPT_DNS_CACHE_TIMEOUT => 300,
        CURLOPT_RESOLVE => $STATIC_DNS_RESOLVE,
        CURLOPT_TCP_KEEPALIVE => 1,
        CURLOPT_TCP_NODELAY => 1,
        CURLOPT_FORBID_REUSE => 0,
    ]);
    $response = curl_exec($ch);
    $error = curl_error($ch);
    $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $contentType = (string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    $finalUrl = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    $totalTime = (float)curl_getinfo($ch, CURLINFO_TOTAL_TIME);
    curl_close($ch);
    return [
        'response' => $response,
        'error' => $error,
        'http_code' => $httpCode,
        'content_type' => $contentType,
        'final_url' => $finalUrl,
        'headers' => $headers,
        'curl_total_ms' => (int)round($totalTime * 1000),
    ];
}

function decodedExtensionCreateTakeCurl(string $url, string $token) {
    global $FORWARD_TIMEOUT, $FORWARD_CONNECT_TIMEOUT, $STATIC_DNS_RESOLVE;
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_HTTPGET => true,
        CURLOPT_HTTPHEADER => [
            'Accept: application/json, text/plain, */*',
            'Content-Type: application/json',
            'Authorization: Bearer ' . $token,
        ],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $FORWARD_TIMEOUT,
        CURLOPT_CONNECTTIMEOUT => $FORWARD_CONNECT_TIMEOUT,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4,
        CURLOPT_DNS_CACHE_TIMEOUT => 300,
        CURLOPT_RESOLVE => $STATIC_DNS_RESOLVE,
        CURLOPT_TCP_KEEPALIVE => 1,
        CURLOPT_TCP_NODELAY => 1,
        CURLOPT_FORBID_REUSE => 0,
    ]);
    return $ch;
}

function atomicWrite(string $file, string $contents): bool {
    $dir = dirname($file);
    if (!is_dir($dir)) @mkdir($dir, 0775, true);
    $tmp = $file . '.' . bin2hex(random_bytes(4)) . '.tmp';
    if (@file_put_contents($tmp, $contents) === false) return false;
    if (!@rename($tmp, $file)) {
        @unlink($tmp);
        return false;
    }
    return true;
}

function decodedExtensionDb(): ?PDO {
    global $DECODED_EXTENSION_SQLITE_FILE;
    static $pdo = null;
    static $failed = false;
    if ($pdo instanceof PDO) return $pdo;
    if ($failed || !class_exists('PDO') || !in_array('sqlite', PDO::getAvailableDrivers(), true)) {
        $failed = true;
        return null;
    }

    try {
        $dir = dirname($DECODED_EXTENSION_SQLITE_FILE);
        if (!is_dir($dir)) @mkdir($dir, 0775, true);
        $pdo = new PDO('sqlite:' . $DECODED_EXTENSION_SQLITE_FILE);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $pdo->exec('PRAGMA journal_mode = WAL');
        $pdo->exec('PRAGMA busy_timeout = 5000');
        $pdo->exec('PRAGMA foreign_keys = ON');
        decodedExtensionDbInit($pdo);
        decodedExtensionDbPrune($pdo);
        return $pdo;
    } catch (\Throwable $_) {
        $pdo = null;
        $failed = true;
        return null;
    }
}

function decodedExtensionDbInit(PDO $pdo): void {
    static $done = false;
    if ($done) return;
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS task_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id TEXT NOT NULL,
            runtime_scope TEXT NOT NULL DEFAULT '',
            task_key TEXT NOT NULL,
            task_json TEXT NOT NULL,
            queued_ts INTEGER NOT NULL,
            queued_at TEXT NOT NULL,
            UNIQUE(account_id, runtime_scope, task_key)
        )
    ");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_task_queue_scope ON task_queue(account_id, runtime_scope, id)");
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS task_leases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id TEXT NOT NULL,
            runtime_scope TEXT NOT NULL DEFAULT '',
            lease_key TEXT NOT NULL,
            task_id TEXT NOT NULL DEFAULT '',
            task_url TEXT NOT NULL DEFAULT '',
            task_account_key TEXT NOT NULL DEFAULT '',
            task_account_username TEXT NOT NULL DEFAULT '',
            api1_token TEXT NOT NULL DEFAULT '',
            api1_token_hash TEXT NOT NULL DEFAULT '',
            api1_token_expires_at INTEGER NOT NULL DEFAULT 0,
            created_ts INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(account_id, runtime_scope, lease_key)
        )
    ");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_task_leases_task ON task_leases(account_id, task_id, created_ts)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_task_leases_url ON task_leases(account_id, task_url, created_ts)");
    $done = true;
}

function decodedExtensionDbPrune(PDO $pdo): void {
    global $DECODED_EXTENSION_QUEUE_TTL, $DECODED_EXTENSION_LEASE_TTL;
    static $lastPrune = 0;
    $now = time();
    if ($lastPrune > 0 && $lastPrune > $now - 60) return;
    $lastPrune = $now;

    try {
        if ($DECODED_EXTENSION_QUEUE_TTL > 0) {
            $stmt = $pdo->prepare('DELETE FROM task_queue WHERE queued_ts > 0 AND queued_ts < :expire_ts');
            $stmt->execute([':expire_ts' => $now - $DECODED_EXTENSION_QUEUE_TTL]);
        }
        if ($DECODED_EXTENSION_LEASE_TTL > 0) {
            $stmt = $pdo->prepare('DELETE FROM task_leases WHERE created_ts > 0 AND created_ts < :expire_ts');
            $stmt->execute([':expire_ts' => $now - $DECODED_EXTENSION_LEASE_TTL]);
        }
    } catch (\Throwable $_) {}
}

function decodedExtensionDbAccountId(?array $pluginAccount): string {
    return is_array($pluginAccount) ? trim((string)($pluginAccount['accountId'] ?? $pluginAccount['id'] ?? $pluginAccount['name'] ?? '')) : '';
}

function decodedExtensionDbRuntimeScope(?array $pluginAccount): string {
    return is_array($pluginAccount) ? trim((string)($pluginAccount['__storage_scope'] ?? '')) : '';
}

function decodedExtensionDbTaskKey(array $task): string {
    $normalized = decodedExtensionNormalizeTask($task);
    if (!$normalized) return '';
    return (string)($normalized['taskId'] ?? $normalized['task_id'] ?? $normalized['tid'] ?? '') . '|' . decodedExtensionTaskUrl($normalized);
}

function decodedExtensionAcquireTakeLock(?array $pluginAccount = null) {
    global $DECODED_EXTENSION_SQLITE_FILE;
    $scope = decodedExtensionDbAccountId($pluginAccount) . '|' . decodedExtensionDbRuntimeScope($pluginAccount);
    $suffix = $scope !== '' ? ('.' . substr(md5($scope), 0, 16)) : '';
    $lockFile = $DECODED_EXTENSION_SQLITE_FILE . $suffix . '.take.lock';
    $fh = @fopen($lockFile, 'c');
    if (!$fh) return null;
    flock($fh, LOCK_EX);
    return $fh;
}

function deferred(callable $task): void {
    static $queue = null;
    if ($queue === null) {
        $queue = [];
        register_shutdown_function(function () use (&$queue) {
            foreach ($queue as $job) {
                try { $job(); } catch (\Throwable $_) {}
            }
        });
    }
    $queue[] = $task;
}

function jwtExp(string $token): int {
    $parts = explode('.', $token);
    if (count($parts) < 2) return 0;
    $payload = strtr($parts[1], '-_', '+/');
    $payload .= str_repeat('=', (4 - strlen($payload) % 4) % 4);
    $decoded = base64_decode($payload, true);
    if ($decoded === false) return 0;
    $data = json_decode($decoded, true);
    return is_array($data) ? (int)($data['exp'] ?? 0) : 0;
}

function getApi1Token(array $auth, string $tokenFile, bool $forceRefresh = false): array {
    global $LOGIN_TIMEOUT, $LOGIN_CONNECT_TIMEOUT, $STATIC_DNS_RESOLVE;
    if (!$forceRefresh && is_file($tokenFile)) {
        $cached = json_decode((string)@file_get_contents($tokenFile), true);
        $token = is_array($cached) ? (string)($cached['token'] ?? '') : '';
        $expiresAt = is_array($cached) ? (int)($cached['expires_at'] ?? 0) : 0;
        if ($token !== '' && $expiresAt > time() + 60) {
            return ['ok' => true, 'token' => $token, 'cached' => true, 'expires_at' => $expiresAt];
        }
    }

    $body = json_encode([
        'username' => (string)($auth['username'] ?? ''),
        'password' => (string)($auth['password'] ?? ''),
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

    $ch = curl_init((string)($auth['login_url'] ?? ''));
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $body,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Accept: */*'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $LOGIN_TIMEOUT,
        CURLOPT_CONNECTTIMEOUT => $LOGIN_CONNECT_TIMEOUT,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4,
        CURLOPT_DNS_CACHE_TIMEOUT => 300,
        CURLOPT_RESOLVE => $STATIC_DNS_RESOLVE,
    ]);
    $response = curl_exec($ch);
    $error = curl_error($ch);
    $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($error) return ['ok' => false, 'msg' => '接口1登录失败: ' . $error, 'http_code' => $httpCode];
    $json = json_decode((string)$response, true);
    $token = is_array($json) ? (string)($json['data']['token'] ?? '') : '';
    if ($token === '') {
        return ['ok' => false, 'msg' => '接口1登录未返回token', 'http_code' => $httpCode, 'response' => $json ?? $response];
    }

    $expiresAt = jwtExp($token);
    if ($expiresAt <= 0) $expiresAt = time() + 3600;
    @file_put_contents($tokenFile, json_encode([
        'token' => $token,
        'expires_at' => $expiresAt,
        'updated_at' => date('Y-m-d H:i:s'),
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
    cacheApi1TokenUsername($token, (string)($auth['username'] ?? ''), $expiresAt);

    return ['ok' => true, 'token' => $token, 'cached' => false, 'expires_at' => $expiresAt];
}

function loadApi1TokenMap(string $file): array {
    if (!is_file($file)) return [];
    $data = json_decode((string)@file_get_contents($file), true);
    return is_array($data) ? $data : [];
}

function cacheApi1TokenUsername(string $token, string $username, int $expiresAt = 0): void {
    global $API1_TOKEN_MAP_FILE;
    $token = trim($token);
    $username = trim($username);
    if ($token === '' || $username === '') return;

    $map = loadApi1TokenMap($API1_TOKEN_MAP_FILE);
    $now = time();
    foreach ($map as $key => $entry) {
        if (!is_array($entry)) {
            unset($map[$key]);
            continue;
        }
        $entryExpiresAt = (int)($entry['expires_at'] ?? 0);
        if ($entryExpiresAt > 0 && ($entryExpiresAt + 300) < $now) {
            unset($map[$key]);
        }
    }

    $map[md5($token)] = [
        'username' => $username,
        'expires_at' => $expiresAt,
        'updated_at' => date('Y-m-d H:i:s'),
    ];
    if (count($map) > 100) {
        $map = array_slice($map, -100, null, true);
    }

    atomicWrite($API1_TOKEN_MAP_FILE, json_encode($map, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

function resolveApi1UsernameFromToken(string $token): string {
    global $API1_TOKEN_MAP_FILE;
    $token = trim($token);
    if ($token === '') return '';

    $map = loadApi1TokenMap($API1_TOKEN_MAP_FILE);
    $entry = $map[md5($token)] ?? null;
    if (!is_array($entry)) return '';

    $expiresAt = (int)($entry['expires_at'] ?? 0);
    if ($expiresAt > 0 && ($expiresAt + 300) < time()) {
        return '';
    }

    return trim((string)($entry['username'] ?? ''));
}

function readApi1AllowedAccounts(string $file): array {
    if (!is_file($file)) return [];
    $data = json_decode((string)@file_get_contents($file), true);
    if (!is_array($data)) return [];
    $accounts = $data['accounts'] ?? $data;
    if (!is_array($accounts)) return [];
    $result = [];
    foreach ($accounts as $account) {
        if (is_array($account)) {
            $name = trim((string)($account['username'] ?? $account['name'] ?? ''));
            $remark = trim((string)($account['remark'] ?? ''));
        } else {
            $name = trim((string)$account);
            $remark = '';
        }
        if ($name !== '') $result[$name] = ['username' => $name, 'remark' => $remark];
    }
    return array_values($result);
}

function parseAccountLines(string $raw): array {
    $clean = [];
    $lines = preg_split('/\r\n|\r|\n/', $raw) ?: [];
    foreach ($lines as $line) {
        $line = trim((string)$line);
        if ($line === '') continue;
        $normalized = str_replace('｜', '|', $line);
        $remarkJoiner = ' ';
        if (strpos($normalized, '|') !== false) {
            $parts = explode('|', $normalized);
            $remarkJoiner = '|';
        } elseif (preg_match('/\t+/', $line)) {
            $parts = preg_split('/\t+/', $line) ?: [];
        } elseif (preg_match('/[，,]/u', $line)) {
            $parts = preg_split('/[，,]/u', $line) ?: [];
            $remarkJoiner = ',';
        } elseif (preg_match('/[；;]/u', $line)) {
            $parts = preg_split('/[；;]/u', $line) ?: [];
            $remarkJoiner = ';';
        } else {
            $parts = preg_split('/\s+/', $line) ?: [];
        }
        $name = $parts[0] ?? '';
        $remark = implode($remarkJoiner, array_slice($parts, 1));
        $name = trim((string)$name);
        if ($name !== '') $clean[$name] = ['username' => $name, 'remark' => trim((string)$remark)];
    }
    ksort($clean);
    return array_values($clean);
}

function saveApiAccounts(string $file, array $accounts): array {
    @file_put_contents($file, json_encode([
        'accounts' => array_values($accounts),
        'updated_at' => date('Y-m-d H:i:s'),
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
    return ['ok' => true, 'data' => array_values($accounts), 'count' => count($accounts)];
}

function saveApi1AllowedAccounts(string $file, string $raw): array {
    return saveApiAccounts($file, parseAccountLines($raw));
}

function decodedExtensionSyncTaskAccountsToApi1Whitelist(array $taskAccounts, string $fallbackRemark = ''): array {
    global $API1_ACCOUNTS_FILE;
    $allowed = readApi1AllowedAccounts($API1_ACCOUNTS_FILE);
    $map = [];
    foreach ($allowed as $account) {
        if (!is_array($account)) continue;
        $username = trim((string)($account['username'] ?? ''));
        if ($username === '') continue;
        $map[$username] = [
            'username' => $username,
            'remark' => trim((string)($account['remark'] ?? '')),
        ];
    }

    $added = 0;
    $updated = 0;
    foreach ($taskAccounts as $taskAccount) {
        if (!is_array($taskAccount)) continue;
        $username = trim((string)($taskAccount['username'] ?? ''));
        if ($username === '') continue;
        $remark = trim((string)($taskAccount['remark'] ?? ''));
        if ($remark === '') $remark = trim($fallbackRemark);
        if (!isset($map[$username])) {
            $map[$username] = ['username' => $username, 'remark' => $remark];
            $added++;
        } elseif ($map[$username]['remark'] === '' && $remark !== '') {
            $map[$username]['remark'] = $remark;
            $updated++;
        }
    }

    if ($added > 0 || $updated > 0) {
        ksort($map);
        saveApiAccounts($API1_ACCOUNTS_FILE, array_values($map));
    }
    return ['added' => $added, 'updated' => $updated, 'count' => count($map)];
}

function decodedExtensionSyncAllTaskAccountsToApi1Whitelist(): array {
    global $DECODED_EXTENSION_ACCOUNTS_FILE;
    $total = ['added' => 0, 'updated' => 0, 'count' => 0];
    foreach (decodedExtensionReadAccounts($DECODED_EXTENSION_ACCOUNTS_FILE) as $account) {
        if (!is_array($account)) continue;
        $result = decodedExtensionSyncTaskAccountsToApi1Whitelist(
            decodedExtensionNormalizeTaskAccounts($account, false),
            trim((string)($account['remark'] ?? ''))
        );
        $total['added'] += (int)($result['added'] ?? 0);
        $total['updated'] += (int)($result['updated'] ?? 0);
        $total['count'] = (int)($result['count'] ?? $total['count']);
    }
    return $total;
}

function accountNames(array $accounts): array {
    return array_values(array_filter(array_map(fn($a) => is_array($a) ? (string)($a['username'] ?? '') : (string)$a, $accounts)));
}

function accountRemarkMap(array $accounts): array {
    $map = [];
    foreach ($accounts as $account) {
        if (!is_array($account)) continue;
        $username = (string)($account['username'] ?? '');
        if ($username !== '') $map[$username] = (string)($account['remark'] ?? '');
    }
    return $map;
}

function api2DisplayRemark(string $username, array $accountRemarks, array $numberRemarks, string $groupId = ''): string {
    $parts = [];
    $numberRemark = $numberRemarks[$username] ?? '';
    if ($numberRemark !== '') $parts[] = $numberRemark;

    $accountKey = $groupId !== '' ? $groupId : $username;
    $accountRemark = $accountRemarks[$accountKey] ?? '';
    if ($accountRemark === '' && $accountKey !== $username) {
        $accountRemark = $accountRemarks[$username] ?? '';
    }
    if ($accountRemark !== '' && !in_array($accountRemark, $parts, true)) {
        $parts[] = $accountRemark;
    }
    return implode(' / ', $parts);
}

function displayAccountRemark(int $apiType, string $username, string $groupId = ''): string {
    global $API1_ACCOUNTS_FILE, $API2_NUMBERS_FILE;
    if ($apiType === 2) {
        return api2DisplayRemark(
            $username,
            [],
            accountRemarkMap(readApi1AllowedAccounts($API2_NUMBERS_FILE)),
            $groupId
        );
    }
    if ($apiType === 1) {
        $api1Remarks = accountRemarkMap(readApi1AllowedAccounts($API1_ACCOUNTS_FILE));
        return $api1Remarks[$username] ?? '';
    }

    $api1Remarks = accountRemarkMap(readApi1AllowedAccounts($API1_ACCOUNTS_FILE));
    if (($api1Remarks[$username] ?? '') !== '') return $api1Remarks[$username];
    return api2DisplayRemark(
        $username,
        [],
        accountRemarkMap(readApi1AllowedAccounts($API2_NUMBERS_FILE)),
        $groupId
    );
}

function displayDecodedExtensionAccountRemark(string $accountId): string {
    global $DECODED_EXTENSION_ACCOUNTS_FILE;
    $accountId = trim($accountId);
    if ($accountId === '') return '';
    $accounts = decodedExtensionReadAccounts($DECODED_EXTENSION_ACCOUNTS_FILE);
    foreach ($accounts as $account) {
        if (!is_array($account)) continue;
        if ((string)($account['accountId'] ?? '') === $accountId) {
            return trim((string)($account['remark'] ?? ''));
        }
    }
    return '';
}

function api1LoginWithPassword(string $url, string $username, string $password): array {
    global $LOGIN_TIMEOUT, $LOGIN_CONNECT_TIMEOUT, $STATIC_DNS_RESOLVE;
    $body = json_encode(['username' => $username, 'password' => $password], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $body,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Accept: */*'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $LOGIN_TIMEOUT,
        CURLOPT_CONNECTTIMEOUT => $LOGIN_CONNECT_TIMEOUT,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4,
        CURLOPT_DNS_CACHE_TIMEOUT => 300,
        CURLOPT_RESOLVE => $STATIC_DNS_RESOLVE,
    ]);
    $response = curl_exec($ch);
    $error = curl_error($ch);
    $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return ['response' => $response, 'error' => $error, 'http_code' => $httpCode];
}

function appendLog(string $file, array $entry, int $max): void {
    $json = json_encode($entry, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    @file_put_contents($file, $json . "\n", FILE_APPEND | LOCK_EX);
    if (mt_rand(1, 50) !== 1) return;
    $size = @filesize($file);
    if ($size === false || $size < 5 * 1024 * 1024) return;
    $lines = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (is_array($lines) && count($lines) > $max) {
        atomicWrite($file, implode("\n", array_slice($lines, -$max)) . "\n");
    }
}

function readLogs(string $file, int $limit = 50): array {
    if (!is_file($file)) return [];
    $lines = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) return [];
    $lines = array_slice($lines, -$limit);
    $result = [];
    foreach (array_reverse($lines) as $line) {
        $d = json_decode($line, true);
        if ($d) $result[] = $d;
    }
    return $result;
}

function jsonResp(array $data): void {
    $payload = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Length: ' . strlen($payload));
    header('Connection: close');
    echo $payload;
    if (function_exists('fastcgi_finish_request')) {
        fastcgi_finish_request();
    } else {
        @ob_end_flush();
        @flush();
    }
    exit;
}

function readDeviceControls(string $file): array {
    if (!is_file($file)) return [];
    $data = json_decode((string)@file_get_contents($file), true);
    return is_array($data) ? $data : [];
}

function saveDeviceControls(string $file, array $devices): void {
    @file_put_contents($file, json_encode($devices, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
}

function deviceKey(string $username, string $deviceId): string {
    return md5($username . '|' . $deviceId);
}

function updateDeviceHeartbeat(string $file, array $input): array {
    global $HEARTBEAT_WRITE_INTERVAL;
    $username = trim((string)($input['username'] ?? $input['用户名'] ?? ''));
    $groupId = trim((string)($input['group_id'] ?? $input['组ID'] ?? ''));
    $deviceId = trim((string)($input['device_id'] ?? $input['设备ID'] ?? ''));
    if ($username === '') $username = 'unknown';
    if ($deviceId === '') $deviceId = 'unknown-' . substr(md5($_SERVER['REMOTE_ADDR'] ?? ''), 0, 8);

    $devices = readDeviceControls($file);
    $key = deviceKey($username, $deviceId);
    $old = $devices[$key] ?? [];
    $disabled = !empty($old['disabled']);
    $apiType = (int)($input['api_type'] ?? ($old['api_type'] ?? 0));
    $now = time();
    $oldSeen = strtotime((string)($old['last_seen'] ?? '')) ?: 0;
    $fingerprintKey = trim((string)($input['fingerprint_key'] ?? ''));
    $fingerprintId = trim((string)($input['fingerprint_id'] ?? ''));
    $fingerprintName = trim((string)($input['fingerprint_name'] ?? ''));
    $platform = strtolower(trim((string)($input['platform'] ?? $input['device_type'] ?? $old['platform'] ?? '')));
    $client = trim((string)($input['client'] ?? $old['client'] ?? ''));
    $deviceLabel = $platform === 'ios' ? 'iOS设备' : (trim((string)($input['device_label'] ?? $old['device_label'] ?? '')) ?: ($platform !== '' ? strtoupper($platform) . '设备' : ''));
    $sameFingerprint =
        (string)($old['fingerprint_key'] ?? '') === $fingerprintKey &&
        (string)($old['fingerprint_id'] ?? '') === $fingerprintId &&
        (string)($old['fingerprint_name'] ?? '') === $fingerprintName;
    if (!empty($old) && !$disabled && $sameFingerprint && ($now - $oldSeen) < $HEARTBEAT_WRITE_INTERVAL) {
        return [
            'ok' => true,
            'allowed' => true,
            'msg' => 'ok',
            'device_key' => $key,
            'throttled' => true,
        ];
    }
    $extensionRemark = ($client === 'gejie-extension' || str_contains($platform, 'extension')) ? displayDecodedExtensionAccountRemark($username) : '';
    $accountRemark = $extensionRemark !== '' ? $extensionRemark : displayAccountRemark($apiType, $username, $groupId);
    $devices[$key] = array_merge($old, [
        'key' => $key,
        'username' => $username,
        'account_remark' => $accountRemark !== '' ? $accountRemark : ($old['account_remark'] ?? ''),
        'group_id' => $groupId,
        'device_id' => $deviceId,
        'fingerprint_key' => $fingerprintKey,
        'fingerprint_id' => $fingerprintId,
        'fingerprint_name' => $fingerprintName,
        'api_type' => $apiType,
        'platform' => $platform,
        'device_type' => $platform,
        'device_label' => $deviceLabel,
        'client' => $client,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
        'last_seen' => date('Y-m-d H:i:s'),
        'first_seen' => $old['first_seen'] ?? date('Y-m-d H:i:s'),
        'disabled' => $disabled,
        'disabled_reason' => $old['disabled_reason'] ?? '',
    ]);
    saveDeviceControls($file, $devices);

    return [
        'ok' => true,
        'allowed' => !$disabled,
        'msg' => $disabled ? ($devices[$key]['disabled_reason'] ?: '设备已被禁用') : 'ok',
        'device_key' => $key,
    ];
}

function checkDeviceAllowed(string $file, array $input): array {
    $username = trim((string)($input['username'] ?? $input['用户名'] ?? ''));
    $deviceId = trim((string)($input['device_id'] ?? $input['设备ID'] ?? ''));
    if ($username === '' || $deviceId === '') return ['allowed' => true];

    $devices = readDeviceControls($file);
    $key = deviceKey($username, $deviceId);
    if (!empty($devices[$key]['disabled'])) {
        return [
            'allowed' => false,
            'msg' => $devices[$key]['disabled_reason'] ?: '设备已被禁用',
            'device_key' => $key,
        ];
    }
    updateDeviceHeartbeat($file, $input);
    return ['allowed' => true, 'device_key' => $key];
}

function updateDeviceControl(string $file, string $key, bool $disabled, string $reason = ''): array {
    $devices = readDeviceControls($file);
    if ($key === '' || empty($devices[$key])) {
        return ['ok' => false, 'msg' => '设备不存在'];
    }

    $devices[$key]['disabled'] = $disabled;
    $devices[$key]['disabled_reason'] = $disabled ? $reason : '';
    $devices[$key]['updated_at'] = date('Y-m-d H:i:s');
    saveDeviceControls($file, $devices);

    return [
        'ok' => true,
        'msg' => $disabled ? '设备已禁用' : '设备已启用',
        'data' => $devices[$key],
    ];
}


function readAndroidSessions(string $file): array {
    if (!is_file($file)) return [];
    $data = json_decode((string)@file_get_contents($file), true);
    return is_array($data) ? $data : [];
}

function saveAndroidSessions(string $file, array $sessions): void {
    @file_put_contents($file, json_encode($sessions, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
}

function androidManagedDeviceKeyFromInput(array $input): string {
    $username = trim((string)($input['username'] ?? '')) ?: 'unknown';
    $deviceId = trim((string)($input['device_id'] ?? '')) ?: ('unknown-' . substr(md5($_SERVER['REMOTE_ADDR'] ?? ''), 0, 8));
    return deviceKey($username, $deviceId);
}

function syncAndroidSession(string $sessionFile, string $deviceFile, array $input): array {
    $username = trim((string)($input['username'] ?? '')) ?: 'unknown';
    $deviceId = trim((string)($input['device_id'] ?? '')) ?: ('unknown-' . substr(md5($_SERVER['REMOTE_ADDR'] ?? ''), 0, 8));
    $key = deviceKey($username, $deviceId);
    $cookie = trim((string)($input['cookies'] ?? $input['cookie'] ?? ''));
    $cookieUrl = trim((string)($input['cookie_url'] ?? $input['url'] ?? ''));
    $host = trim((string)($input['cookie_host'] ?? ''));
    if ($host === '' && $cookieUrl !== '') {
        $parts = parse_url($cookieUrl);
        $host = is_array($parts) ? (string)($parts['host'] ?? '') : '';
    }
    if ($cookie === '') return ['ok' => false, 'success' => false, 'msg' => 'cookie empty'];

    $deviceCheck = checkDeviceAllowed($deviceFile, $input + ['username' => $username, 'device_id' => $deviceId, 'api_type' => 1]);
    if (empty($deviceCheck['allowed'])) return ['ok' => false, 'success' => false, 'msg' => $deviceCheck['msg'] ?? 'device disabled', 'device_key' => $key];

    $sessions = readAndroidSessions($sessionFile);
    $sessions[$key] = [
        'key' => $key,
        'username' => $username,
        'device_id' => $deviceId,
        'fingerprint_key' => trim((string)($input['fingerprint_key'] ?? '')),
        'device_label' => trim((string)($input['device_label'] ?? '')),
        'cookie' => $cookie,
        'cookie_len' => strlen($cookie),
        'cookie_url' => $cookieUrl,
        'cookie_host' => $host,
        'user_agent' => trim((string)($input['user_agent'] ?? $input['ua'] ?? '')),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
        'updated_at' => date('Y-m-d H:i:s'),
    ];
    saveAndroidSessions($sessionFile, $sessions);

    $devices = readDeviceControls($deviceFile);
    $old = $devices[$key] ?? [];
    $devices[$key] = array_merge($old, [
        'key' => $key,
        'username' => $username,
        'device_id' => $deviceId,
        'fingerprint_key' => trim((string)($input['fingerprint_key'] ?? ($old['fingerprint_key'] ?? ''))),
        'platform' => 'android',
        'device_type' => trim((string)($input['device_type'] ?? 'android')),
        'device_label' => trim((string)($input['device_label'] ?? ($old['device_label'] ?? 'Android'))),
        'client' => trim((string)($input['client'] ?? 'ajie-android')),
        'client_label' => trim((string)($input['client_label'] ?? 'Ajie Android')),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
        'last_seen' => date('Y-m-d H:i:s'),
        'first_seen' => $old['first_seen'] ?? date('Y-m-d H:i:s'),
        'disabled' => !empty($old['disabled']),
        'disabled_reason' => $old['disabled_reason'] ?? '',
        'has_android_session' => true,
        'android_session_at' => date('Y-m-d H:i:s'),
        'android_cookie_host' => $host,
        'android_command' => $old['android_command'] ?? 'run',
        'android_poll_interval_seconds' => max(10, (int)($old['android_poll_interval_seconds'] ?? 30)),
    ]);
    saveDeviceControls($deviceFile, $devices);

    return ['ok' => true, 'success' => true, 'msg' => 'session synced', 'device_key' => $key, 'data' => ['has_session' => true, 'cookie_host' => $host]];
}


function clearAndroidSession(string $sessionFile, string $deviceFile, array $input): array {
    $username = trim((string)($input['username'] ?? '')) ?: 'unknown';
    $deviceId = trim((string)($input['device_id'] ?? '')) ?: ('unknown-' . substr(md5($_SERVER['REMOTE_ADDR'] ?? ''), 0, 8));
    $key = deviceKey($username, $deviceId);
    $sessions = readAndroidSessions($sessionFile);
    if (isset($sessions[$key])) {
        unset($sessions[$key]);
        saveAndroidSessions($sessionFile, $sessions);
    }
    $devices = readDeviceControls($deviceFile);
    if (isset($devices[$key])) {
        $devices[$key]['has_android_session'] = false;
        $devices[$key]['android_has_cookie'] = false;
        $devices[$key]['android_session_at'] = '';
        $devices[$key]['android_cookie_host'] = '';
        $devices[$key]['updated_at'] = date('Y-m-d H:i:s');
        saveDeviceControls($deviceFile, $devices);
    }
    return ['ok' => true, 'success' => true, 'msg' => 'session cleared', 'device_key' => $key];
}

function pollAndroidDevice(string $deviceFile, string $sessionFile, array $input): array {
    $hb = updateDeviceHeartbeat($deviceFile, $input + ['api_type' => 1, 'platform' => 'android', 'client' => ($input['client'] ?? 'ajie-android')]);
    $key = (string)($hb['device_key'] ?? androidManagedDeviceKeyFromInput($input));
    $devices = readDeviceControls($deviceFile);
    $device = $devices[$key] ?? [];
    if (isset($devices[$key])) {
        $devices[$key]['android_has_task_token'] = !empty($input['has_task_token']);
        $devices[$key]['android_has_cookie'] = !empty($input['has_cookie']);
        $devices[$key]['updated_at'] = date('Y-m-d H:i:s');
        saveDeviceControls($deviceFile, $devices);
        $device = $devices[$key];
    }
    $sessions = readAndroidSessions($sessionFile);
    $hasSession = !empty($sessions[$key]['cookie']);
    $disabled = !empty($device['disabled']);
    $command = $disabled ? 'stop' : (string)($device['android_command'] ?? 'run');
    if (!$hasSession && $command === 'run') $command = 'sync_session';
    $interval = max(10, (int)($device['android_poll_interval_seconds'] ?? 30));
    return [
        'ok' => true,
        'success' => true,
        'allowed' => !$disabled,
        'device_key' => $key,
        'command' => $command,
        'data' => [
            'command' => $command,
            'has_session' => $hasSession,
            'poll_interval_seconds' => $interval,
            'disabled_reason' => $device['disabled_reason'] ?? '',
            'server_time' => date('Y-m-d H:i:s'),
        ],
    ];
}

function updateAndroidDeviceCommand(string $deviceFile, string $key, string $command, int $pollInterval = 0): array {
    $allowed = ['run', 'pause', 'stop', 'sync_session', 'clear_session'];
    if (!in_array($command, $allowed, true)) return ['ok' => false, 'msg' => 'bad command'];
    $devices = readDeviceControls($deviceFile);
    if ($key === '' || empty($devices[$key])) return ['ok' => false, 'msg' => 'device not found'];
    $devices[$key]['android_command'] = $command;
    if ($pollInterval > 0) $devices[$key]['android_poll_interval_seconds'] = max(10, min(300, $pollInterval));
    $devices[$key]['updated_at'] = date('Y-m-d H:i:s');
    saveDeviceControls($deviceFile, $devices);
    return ['ok' => true, 'msg' => 'command saved', 'data' => $devices[$key]];
}

function readUpdateConfig(string $file): array {
    $defaults = [
        'version_code' => 1,
        'version_name' => '1.0.0',
        'apk_url' => '',
        'title' => '发现新版本',
        'message' => '',
        'force' => false,
        'updated_at' => '',
    ];
    if (!is_file($file)) return $defaults;
    $data = json_decode((string)@file_get_contents($file), true);
    return is_array($data) ? array_merge($defaults, $data) : $defaults;
}

function saveUpdateConfig(string $file, array $input): array {
    $config = readUpdateConfig($file);
    $config['version_code'] = max(1, (int)($input['version_code'] ?? $config['version_code']));
    $config['version_name'] = trim((string)($input['version_name'] ?? $config['version_name']));
    $config['apk_url'] = trim((string)($input['apk_url'] ?? $config['apk_url']));
    $config['title'] = trim((string)($input['title'] ?? $config['title']));
    $config['message'] = trim((string)($input['message'] ?? $config['message']));
    $config['force'] = !empty($input['force']) && (string)$input['force'] !== '0' && $input['force'] !== 'false';
    $config['updated_at'] = date('Y-m-d H:i:s');

    @file_put_contents($file, json_encode($config, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
    return ['ok' => true, 'msg' => '更新配置已保存', 'data' => $config];
}

function uploadUpdateApk(string $configFile, string $apkDir, array $input, array $files): array {
    if (empty($files['apk']) || !is_uploaded_file($files['apk']['tmp_name'])) {
        return saveUpdateConfig($configFile, $input);
    }
    if (($files['apk']['error'] ?? UPLOAD_ERR_OK) !== UPLOAD_ERR_OK) {
        return ['ok' => false, 'msg' => 'APK上传失败，错误码: ' . (int)$files['apk']['error']];
    }
    $original = (string)($files['apk']['name'] ?? '');
    if (strtolower(pathinfo($original, PATHINFO_EXTENSION)) !== 'apk') {
        return ['ok' => false, 'msg' => '只允许上传 .apk 文件'];
    }
    if (!is_dir($apkDir)) @mkdir($apkDir, 0755, true);

    $versionCode = max(1, (int)($input['version_code'] ?? 1));
    $safeName = 'taskhelper_v' . $versionCode . '_' . date('Ymd_His') . '.apk';
    $target = $apkDir . '/' . $safeName;
    if (!move_uploaded_file($files['apk']['tmp_name'], $target)) {
        return ['ok' => false, 'msg' => '保存APK失败，请检查目录权限'];
    }

    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? '';
    $basePath = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/\\');
    $apkUrl = $scheme . '://' . $host . ($basePath ? $basePath : '') . '/app_updates/' . rawurlencode($safeName);

    $input['apk_url'] = $apkUrl;
    $saved = saveUpdateConfig($configFile, $input);
    if (!empty($saved['data'])) {
        $saved['data']['apk_file'] = $safeName;
        $saved['data']['apk_size'] = filesize($target);
    }
    return $saved;
}

function buildUpdateResponse(string $file, int $currentCode): array {
    $config = readUpdateConfig($file);
    $hasUpdate = !empty($config['apk_url']) && (int)$config['version_code'] > $currentCode;
    return [
        'ok' => true,
        'has_update' => $hasUpdate,
        'version_code' => (int)$config['version_code'],
        'version_name' => (string)$config['version_name'],
        'apk_url' => (string)$config['apk_url'],
        'title' => (string)$config['title'],
        'message' => (string)$config['message'],
        'force' => !empty($config['force']),
        'updated_at' => (string)$config['updated_at'],
    ];
}

function pluginVersionCodeFromString(string $version): int {
    $parts = preg_split('/[^0-9]+/', $version) ?: [];
    $nums = [];
    foreach ($parts as $part) {
        if ($part === '') continue;
        $nums[] = max(0, (int)$part);
        if (count($nums) >= 4) break;
    }
    while (count($nums) < 4) $nums[] = 0;
    return $nums[0] * 1000000 + $nums[1] * 10000 + $nums[2] * 100 + $nums[3];
}

function readPluginUpdateConfig(string $file): array {
    $defaults = [
        'enabled' => true,
        'version_code' => 1000000,
        'version_name' => '1.0.0',
        'package_url' => '',
        'package_name' => '',
        'package_size' => 0,
        'title' => '发现插件新版本',
        'message' => '',
        'force' => false,
        'updated_at' => '',
    ];
    if (!is_file($file)) return $defaults;
    $data = json_decode((string)@file_get_contents($file), true);
    return is_array($data) ? array_merge($defaults, $data) : $defaults;
}

function savePluginUpdateConfig(string $file, array $input): array {
    $config = readPluginUpdateConfig($file);
    $versionName = trim((string)($input['version_name'] ?? $config['version_name']));
    $versionCode = (int)($input['version_code'] ?? 0);
    if ($versionCode < 1) $versionCode = pluginVersionCodeFromString($versionName);
    $config['enabled'] = !array_key_exists('enabled', $input) || ((string)$input['enabled'] !== '0' && $input['enabled'] !== false && $input['enabled'] !== 'false');
    $config['version_code'] = max(1, $versionCode);
    $config['version_name'] = $versionName !== '' ? $versionName : $config['version_name'];
    $config['package_url'] = trim((string)($input['package_url'] ?? $config['package_url']));
    $config['title'] = trim((string)($input['title'] ?? $config['title']));
    $config['message'] = trim((string)($input['message'] ?? $config['message']));
    $config['force'] = !empty($input['force']) && (string)$input['force'] !== '0' && $input['force'] !== 'false';
    $config['updated_at'] = date('Y-m-d H:i:s');
    atomicWrite($file, json_encode($config, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    return ['ok' => true, 'msg' => '插件更新配置已保存', 'data' => $config];
}

function uploadPluginUpdatePackage(string $configFile, string $packageDir, array $input, array $files): array {
    if (empty($files['package']) || !is_uploaded_file($files['package']['tmp_name'])) {
        return savePluginUpdateConfig($configFile, $input);
    }
    if (($files['package']['error'] ?? UPLOAD_ERR_OK) !== UPLOAD_ERR_OK) {
        return ['ok' => false, 'msg' => '插件包上传失败，错误码: ' . (int)$files['package']['error']];
    }
    $original = (string)($files['package']['name'] ?? '');
    $ext = strtolower(pathinfo($original, PATHINFO_EXTENSION));
    if (!in_array($ext, ['zip', 'crx'], true)) {
        return ['ok' => false, 'msg' => '只允许上传 .zip 或 .crx 插件包'];
    }
    if (!is_dir($packageDir)) @mkdir($packageDir, 0755, true);
    $versionName = trim((string)($input['version_name'] ?? '1.0.0')) ?: '1.0.0';
    $versionCode = max(1, (int)($input['version_code'] ?? pluginVersionCodeFromString($versionName)));
    $safeVersion = preg_replace('/[^0-9A-Za-z._-]+/', '_', $versionName);
    $safeName = 'ajie_plugin_v' . $safeVersion . '_' . $versionCode . '_' . date('Ymd_His') . '.' . $ext;
    $target = rtrim($packageDir, '/\\') . '/' . $safeName;
    if (!move_uploaded_file($files['package']['tmp_name'], $target)) {
        return ['ok' => false, 'msg' => '保存插件包失败，请检查目录权限'];
    }
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? '';
    $basePath = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/\\');
    $packageUrl = $scheme . '://' . $host . ($basePath ? $basePath : '') . '/plugin_updates/' . rawurlencode($safeName);
    $input['package_url'] = $packageUrl;
    $input['version_code'] = $versionCode;
    $input['version_name'] = $versionName;
    $saved = savePluginUpdateConfig($configFile, $input);
    if (!empty($saved['data'])) {
        $saved['data']['package_name'] = $safeName;
        $saved['data']['package_size'] = filesize($target);
        atomicWrite($configFile, json_encode($saved['data'], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }
    return $saved;
}

function buildPluginUpdateResponse(string $file, string $currentVersion = '', int $currentCode = 0): array {
    $config = readPluginUpdateConfig($file);
    if ($currentCode < 1 && $currentVersion !== '') $currentCode = pluginVersionCodeFromString($currentVersion);
    $hasUpdate = !empty($config['enabled']) && !empty($config['package_url']) && (int)$config['version_code'] > max(0, $currentCode);
    return [
        'ok' => true,
        'has_update' => $hasUpdate,
        'current_version' => $currentVersion,
        'current_version_code' => $currentCode,
        'version_code' => (int)$config['version_code'],
        'version_name' => (string)$config['version_name'],
        'package_url' => (string)$config['package_url'],
        'download_url' => (string)$config['package_url'],
        'title' => (string)$config['title'],
        'message' => (string)$config['message'],
        'force' => !empty($config['force']),
        'updated_at' => (string)$config['updated_at'],
    ];
}

function readVersionControls(string $file): array {
    $defaults = [
        'min_version_code' => 0,
        'min_version_msg' => '您的版本已停用，请更新到最新版本',
        'blocked_versions' => [],
        'api2_login_min' => 0,
        'api2_login_max' => 10000,
        'updated_at' => '',
    ];
    if (!is_file($file)) return $defaults;
    $data = json_decode((string)@file_get_contents($file), true);
    return is_array($data) ? array_merge($defaults, $data) : $defaults;
}

function saveVersionControls(string $file, array $input): array {
    $config = readVersionControls($file);
    $config['min_version_code'] = max(0, (int)($input['min_version_code'] ?? $config['min_version_code']));
    $config['min_version_msg'] = trim((string)($input['min_version_msg'] ?? $config['min_version_msg']));
    if (isset($input['blocked_versions']) && is_array($input['blocked_versions'])) {
        $config['blocked_versions'] = $input['blocked_versions'];
    }
    $api2Min = max(0, (int)($input['api2_login_min'] ?? $config['api2_login_min']));
    $api2Max = max($api2Min, (int)($input['api2_login_max'] ?? $config['api2_login_max']));
    $config['api2_login_min'] = $api2Min;
    $config['api2_login_max'] = $api2Max;
    $config['updated_at'] = date('Y-m-d H:i:s');
    @file_put_contents($file, json_encode($config, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
    return ['ok' => true, 'msg' => '版本控制已保存', 'data' => $config];
}

function checkVersionBlocked(string $file, int $versionCode): array {
    $config = readVersionControls($file);
    if ($config['min_version_code'] > 0 && $versionCode > 0 && $versionCode < $config['min_version_code']) {
        return ['blocked' => true, 'message' => $config['min_version_msg'] ?: '您的版本已停用，请更新到最新版本'];
    }
    $blocked = $config['blocked_versions'] ?? [];
    $key = (string)$versionCode;
    if (isset($blocked[$key])) {
        $msg = is_array($blocked[$key]) ? ($blocked[$key]['message'] ?? '') : (string)$blocked[$key];
        return ['blocked' => true, 'message' => $msg ?: '此版本已停用，请更新'];
    }
    return ['blocked' => false];
}

function jsonDecodeAssoc(string $json): ?array {
    $decoded = json_decode($json, true);
    return json_last_error() === JSON_ERROR_NONE && is_array($decoded) ? $decoded : null;
}

function webPluginBase64UrlDecode(string $value) {
    $value = strtr($value, '-_', '+/');
    $value .= str_repeat('=', (4 - strlen($value) % 4) % 4);
    return base64_decode($value, true);
}

function normalizeWebPluginAliases(array $input): array {
    $actMap = [
        'l' => 'api1_login',
        't' => 'api1_take',
        's' => 'api1_submit',
        'h' => 'heartbeat',
    ];
    $action = trim((string)($input['act'] ?? $input['a'] ?? ''));
    if (isset($actMap[$action])) $action = $actMap[$action];
    if ($action !== '') $input['act'] = $action;

    $aliasMap = [
        'u' => 'username',
        'p' => 'password',
        'k' => 'auth_token',
        'q' => 'url',
        'r' => 'result',
        'av' => 'appVersion',
        'sid' => 'submit_id',
        'tid' => 'task_id',
        'deal_id' => 'deal_id',
        'tr' => 'trace_id',
        'iid' => 'item_id',
        'sh' => 'shop_id',
        'pu' => 'product_url',
        'pd' => 'pdp_url',
        'g' => 'group_id',
        'did' => 'device_id',
        'at' => 'api_type',
        'pf' => 'platform',
        'dt' => 'device_type',
        'dl' => 'device_label',
        'c' => 'client',
        'fk' => 'fingerprint_key',
        'fid' => 'fingerprint_id',
        'fn' => 'fingerprint_name',
    ];

    foreach ($aliasMap as $from => $to) {
        if (array_key_exists($from, $input) && (!array_key_exists($to, $input) || $input[$to] === '')) {
            $input[$to] = $input[$from];
        }
    }

    if (!isset($input['api_type']) && in_array((string)($input['act'] ?? ''), ['api1_login', 'api1_take', 'api1_submit', 'heartbeat'], true)) {
        $input['api_type'] = 1;
    }
    return $input;
}

function applyWebPluginServerDefaults(array $input): array {
    global $WEB_PLUGIN_AUTH;
    if (empty($input['_web_obfuscated'])) return $input;

    $serverUsername = trim((string)($WEB_PLUGIN_AUTH['username'] ?? ''));
    $serverPassword = (string)($WEB_PLUGIN_AUTH['password'] ?? '');
    if (trim((string)($input['username'] ?? '')) === '' && $serverUsername !== '') $input['username'] = $serverUsername;
    if (trim((string)($input['group_id'] ?? '')) === '' && $serverUsername !== '') $input['group_id'] = $serverUsername;
    if (($input['act'] ?? '') === 'api1_login' && (string)($input['password'] ?? '') === '' && $serverPassword !== '') {
        $input['password'] = $serverPassword;
    }
    return $input;
}

function normalizeWebPluginPayload(array $input): array {
    if (isset($input['x']) && is_string($input['x'])) {
        $decodedRaw = webPluginBase64UrlDecode((string)$input['x']);
        if ($decodedRaw === false) jsonResp(['ok' => false, 'msg' => '网页插件参数解析失败']);

        $decoded = json_decode($decodedRaw, true);
        if (!is_array($decoded)) jsonResp(['ok' => false, 'msg' => '网页插件参数解析失败']);

        $body = isset($decoded['b']) && is_array($decoded['b']) ? $decoded['b'] : $decoded;
        $action = trim((string)($decoded['a'] ?? $body['a'] ?? ''));
        if ($action !== '') $body['a'] = $action;
        $body['_web_obfuscated'] = true;
        return applyWebPluginServerDefaults(normalizeWebPluginAliases($body));
    }

    return normalizeWebPluginAliases($input);
}

function isControllerPayload(array $input): bool {
    $checks = [
        strtolower(trim((string)($input['client'] ?? ''))),
        trim((string)($input['device_label'] ?? '')),
        trim((string)($input['fingerprint_name'] ?? '')),
        strtolower(trim((string)($input['device_id'] ?? ''))),
        strtolower(trim((string)($input['fingerprint_key'] ?? ''))),
        strtolower(trim((string)($input['fingerprint_id'] ?? ''))),
        strtolower(trim((string)($input['source'] ?? ''))),
    ];
    foreach ($checks as $value) {
        if ($value === '') continue;
        if ($value === 'gejie-controller') return true;
        if ($value === '中控' || $value === 'ajie中控') return true;
        if (strpos($value, 'ctrl-') === 0 || strpos($value, 'ctrl_') === 0) return true;
        if (strpos($value, 'gejie-controller') !== false || strpos($value, '中控') !== false) return true;
    }
    return false;
}

function isWebPluginPayload(array $input): bool {
    if (isControllerPayload($input)) return false;
    $source = strtolower(trim((string)($input['source'] ?? '')));
    $client = strtolower(trim((string)($input['client'] ?? '')));
    $deviceType = strtolower(trim((string)($input['device_type'] ?? '')));
    $platform = strtolower(trim((string)($input['platform'] ?? '')));
    return strpos($source, 'web_') === 0
        || !empty($input['_web_obfuscated'])
        || $client === 'gejie-extension'
        || $deviceType === 'web'
        || $platform === 'web';
}

function resolveClientLabel(array $input): string {
    if (isControllerPayload($input)) return '中控';
    if (isWebPluginPayload($input)) return '网页插件';
    return '';
}

function resolveLogSource(array $input, string $defaultSource, string $webSource, string $controllerSource): string {
    if (isControllerPayload($input)) return $controllerSource;
    if (isWebPluginPayload($input)) return $webSource;
    return $defaultSource;
}

function elapsedMs(float $start): int {
    return (int)round((microtime(true) - $start) * 1000);
}

function durationMs(float $start, float $end): int {
    return (int)round(($end - $start) * 1000);
}

function api2ForwardPayload(string $username, string $groupId, array $taskInfo, array $actualData): array {
    return [
        "\u{7528}\u{6237}\u{540d}" => $username,
        "\u{7ec4}ID" => $groupId,
        "\u{4efb}\u{52a1}\u{6570}\u{636e}" => $taskInfo,
        'data' => $actualData,
    ];
}

function api1ForwardSuccess($serverResp): bool {
    if (!is_array($serverResp)) return false;
    $respCode = (string)($serverResp['code'] ?? '');
    $respData = is_array($serverResp['data'] ?? null) ? $serverResp['data'] : null;
    $respDataCode = is_array($respData) ? (string)($respData['code'] ?? '') : '';
    $respDataMsgIsNull = is_array($respData) && array_key_exists('msg', $respData) && $respData['msg'] === null;
    return $respCode === '200' && $respDataCode === 'SUCCESS' && $respDataMsgIsNull;
}

function api1SubmitFailureMessage($serverResp, string $fallback = 'upstream submit failed'): string {
    if (!is_array($serverResp)) {
        $raw = trim((string)$serverResp);
        return $raw !== '' ? $fallback . ': ' . mb_substr($raw, 0, 180) : $fallback;
    }
    $data = is_array($serverResp['data'] ?? null) ? $serverResp['data'] : [];
    $parts = [];
    foreach ([
        'code' => $serverResp['code'] ?? '',
        'msg' => $serverResp['msg'] ?? '',
        'data_code' => $data['code'] ?? '',
        'data_msg' => $data['msg'] ?? '',
    ] as $key => $value) {
        if ($value === null || $value === '') continue;
        $parts[] = $key . '=' . (is_scalar($value) ? (string)$value : json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }
    return $parts ? $fallback . ': ' . implode(' ', $parts) : $fallback;
}

function api1ParseTimeoutResponse($serverResp, string $raw): bool {
    $haystack = $raw;
    if (is_array($serverResp)) {
        $encoded = json_encode($serverResp, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if (is_string($encoded)) $haystack .= "\n" . $encoded;
    }
    return strpos($haystack, '解析超时') !== false
        || stripos($haystack, 'parse timeout') !== false
        || stripos($haystack, 'parse timed out') !== false;
}

function api1SubmitDealNotFound($serverResp): bool {
    $haystack = is_array($serverResp) ? (json_encode($serverResp, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '') : (string)$serverResp;
    return stripos($haystack, 'not found took task for deal_id') !== false;
}

function api2ForwardSuccess($serverResp): bool {
    if (!is_array($serverResp)) return false;
    $ok = $serverResp['ok'] ?? null;
    if ($ok === true || $ok === 1 || $ok === '1') return true;
    if (is_string($ok) && strtolower(trim($ok)) === 'true') return true;
    $code = strtoupper(trim((string)($serverResp['code'] ?? '')));
    if ($code === '200' || $code === 'SUCCESS') return true;
    $data = $serverResp['data'] ?? null;
    if (is_array($data)) {
        $dataCode = strtoupper(trim((string)($data['code'] ?? '')));
        $dataMsg = $data['msg'] ?? null;
        if ($dataCode === 'SUCCESS' && ($dataMsg === null || $dataMsg === '')) return true;
    }
    return false;
}

function forwardAttemptSummary(array $result, $serverResp): array {
    return [
        'http_code' => (int)($result['http_code'] ?? 0),
        'error' => (string)($result['error'] ?? ''),
        'response_code' => is_array($serverResp) ? (string)($serverResp['code'] ?? '') : '',
        'response_msg' => is_array($serverResp) ? (string)($serverResp['msg'] ?? '') : '',
        'curl_ms' => (int)($result['curl_total_ms'] ?? 0),
    ];
}

function compactLogResponse($response, int $maxBytes) {
    if (is_array($response)) {
        $encoded = json_encode($response, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if (is_string($encoded) && strlen($encoded) > $maxBytes) {
            return [
                '_truncated' => true,
                '_bytes' => strlen($encoded),
                'preview' => mb_substr($encoded, 0, $maxBytes),
            ];
        }
        return $response;
    }

    $text = (string)$response;
    if (strlen($text) > $maxBytes) {
        return [
            '_truncated' => true,
            '_bytes' => strlen($text),
            'preview' => mb_substr($text, 0, $maxBytes),
        ];
    }
    return $response;
}

function decodedExtensionApiPath(): string {
    $path = (string)parse_url((string)($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH);
    $pathInfo = (string)($_SERVER['PATH_INFO'] ?? '');
    foreach ([$pathInfo, $path] as $candidate) {
        if (preg_match('#/(api/(login|task|submit|heartbeat))/?$#', $candidate, $m)) {
            return '/' . $m[1];
        }
    }
    return '';
}

function decodedExtensionCorsHeaders(): void {
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
    header('Access-Control-Max-Age: 86400');
}

function decodedExtensionBearerToken(): string {
    $authHeader = (string)($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
    if (stripos($authHeader, 'Bearer ') === 0) return trim(substr($authHeader, 7));
    return '';
}

function decodedExtensionReadJsonBody(): array {
    $raw = (string)file_get_contents('php://input');
    if ($raw === '') return [];
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function decodedExtensionTaskUrl(array $task): string {
    foreach (['url', 'taskUrl', 'task_url', 'productUrl', 'product_url', 'externalTaskUrl'] as $key) {
        $value = trim((string)($task[$key] ?? ''));
        if ($value !== '') return $value;
    }
    return '';
}

function decodedExtensionTaskDealId(array $task): string {
    foreach (['deal_id', 'dealId', 'dealID', 'taskId', 'task_id', 'tid', 'trace_id', 'id'] as $key) {
        $value = trim((string)($task[$key] ?? ''));
        if ($value !== '') return $value;
    }
    return '';
}

function decodedExtensionNormalizeTask(array $task): ?array {
    $url = decodedExtensionTaskUrl($task);
    if ($url === '') return null;

    $taskId = decodedExtensionTaskDealId($task);
    if ($taskId === '') $taskId = substr(md5($url), 0, 16);

    $task['url'] = $url;
    $task['taskUrl'] = (string)($task['taskUrl'] ?? $url);
    $task['taskId'] = (string)($task['taskId'] ?? $taskId);
    $task['task_id'] = (string)($task['task_id'] ?? $taskId);
    $task['tid'] = (string)($task['tid'] ?? $taskId);
    $task['deal_id'] = (string)($task['deal_id'] ?? $taskId);
    $task['dealId'] = (string)($task['dealId'] ?? $taskId);

    if (!isset($task['itemId']) && isset($task['item_id'])) $task['itemId'] = $task['item_id'];
    if (!isset($task['shopId']) && isset($task['shop_id'])) $task['shopId'] = $task['shop_id'];

    return $task;
}

function decodedExtensionIsList(array $value): bool {
    $i = 0;
    foreach ($value as $key => $_) {
        if ($key !== $i++) return false;
    }
    return true;
}

function decodedExtensionLoadQueue(string $file): array {
    if (!is_file($file)) return ['wrapper' => null, 'tasks' => []];
    $data = json_decode((string)@file_get_contents($file), true);
    if (!is_array($data)) return ['wrapper' => null, 'tasks' => []];

    if (decodedExtensionIsList($data)) return ['wrapper' => null, 'tasks' => $data];
    $tasks = $data['tasks'] ?? $data['data'] ?? $data['queue'] ?? [];
    return ['wrapper' => $data, 'tasks' => is_array($tasks) ? $tasks : []];
}

function decodedExtensionAccountStorageSuffix(array $pluginAccount): string {
    $accountId = trim((string)($pluginAccount['accountId'] ?? $pluginAccount['id'] ?? $pluginAccount['name'] ?? ''));
    if ($accountId === '') return '';
    $scope = trim((string)($pluginAccount['__storage_scope'] ?? ''));
    $identity = $scope !== '' ? ($accountId . '|' . $scope) : $accountId;
    $safe = preg_replace('/[^A-Za-z0-9_-]+/', '_', $scope !== '' ? ($accountId . '_' . $scope) : $accountId);
    $safe = trim((string)$safe, '_');
    if ($safe === '') $safe = 'account';
    return substr($safe, 0, 64) . '_' . substr(md5($identity), 0, 8);
}

function decodedExtensionRuntimeAccount(array $pluginAccount, array $deviceContext, string $forcedScope = ''): array {
    $runtime = $pluginAccount;
    $forcedScope = trim($forcedScope);
    if ($forcedScope !== '') {
        $runtime['__storage_scope'] = $forcedScope;
        $runtime['__device_id'] = trim((string)($deviceContext['device_id'] ?? ''));
        return $runtime;
    }
    $deviceId = trim((string)($deviceContext['device_id'] ?? ''));
    $clientInstance = trim((string)($deviceContext['client_instance_id'] ?? ''));
    $fingerprint = trim((string)($deviceContext['fingerprint_key'] ?? $deviceContext['fingerprint_id'] ?? ''));
    $scopeParts = array_filter([$deviceId, $clientInstance, $fingerprint], fn($v) => trim((string)$v) !== '');
    if ($scopeParts) {
        $runtime['__storage_scope'] = implode('|', $scopeParts);
        $runtime['__device_id'] = $deviceId;
    }
    return $runtime;
}

function decodedExtensionQueueFileForAccount(?array $pluginAccount = null): string {
    global $DECODED_EXTENSION_TASK_QUEUE_FILE;
    if (!is_array($pluginAccount)) return $DECODED_EXTENSION_TASK_QUEUE_FILE;
    $suffix = decodedExtensionAccountStorageSuffix($pluginAccount);
    if ($suffix === '') return $DECODED_EXTENSION_TASK_QUEUE_FILE;
    return dirname($DECODED_EXTENSION_TASK_QUEUE_FILE) . '/decoded_extension_tasks_' . $suffix . '.json';
}

function decodedExtensionStateFileForAccount(?array $pluginAccount = null): string {
    global $DECODED_EXTENSION_STATE_FILE;
    if (!is_array($pluginAccount)) return $DECODED_EXTENSION_STATE_FILE;
    $suffix = decodedExtensionAccountStorageSuffix($pluginAccount);
    if ($suffix === '') return $DECODED_EXTENSION_STATE_FILE;
    return dirname($DECODED_EXTENSION_STATE_FILE) . '/.decoded_extension_state_' . $suffix . '.json';
}

function decodedExtensionSaveQueue(string $file, ?array $wrapper, array $tasks): void {
    $payload = $wrapper === null ? array_values($tasks) : array_merge($wrapper, ['tasks' => array_values($tasks)]);
    atomicWrite($file, json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

function decodedExtensionMutateQueue(?array $pluginAccount, callable $mutator) {
    $file = decodedExtensionQueueFileForAccount($pluginAccount);
    $lockFile = $file . '.lock';
    $fh = @fopen($lockFile, 'c');
    if (!$fh) {
        $queue = decodedExtensionLoadQueue($file);
        $result = $mutator($queue);
        decodedExtensionSaveQueue($file, $queue['wrapper'], $queue['tasks']);
        return $result;
    }
    flock($fh, LOCK_EX);
    $queue = decodedExtensionLoadQueue($file);
    $result = $mutator($queue);
    decodedExtensionSaveQueue($file, $queue['wrapper'], $queue['tasks']);
    flock($fh, LOCK_UN);
    fclose($fh);
    return $result;
}

function decodedExtensionAppendLocalTasks(array $tasks, ?array $pluginAccount = null): void {
    if (!$tasks) return;
    $pdo = decodedExtensionDb();
    $accountId = decodedExtensionDbAccountId($pluginAccount);
    if ($pdo instanceof PDO && $accountId !== '') {
        $runtimeScope = decodedExtensionDbRuntimeScope($pluginAccount);
        $stmt = $pdo->prepare("
            INSERT OR IGNORE INTO task_queue (account_id, runtime_scope, task_key, task_json, queued_ts, queued_at)
            VALUES (:account_id, :runtime_scope, :task_key, :task_json, :queued_ts, :queued_at)
        ");
        try {
            $pdo->beginTransaction();
            foreach ($tasks as $task) {
                if (!is_array($task)) continue;
                $normalized = decodedExtensionNormalizeTask($task);
                if (!$normalized) continue;
                $normalized['__queued_ts'] = (int)($normalized['__queued_ts'] ?? time());
                $normalized['__queued_at'] = (string)($normalized['__queued_at'] ?? date('Y-m-d H:i:s'));
                $taskKey = decodedExtensionDbTaskKey($normalized);
                if ($taskKey === '') continue;
                $stmt->execute([
                    ':account_id' => $accountId,
                    ':runtime_scope' => $runtimeScope,
                    ':task_key' => $taskKey,
                    ':task_json' => json_encode($normalized, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                    ':queued_ts' => (int)$normalized['__queued_ts'],
                    ':queued_at' => (string)$normalized['__queued_at'],
                ]);
            }
            $pdo->commit();
            return;
        } catch (\Throwable $_) {
            if ($pdo->inTransaction()) $pdo->rollBack();
        }
    }

    decodedExtensionMutateQueue($pluginAccount, function (&$queue) use ($tasks) {
        $queued = $queue['tasks'];
        $seen = [];
        foreach ($queued as $task) {
            if (!is_array($task)) continue;
            $normalized = decodedExtensionNormalizeTask($task);
            if (!$normalized) continue;
            $key = (string)($normalized['taskId'] ?? $normalized['task_id'] ?? $normalized['tid'] ?? '') . '|' . decodedExtensionTaskUrl($normalized);
            $seen[$key] = true;
        }
        foreach ($tasks as $task) {
            if (!is_array($task)) continue;
            $normalized = decodedExtensionNormalizeTask($task);
            if (!$normalized) continue;
            $normalized['__queued_ts'] = (int)($normalized['__queued_ts'] ?? time());
            $normalized['__queued_at'] = (string)($normalized['__queued_at'] ?? date('Y-m-d H:i:s'));
            $key = (string)($normalized['taskId'] ?? $normalized['task_id'] ?? $normalized['tid'] ?? '') . '|' . decodedExtensionTaskUrl($normalized);
            if (isset($seen[$key])) continue;
            $queued[] = $normalized;
            $seen[$key] = true;
        }
        $queue['tasks'] = $queued;
        return true;
    });
}

function decodedExtensionPopLocalTasks(int $count, ?array $pluginAccount = null): array {
    global $DECODED_EXTENSION_QUEUE_TTL;
    $count = max(1, $count);
    $pdo = decodedExtensionDb();
    $accountId = decodedExtensionDbAccountId($pluginAccount);
    if ($pdo instanceof PDO && $accountId !== '') {
        $runtimeScope = decodedExtensionDbRuntimeScope($pluginAccount);
        $picked = [];
        $now = time();
        try {
            $pdo->beginTransaction();
            while (count($picked) < $count) {
                $stmt = $pdo->prepare("
                    SELECT id, task_json, queued_ts
                    FROM task_queue
                    WHERE account_id = :account_id AND runtime_scope = :runtime_scope
                    ORDER BY id ASC
                    LIMIT 50
                ");
                $stmt->execute([':account_id' => $accountId, ':runtime_scope' => $runtimeScope]);
                $rows = $stmt->fetchAll();
                if (!$rows) break;

                $deleteStmt = $pdo->prepare('DELETE FROM task_queue WHERE id = :id');
                foreach ($rows as $row) {
                    $deleteStmt->execute([':id' => (int)$row['id']]);
                    $task = json_decode((string)$row['task_json'], true);
                    $task = is_array($task) ? decodedExtensionNormalizeTask($task) : null;
                    if (!$task) continue;
                    $queuedTs = (int)($task['__queued_ts'] ?? $row['queued_ts'] ?? 0);
                    if ($queuedTs > 0 && $DECODED_EXTENSION_QUEUE_TTL > 0 && $queuedTs < $now - $DECODED_EXTENSION_QUEUE_TTL) continue;
                    $hasAccountBinding = trim((string)($task['task_account_key'] ?? $task['taskAccountKey'] ?? $task['task_account_username'] ?? $task['taskAccountUsername'] ?? '')) !== '';
                    if ($hasAccountBinding) $picked[] = $task;
                    if (count($picked) >= $count) break;
                }
            }
            $pdo->commit();
            if ($picked || !is_file(decodedExtensionQueueFileForAccount($pluginAccount))) return $picked;
        } catch (\Throwable $_) {
            if ($pdo->inTransaction()) $pdo->rollBack();
        }
    }

    return decodedExtensionMutateQueue($pluginAccount, function (&$queue) use ($count, $DECODED_EXTENSION_QUEUE_TTL) {
        $tasks = $queue['tasks'];
        if (!$tasks) return [];
        $picked = [];
        $now = time();
        while ($tasks && count($picked) < $count) {
            $candidate = array_shift($tasks);
            $task = decodedExtensionNormalizeTask($candidate);
            if (!$task) continue;
            $queuedTs = (int)($task['__queued_ts'] ?? 0);
            if ($queuedTs > 0 && $DECODED_EXTENSION_QUEUE_TTL > 0 && $queuedTs < $now - $DECODED_EXTENSION_QUEUE_TTL) continue;
            $hasAccountBinding = trim((string)($task['task_account_key'] ?? $task['taskAccountKey'] ?? $task['task_account_username'] ?? $task['taskAccountUsername'] ?? '')) !== '';
            if ($hasAccountBinding) $picked[] = $task;
        }
        $queue['tasks'] = $tasks;
        return $picked;
    });
}

function decodedExtensionClearLocalTasks(?array $pluginAccount = null): int {
    $pdo = decodedExtensionDb();
    $accountId = decodedExtensionDbAccountId($pluginAccount);
    if ($pdo instanceof PDO && $accountId !== '') {
        $removed = 0;
        try {
            $stmt = $pdo->prepare('DELETE FROM task_queue WHERE account_id = :account_id AND runtime_scope = :runtime_scope');
            $stmt->execute([
                ':account_id' => $accountId,
                ':runtime_scope' => decodedExtensionDbRuntimeScope($pluginAccount),
            ]);
            $removed += $stmt->rowCount();
        } catch (\Throwable $_) {}
        if (is_file(decodedExtensionQueueFileForAccount($pluginAccount))) {
            $removed += (int)decodedExtensionMutateQueue($pluginAccount, function (&$queue) {
                $count = is_array($queue['tasks'] ?? null) ? count($queue['tasks']) : 0;
                $queue['tasks'] = [];
                return $count;
            });
        }
        return $removed;
    }

    return (int)decodedExtensionMutateQueue($pluginAccount, function (&$queue) {
        $count = is_array($queue['tasks'] ?? null) ? count($queue['tasks']) : 0;
        $queue['tasks'] = [];
        return $count;
    });
}

function decodedExtensionPopLocalTask(?array $pluginAccount = null): ?array {
    $picked = decodedExtensionPopLocalTasks(1, $pluginAccount);
    return $picked[0] ?? null;
}

function decodedExtensionTaskFromApi1Response($serverResp): ?array {
    if (!is_array($serverResp)) return null;
    $data = $serverResp['data'] ?? null;
    if (!is_array($data)) return null;
    return decodedExtensionNormalizeTask($data);
}

function decodedExtensionRawSuccess(): array {
    return ['code' => '200', 'data' => ['code' => 'SUCCESS', 'msg' => null]];
}

function decodedExtensionReadAccounts(string $file): array {
    if (!is_file($file)) return [];
    $data = json_decode((string)@file_get_contents($file), true);
    if (!is_array($data)) return [];
    $accounts = $data['accounts'] ?? $data;
    if (!is_array($accounts)) return [];

    $result = [];
    foreach ($accounts as $account) {
        if (!is_array($account)) continue;
        $accountId = trim((string)($account['accountId'] ?? $account['id'] ?? $account['name'] ?? ''));
        $token = trim((string)($account['token'] ?? $account['auth_token'] ?? ''));
        $enabled = !array_key_exists('enabled', $account) || (bool)$account['enabled'];
        if ($accountId !== '' && $token !== '') {
            $account['accountId'] = $accountId;
            $account['token'] = $token;
            $account['enabled'] = $enabled;
            $result[] = $account;
        }
    }
    return $result;
}

function decodedExtensionTaskAccountKey(string $username, string $remark = ''): string {
    return substr(md5($username . '|' . $remark), 0, 16);
}

function decodedExtensionParseTaskAccountLine(string $line): array {
    $line = trim($line);
    if ($line === '') return ['', '', ''];
    $line = str_replace("\xEF\xBD\x9C", '|', $line);
    if (strpos($line, '|') !== false) {
        return array_pad(explode('|', $line, 3), 3, '');
    }
    if (strpos($line, "\t") !== false) {
        return array_pad(preg_split('/\t+/', $line, 3) ?: [], 3, '');
    }
    if (strpos($line, ',') !== false || strpos($line, "\xEF\xBC\x8C") !== false) {
        return array_pad(str_getcsv(str_replace("\xEF\xBC\x8C", ',', $line)) ?: [], 3, '');
    }
    if (strpos($line, ';') !== false || strpos($line, "\xEF\xBC\x9B") !== false) {
        return array_pad(preg_split('/(?:;|\xEF\xBC\x9B)+/', $line, 3) ?: [], 3, '');
    }
    return array_pad(preg_split('/\s+/', $line, 3) ?: [], 3, '');
}

function decodedExtensionNormalizeTaskMode($value): string {
    $value = strtolower(trim((string)$value));
    return $value === 'concurrent' ? 'concurrent' : 'poll';
}

function decodedExtensionNormalizeTaskParallelism($value, int $accountCount): int {
    $accountCount = max(1, $accountCount);
    if ($value === null || trim((string)$value) === '') return $accountCount;
    $parallelism = (int)$value;
    if ($parallelism < 1) $parallelism = 1;
    return min($parallelism, $accountCount);
}

function decodedExtensionNormalizeTaskAccounts(array $account, bool $includePasswords): array {
    $rows = [];
    $source = $account['api1_accounts'] ?? $account['task_accounts'] ?? null;
    if (is_array($source)) {
        $rows = $source;
    } else {
        $legacyUsername = trim((string)($account['api1_username'] ?? $account['task_username'] ?? $account['upstream_username'] ?? ''));
        $legacyPassword = (string)($account['api1_password'] ?? $account['task_password'] ?? $account['upstream_password'] ?? '');
        if ($legacyUsername !== '') {
            $rows[] = [
                'username' => $legacyUsername,
                'password' => $legacyPassword,
                'enabled' => true,
                'remark' => (string)($account['remark'] ?? ''),
            ];
        }
    }

    $result = [];
    foreach ($rows as $row) {
        if (!is_array($row)) continue;
        $username = trim((string)($row['username'] ?? $row['api1_username'] ?? $row['task_username'] ?? ''));
        $password = (string)($row['password'] ?? $row['api1_password'] ?? $row['task_password'] ?? '');
        $remark = trim((string)($row['remark'] ?? ''));
        if ($username === '') continue;
        if ($includePasswords && $password === '') continue;
        $item = [
            'key' => trim((string)($row['key'] ?? '')) ?: decodedExtensionTaskAccountKey($username, $remark),
            'username' => $username,
            'enabled' => !array_key_exists('enabled', $row) || (bool)$row['enabled'],
            'remark' => $remark,
        ];
        if ($includePasswords) $item['password'] = $password;
        $result[$item['key']] = $item;
    }
    return array_values($result);
}

function decodedExtensionEnabledTaskAccounts(array $pluginAccount): array {
    return array_values(array_filter(decodedExtensionNormalizeTaskAccounts($pluginAccount, true), fn($account) => !empty($account['enabled'])));
}

function decodedExtensionSaveAccounts(array $accounts): array {
    global $DECODED_EXTENSION_ACCOUNTS_FILE;
    $clean = [];
    foreach ($accounts as $account) {
        if (!is_array($account)) continue;
        $accountId = trim((string)($account['accountId'] ?? ''));
        $token = trim((string)($account['token'] ?? ''));
        $taskAccounts = decodedExtensionNormalizeTaskAccounts($account, true);
        if ($accountId === '' || $token === '' || !$taskAccounts) continue;
        $enabledTaskCount = count(array_filter($taskAccounts, fn($a) => !empty($a['enabled'])));
        $clean[$accountId] = [
            'accountId' => $accountId,
            'token' => $token,
            'parallel_control_token' => trim((string)($account['parallel_control_token'] ?? $account['control_token'] ?? '')) ?: decodedExtensionRandomToken(),
            'api1_accounts' => $taskAccounts,
            'task_mode' => decodedExtensionNormalizeTaskMode($account['task_mode'] ?? 'poll'),
            'task_parallelism' => decodedExtensionNormalizeTaskParallelism($account['task_parallelism'] ?? null, $enabledTaskCount ?: count($taskAccounts)),
            'enabled' => !array_key_exists('enabled', $account) || (bool)$account['enabled'],
            'remark' => trim((string)($account['remark'] ?? '')),
            'created_at' => (string)($account['created_at'] ?? date('Y-m-d H:i:s')),
            'updated_at' => date('Y-m-d H:i:s'),
        ];
    }
    ksort($clean);
    atomicWrite($DECODED_EXTENSION_ACCOUNTS_FILE, json_encode([
        'accounts' => array_values($clean),
        'updated_at' => date('Y-m-d H:i:s'),
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    return array_values($clean);
}

function decodedExtensionPublicAccounts(array $accounts): array {
    $result = [];
    foreach ($accounts as $account) {
        if (!is_array($account)) continue;
        $taskAccounts = decodedExtensionNormalizeTaskAccounts($account, false);
        $taskMode = decodedExtensionNormalizeTaskMode($account['task_mode'] ?? 'poll');
        $enabledTaskAccounts = array_values(array_filter($taskAccounts, fn($a) => !empty($a['enabled'])));
        $disabledTaskAccounts = array_values(array_filter($taskAccounts, fn($a) => empty($a['enabled'])));
        $enabledCount = count($enabledTaskAccounts);
        $taskParallelism = decodedExtensionNormalizeTaskParallelism($account['task_parallelism'] ?? null, $enabledCount ?: count($taskAccounts));
        $publicTaskAccounts = [];
        foreach ($taskAccounts as $taskAccount) {
            $publicTaskAccounts[] = [
                'key' => (string)($taskAccount['key'] ?? ''),
                'username' => (string)($taskAccount['username'] ?? ''),
                'enabled' => !empty($taskAccount['enabled']),
                'remark' => (string)($taskAccount['remark'] ?? ''),
            ];
        }
        $result[] = [
            'accountId' => (string)($account['accountId'] ?? ''),
            'token' => (string)($account['token'] ?? ''),
            'parallel_control_token' => (string)($account['parallel_control_token'] ?? ''),
            'parallel_control_url' => decodedExtensionParallelControlUrl((string)($account['parallel_control_token'] ?? '')),
            'api1_accounts' => $publicTaskAccounts,
            'api1_count' => count(array_filter($publicTaskAccounts, fn($a) => !empty($a['enabled']))),
            'api1_total_count' => count($publicTaskAccounts),
            'api1_disabled_count' => count($disabledTaskAccounts),
            'api1_usernames' => implode(', ', array_map(fn($a) => (string)($a['username'] ?? ''), $enabledTaskAccounts)),
            'api1_disabled_usernames' => implode(', ', array_map(fn($a) => (string)($a['username'] ?? ''), $disabledTaskAccounts)),
            'task_mode' => $taskMode,
            'task_parallelism' => $taskParallelism,
            'task_mode_label' => $taskMode === 'concurrent' ? '并发' : '轮询',
            'enabled' => !empty($account['enabled']),
            'remark' => (string)($account['remark'] ?? ''),
            'created_at' => (string)($account['created_at'] ?? ''),
            'updated_at' => (string)($account['updated_at'] ?? ''),
        ];
    }
    return $result;
}

function decodedExtensionGeneratedServerBaseUrl(): string {
    $https = (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off')
        || (string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
    $scheme = $https ? 'https' : 'http';
    $host = (string)($_SERVER['HTTP_HOST'] ?? '');
    $script = (string)($_SERVER['SCRIPT_NAME'] ?? '/decrypt_proxy.php');
    return $host !== '' ? $scheme . '://' . $host . $script : $script;
}

function decodedExtensionParallelControlBaseUrl(): string {
    global $PARALLEL_CONTROL_BASE_URL;
    return trim((string)$PARALLEL_CONTROL_BASE_URL);
}

function decodedExtensionParallelControlUrl(string $token): string {
    $token = trim($token);
    if ($token === '') return '';
    $base = decodedExtensionParallelControlBaseUrl();
    if ($base === '') {
        $script = (string)($_SERVER['SCRIPT_NAME'] ?? '/decrypt_proxy.php');
        return $script . '?act=parallel_control&t=' . rawurlencode($token);
    }
    $sep = strpos($base, '?') === false ? '?' : '&';
    return $base . $sep . 't=' . rawurlencode($token);
}

function decodedExtensionIsParallelControlPrettyRoute(): bool {
    if (isset($_GET['act'])) return false;
    if (trim((string)($_GET['t'] ?? '')) === '') return false;
    $path = parse_url((string)($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH);
    $path = '/' . trim((string)$path, '/');
    if ($path === '/') return true;
    $name = strtolower(basename($path));
    return in_array($name, ['control', 'parallel_control', 'parallel-control', 'concurrency'], true);
}

function decodedExtensionRandomToken(): string {
    return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
}

function decodedExtensionRandomAccountId(array $accounts): string {
    $used = [];
    foreach ($accounts as $account) {
        if (is_array($account)) $used[(string)($account['accountId'] ?? '')] = true;
    }
    do {
        $id = 'U' . date('ymd') . random_int(100000, 999999);
    } while (isset($used[$id]));
    return $id;
}

function decodedExtensionAccountIndex(array $accounts, string $accountId): int {
    foreach ($accounts as $i => $account) {
        if (is_array($account) && (string)($account['accountId'] ?? '') === $accountId) return (int)$i;
    }
    return -1;
}

function decodedExtensionAdminSaveAccount(array $input): array {
    global $DECODED_EXTENSION_ACCOUNTS_FILE;
    $accounts = decodedExtensionReadAccounts($DECODED_EXTENSION_ACCOUNTS_FILE);
    $accountId = trim((string)($input['accountId'] ?? ''));
    $idx = $accountId !== '' ? decodedExtensionAccountIndex($accounts, $accountId) : -1;
    $old = $idx >= 0 ? $accounts[$idx] : [];
    if ($accountId === '') $accountId = decodedExtensionRandomAccountId($accounts);

    $taskAccounts = [];
    if (isset($input['api1_accounts']) && is_array($input['api1_accounts'])) {
        $oldByKey = [];
        $oldByUsername = [];
        foreach (decodedExtensionNormalizeTaskAccounts(is_array($old) ? $old : [], true) as $oldTaskAccount) {
            $oldByKey[(string)($oldTaskAccount['key'] ?? '')] = $oldTaskAccount;
            $oldByUsername[(string)($oldTaskAccount['username'] ?? '')] = $oldTaskAccount;
        }
        foreach ($input['api1_accounts'] as $row) {
            if (!is_array($row)) continue;
            $username = trim((string)($row['username'] ?? $row['api1_username'] ?? ''));
            $remark = trim((string)($row['remark'] ?? ''));
            $key = trim((string)($row['key'] ?? '')) ?: decodedExtensionTaskAccountKey($username, $remark);
            $password = (string)($row['password'] ?? $row['api1_password'] ?? '');
            if ($password === '' && isset($oldByKey[$key])) $password = (string)($oldByKey[$key]['password'] ?? '');
            if ($password === '' && isset($oldByUsername[$username])) $password = (string)($oldByUsername[$username]['password'] ?? '');
            if ($username !== '' && $password !== '') {
                $taskAccounts[] = [
                    'key' => $key,
                    'username' => $username,
                    'password' => $password,
                    'enabled' => !array_key_exists('enabled', $row) || (bool)$row['enabled'],
                    'remark' => $remark,
                ];
            }
        }
    } else {
        $api1Username = trim((string)($input['api1_username'] ?? $input['task_username'] ?? ($old['api1_username'] ?? '')));
        $api1Password = (string)($input['api1_password'] ?? $input['task_password'] ?? '');
        if ($api1Password === '' && is_array($old)) $api1Password = (string)($old['api1_password'] ?? '');
        if ($api1Username !== '' && $api1Password !== '') {
            $taskAccounts[] = [
                'username' => $api1Username,
                'password' => $api1Password,
                'enabled' => true,
                'remark' => trim((string)($input['task_remark'] ?? '')),
            ];
        } elseif (is_array($old)) {
            $taskAccounts = decodedExtensionNormalizeTaskAccounts($old, true);
        }
    }

    if (!$taskAccounts) {
        return ['ok' => false, 'msg' => '任务账号池为空'];
    }

    $taskMode = decodedExtensionNormalizeTaskMode($input['task_mode'] ?? ($old['task_mode'] ?? 'poll'));
    $enabledTaskCount = count(array_filter($taskAccounts, fn($a) => !empty($a['enabled'])));
    $taskParallelism = decodedExtensionNormalizeTaskParallelism($input['task_parallelism'] ?? ($old['task_parallelism'] ?? null), $enabledTaskCount ?: count($taskAccounts));
    $account = [
        'accountId' => $accountId,
        'token' => trim((string)($input['token'] ?? ($old['token'] ?? ''))) ?: decodedExtensionRandomToken(),
        'parallel_control_token' => trim((string)($input['parallel_control_token'] ?? ($old['parallel_control_token'] ?? ''))) ?: decodedExtensionRandomToken(),
        'api1_accounts' => $taskAccounts,
        'task_mode' => $taskMode,
        'task_parallelism' => $taskParallelism,
        'enabled' => array_key_exists('enabled', $input) ? (bool)$input['enabled'] : (!is_array($old) || !array_key_exists('enabled', $old) || (bool)$old['enabled']),
        'remark' => trim((string)($input['remark'] ?? ($old['remark'] ?? ''))),
        'created_at' => is_array($old) ? (string)($old['created_at'] ?? date('Y-m-d H:i:s')) : date('Y-m-d H:i:s'),
    ];

    if ($idx >= 0) $accounts[$idx] = $account;
    else $accounts[] = $account;
    $saved = decodedExtensionSaveAccounts($accounts);
    $whitelistSync = decodedExtensionSyncTaskAccountsToApi1Whitelist($taskAccounts, (string)($account['remark'] ?? ''));
    return [
        'ok' => true,
        'data' => decodedExtensionPublicAccounts($saved),
        'account' => decodedExtensionPublicAccounts([$account])[0],
        'whitelist_sync' => $whitelistSync,
    ];
}

function decodedExtensionAdminBatchAccounts(string $raw): array {
    $added = 0;
    $created = [];
    $whitelistSync = ['added' => 0, 'updated' => 0];
    $lines = preg_split('/\r\n|\r|\n/', $raw) ?: [];
    foreach ($lines as $line) {
        $line = trim((string)$line);
        if ($line === '') continue;
        [$username, $password, $remark] = decodedExtensionParseTaskAccountLine($line);
        $resp = decodedExtensionAdminSaveAccount([
            'api1_username' => trim((string)$username),
            'api1_password' => (string)$password,
            'remark' => trim((string)$remark),
            'enabled' => true,
        ]);
        if (!empty($resp['ok'])) {
            $added++;
            $created[] = $resp['account'] ?? null;
            $sync = is_array($resp['whitelist_sync'] ?? null) ? $resp['whitelist_sync'] : [];
            $whitelistSync['added'] += (int)($sync['added'] ?? 0);
            $whitelistSync['updated'] += (int)($sync['updated'] ?? 0);
        }
    }
    return ['ok' => true, 'count' => $added, 'created' => array_values(array_filter($created)), 'whitelist_sync' => $whitelistSync];
}

function decodedExtensionAdminDeleteAccount(string $accountId): array {
    global $DECODED_EXTENSION_ACCOUNTS_FILE;
    $accounts = decodedExtensionReadAccounts($DECODED_EXTENSION_ACCOUNTS_FILE);
    $accounts = array_values(array_filter($accounts, fn($a) => is_array($a) && (string)($a['accountId'] ?? '') !== $accountId));
    $saved = decodedExtensionSaveAccounts($accounts);
    return ['ok' => true, 'data' => decodedExtensionPublicAccounts($saved)];
}

function decodedExtensionAdminToggleAccount(string $accountId, bool $enabled): array {
    global $DECODED_EXTENSION_ACCOUNTS_FILE;
    $accounts = decodedExtensionReadAccounts($DECODED_EXTENSION_ACCOUNTS_FILE);
    foreach ($accounts as &$account) {
        if (is_array($account) && (string)($account['accountId'] ?? '') === $accountId) {
            $account['enabled'] = $enabled;
        }
    }
    unset($account);
    $saved = decodedExtensionSaveAccounts($accounts);
    return ['ok' => true, 'data' => decodedExtensionPublicAccounts($saved)];
}

function decodedExtensionAdminResetToken(string $accountId): array {
    global $DECODED_EXTENSION_ACCOUNTS_FILE;
    $accounts = decodedExtensionReadAccounts($DECODED_EXTENSION_ACCOUNTS_FILE);
    foreach ($accounts as &$account) {
        if (is_array($account) && (string)($account['accountId'] ?? '') === $accountId) {
            $account['token'] = decodedExtensionRandomToken();
        }
    }
    unset($account);
    $saved = decodedExtensionSaveAccounts($accounts);
    return ['ok' => true, 'data' => decodedExtensionPublicAccounts($saved)];
}

function decodedExtensionAdminResetParallelControlToken(string $accountId): array {
    global $DECODED_EXTENSION_ACCOUNTS_FILE;
    $accounts = decodedExtensionReadAccounts($DECODED_EXTENSION_ACCOUNTS_FILE);
    foreach ($accounts as &$account) {
        if (is_array($account) && (string)($account['accountId'] ?? '') === $accountId) {
            $account['parallel_control_token'] = decodedExtensionRandomToken();
        }
    }
    unset($account);
    $saved = decodedExtensionSaveAccounts($accounts);
    return ['ok' => true, 'data' => decodedExtensionPublicAccounts($saved)];
}

function decodedExtensionFindAccountByParallelControlToken(string $token): ?array {
    global $DECODED_EXTENSION_ACCOUNTS_FILE;
    $token = trim($token);
    if ($token === '') return null;
    $accounts = decodedExtensionReadAccounts($DECODED_EXTENSION_ACCOUNTS_FILE);
    foreach ($accounts as $account) {
        if (!is_array($account)) continue;
        if (hash_equals((string)($account['parallel_control_token'] ?? ''), $token)) {
            return $account;
        }
    }
    return null;
}

function decodedExtensionParallelControlPublicData(array $account): array {
    $taskAccounts = decodedExtensionNormalizeTaskAccounts($account, false);
    $enabled = array_values(array_filter($taskAccounts, fn($a) => !empty($a['enabled'])));
    $enabledCount = count($enabled);
    $maxParallelism = max(1, $enabledCount ?: count($taskAccounts));
    $parallelism = decodedExtensionNormalizeTaskParallelism($account['task_parallelism'] ?? null, $maxParallelism);
    $names = array_values(array_map(fn($a) => (string)($a['username'] ?? ''), $enabled));
    return [
        'accountId' => (string)($account['accountId'] ?? ''),
        'remark' => (string)($account['remark'] ?? ''),
        'enabled' => !empty($account['enabled']),
        'task_mode' => decodedExtensionNormalizeTaskMode($account['task_mode'] ?? 'poll'),
        'task_parallelism' => $parallelism,
        'max_parallelism' => $maxParallelism,
        'enabled_task_count' => $enabledCount,
        'task_usernames' => array_slice($names, 0, 10),
        'hidden_task_username_count' => max(0, count($names) - 10),
        'updated_at' => (string)($account['updated_at'] ?? ''),
    ];
}

function decodedExtensionParallelControlInfo(string $token): array {
    $account = decodedExtensionFindAccountByParallelControlToken($token);
    if (!$account) return ['ok' => false, 'msg' => '控制链接无效或已重置'];
    return ['ok' => true, 'data' => decodedExtensionParallelControlPublicData($account)];
}

function decodedExtensionParallelControlAllowedUsernames(array $account): array {
    $allowed = [];
    $accountId = trim((string)($account['accountId'] ?? ''));
    if ($accountId !== '') {
        $allowed[$accountId] = true;
    }

    $taskAccounts = decodedExtensionNormalizeTaskAccounts($account, false);
    foreach ($taskAccounts as $taskAccount) {
        if (empty($taskAccount['enabled'])) continue;
        $username = trim((string)($taskAccount['username'] ?? ''));
        if ($username !== '') {
            $allowed[$username] = true;
        }
    }

    return $allowed;
}

function decodedExtensionParallelControlMatchesAccount(array $row, string $accountId, array $allowedUsernames): bool {
    foreach (['username', 'group_id', 'api1_username', 'task_account_username'] as $key) {
        $value = trim((string)($row[$key] ?? ''));
        if ($value === '') continue;
        if (($accountId !== '' && hash_equals($accountId, $value)) || isset($allowedUsernames[$value])) {
            return true;
        }
    }
    return false;
}

function decodedExtensionParallelControlLiveStats(string $token): array {
    global $DEVICE_FILE, $LOG_FILE, $MAX_LOGS;

    $token = trim($token);
    if ($token === '') return ['ok' => false, 'msg' => '缂哄皯鎺у埗 token'];

    $account = decodedExtensionFindAccountByParallelControlToken($token);
    if (!$account) return ['ok' => false, 'msg' => '鎺у埗閾炬帴鏃犳晥鎴栧凡閲嶇疆'];

    $accountId = trim((string)($account['accountId'] ?? ''));
    $accountRemark = trim((string)($account['remark'] ?? ''));
    $allowedUsernames = decodedExtensionParallelControlAllowedUsernames($account);
    $taskAccounts = decodedExtensionNormalizeTaskAccounts($account, false);
    $taskUsernames = array_values(array_map(
        fn($taskAccount) => trim((string)($taskAccount['username'] ?? '')),
        array_filter($taskAccounts, fn($taskAccount) => !empty($taskAccount['enabled']))
    ));

    $now = time();
    $onlineThreshold = 120;
    $deviceRows = [];
    $onlineCount = 0;
    foreach (readDeviceControls($DEVICE_FILE) as $device) {
        if (!is_array($device)) continue;
        if (!decodedExtensionParallelControlMatchesAccount($device, $accountId, $allowedUsernames)) continue;

        $lastSeen = strtotime((string)($device['last_seen'] ?? '')) ?: 0;
        $online = $lastSeen && ($now - $lastSeen) <= $onlineThreshold;
        if (!empty($device['disabled'])) $online = false;

        $device['online'] = $online;
        $remark = displayAccountRemark((int)($device['api_type'] ?? 0), (string)($device['username'] ?? ''), (string)($device['group_id'] ?? ''));
        if ($remark === '') $remark = displayDecodedExtensionAccountRemark((string)($device['username'] ?? ''));
        $device['account_remark'] = $remark !== '' ? $remark : (string)($device['account_remark'] ?? '');

        $deviceRows[] = $device;
        if ($online) $onlineCount++;
    }
    usort($deviceRows, fn($a, $b) => strcmp((string)($b['last_seen'] ?? ''), (string)($a['last_seen'] ?? '')));
    $deviceRows = array_values(array_filter($deviceRows, fn($device) => !empty($device['disabled']) || !empty($device['online'])));

    $logs = [];
    foreach (readLogs($LOG_FILE, min(200, max(50, $MAX_LOGS))) as $log) {
        if (!is_array($log)) continue;
        if (!decodedExtensionParallelControlMatchesAccount($log, $accountId, $allowedUsernames)) continue;

        $source = strtolower(trim((string)($log['source'] ?? '')));
        $status = strtolower(trim((string)($log['status'] ?? '')));
        if (in_array($source, ['web_take', 'api1_take', 'ctrl_take', 'decoded_extension_task', 'decoded_extension_task_local', 'decoded_extension_task_batch'], true)) {
            continue;
        }
        if ($source === 'decoded_extension_submit' && $status === 'client_task_failed') {
            continue;
        }

        $forwardUrl = strtolower((string)($log['forward_url'] ?? ''));
        $isSubmitLog =
            !empty($log['submit_id']) ||
            !empty($log['upload_id']) ||
            strpos($source, 'submit') !== false ||
            strpos($source, 'forward') !== false ||
            strpos($source, 'relay') !== false ||
            strpos($status, 'submit') !== false ||
            strpos($status, 'forward') !== false ||
            strpos($forwardUrl, '/submit') !== false ||
            in_array($source, ['decoded_extension_submit', 'ios_api2_submit', 'api1_submit', 'web_submit', 'ctrl_submit'], true);
        if (!$isSubmitLog) continue;

        $remark = displayAccountRemark((int)($log['api_type'] ?? 0), (string)($log['username'] ?? ''), (string)($log['group_id'] ?? ''));
        if ($remark === '') $remark = displayDecodedExtensionAccountRemark((string)($log['username'] ?? ''));
        $clientLabel = resolveClientLabel($log);
        if ($clientLabel !== '') {
            $log['client_label'] = $clientLabel;
        } elseif (($log['client_label'] ?? '') === '' && !empty($taskUsernames)) {
            $username = trim((string)($log['username'] ?? ''));
            if ($username !== '' && in_array($username, $taskUsernames, true)) {
                $log['client_label'] = '任务子账号';
            }
        }

        $log['account_remark'] = $remark !== '' ? $remark : (string)($log['account_remark'] ?? '');
        if (isset($log['response'])) {
            $log['response'] = compactLogResponse($log['response'], 1200);
        }
        $logs[] = $log;
        if (count($logs) >= 18) break;
    }

    return [
        'ok' => true,
        'data' => [
            'accountId' => $accountId,
            'remark' => $accountRemark,
            'task_usernames' => $taskUsernames,
            'device_count' => count($deviceRows),
            'online_device_count' => $onlineCount,
            'devices' => $deviceRows,
            'logs' => $logs,
            'fromCache' => false,
            'cacheAge' => 0,
            'updated_at' => date('Y-m-d H:i:s'),
        ],
    ];
}

function decodedExtensionLoadCxPayloadForDate(string $date, bool $force = false): array {
    $cxFile = __DIR__ . '/cx.php';
    if (!is_file($cxFile)) {
        return ['ok' => false, 'msg' => 'cx.php 不存在，无法读取当日任务统计'];
    }

    $oldGet = $_GET;
    $_GET['date'] = $date;
    $_GET['auto'] = '1';
    if ($force) {
        $_GET['force'] = '1';
        $_GET['refresh'] = '1';
    }
    unset($_GET['format']);

    if (!defined('CX_DATA_ONLY')) {
        define('CX_DATA_ONLY', true);
    }

    $payload = include $cxFile;
    $_GET = $oldGet;

    if (is_array($payload) && decodedExtensionShouldFallbackCxHttp($payload, $force)) {
        $httpLoaded = decodedExtensionLoadCxPayloadViaHttp($date, $force);
        if (!empty($httpLoaded['ok'])) {
            $httpPayload = is_array($httpLoaded['payload'] ?? null) ? $httpLoaded['payload'] : [];
            if (decodedExtensionCxPayloadHasActivity($httpPayload) || !decodedExtensionCxPayloadHasActivity($payload)) {
                return $httpLoaded;
            }
        }
        $cacheLoaded = decodedExtensionLoadLatestCxCachePayload($date);
        if (!empty($cacheLoaded['ok'])) {
            $cachePayload = is_array($cacheLoaded['payload'] ?? null) ? $cacheLoaded['payload'] : [];
            if (decodedExtensionCxPayloadHasActivity($cachePayload)) {
                return $cacheLoaded;
            }
        }
    }

    if (!is_array($payload)) {
        return ['ok' => false, 'msg' => '当日任务统计读取失败'];
    }
    return ['ok' => true, 'payload' => $payload];
}

function decodedExtensionCxPayloadHasActivity(array $payload): bool {
    foreach (['batchItems', 'items'] as $section) {
        $rows = is_array($payload[$section] ?? null) ? $payload[$section] : [];
        foreach ($rows as $row) {
            if (!is_array($row)) continue;
            $total =
                (int)($row['takeCount'] ?? 0) +
                (int)($row['completeCount'] ?? 0) +
                (int)($row['checkSuccessCount'] ?? 0) +
                (int)($row['checkFailCount'] ?? 0);
            if ($total > 0) return true;
        }
    }
    return false;
}

function decodedExtensionShouldFallbackCxHttp(array $payload, bool $force): bool {
    $warning = (string)($payload['warning'] ?? '');
    $error = (string)($payload['error'] ?? '');
    if (!empty($payload['ok']) && $warning === '' && $error === '' && decodedExtensionCxPayloadHasActivity($payload)) {
        return false;
    }
    return $force
        || $error !== ''
        || !decodedExtensionCxPayloadHasActivity($payload);
}

function decodedExtensionLoadCxPayloadViaHttp(string $date, bool $force = false): array {
    $host = trim((string)($_SERVER['HTTP_HOST'] ?? ''));
    if ($host === '') return ['ok' => false, 'msg' => 'HTTP_HOST empty'];

    $https = (string)($_SERVER['HTTPS'] ?? '');
    $forwardedProto = strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''));
    $scheme = ($forwardedProto === 'https' || ($https !== '' && $https !== 'off') || (string)($_SERVER['SERVER_PORT'] ?? '') === '443')
        ? 'https'
        : 'http';
    $scriptDir = str_replace('\\', '/', dirname((string)($_SERVER['SCRIPT_NAME'] ?? '')));
    $scriptDir = rtrim($scriptDir, '/.');
    $base = $scheme . '://' . $host . ($scriptDir !== '' ? $scriptDir : '');

    foreach (['/cx', '/cx.php'] as $path) {
        $query = [
            'date' => $date,
            'auto' => '1',
            'format' => 'json',
            '_ts' => (string)time(),
        ];
        if ($force) {
            $query['force'] = '1';
            $query['refresh'] = '1';
        }
        $ch = curl_init($base . $path . '?' . http_build_query($query));
        if (!$ch) continue;
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_CONNECTTIMEOUT => 2,
            CURLOPT_HTTPHEADER => ['Accept: application/json', 'X-Requested-With: fetch'],
        ]);
        $body = curl_exec($ch);
        $err = curl_error($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($err || $body === false || $code < 200 || $code >= 300) continue;
        $json = json_decode((string)$body, true);
        if (is_array($json)) {
            $json['_loaded_via'] = $path;
            return ['ok' => true, 'payload' => $json];
        }
    }

    return ['ok' => false, 'msg' => 'cx HTTP fallback failed'];
}

function decodedExtensionLoadLatestCxCachePayload(string $date): array {
    $cacheDir = __DIR__ . '/cx_cache';
    if (!is_dir($cacheDir)) return ['ok' => false, 'msg' => 'cx cache missing'];

    $files = [];
    foreach (['cx_cache_*.json', 'cx_lastgood_*.json', 'cx_date_lastgood_*.json'] as $pattern) {
        foreach (glob($cacheDir . '/' . $pattern) ?: [] as $file) {
            if (is_file($file)) $files[] = $file;
        }
    }

    $bestPayload = null;
    $bestScore = 0;
    foreach ($files as $file) {
        $raw = json_decode((string)@file_get_contents($file), true);
        if (!is_array($raw)) continue;
        $payload = is_array($raw['payload'] ?? null) ? $raw['payload'] : $raw;
        if (!is_array($payload) || !decodedExtensionCxPayloadHasActivity($payload)) continue;
        $payloadDate = trim((string)($payload['date'] ?? ''));
        if ($payloadDate !== '' && $payloadDate !== $date) continue;
        $score = max(
            (int)($payload['fetchTime'] ?? 0),
            (int)($raw['_ts'] ?? 0),
            (int)@filemtime($file)
        );
        if ($score >= $bestScore) {
            $bestScore = $score;
            $payload['fromCache'] = true;
            $payload['cacheAge'] = max(0, time() - $score);
            $payload['_loaded_via'] = 'cx_cache';
            $bestPayload = $payload;
        }
    }

    if (is_array($bestPayload)) return ['ok' => true, 'payload' => $bestPayload];
    return ['ok' => false, 'msg' => 'cx cache has no activity'];
}

function decodedExtensionParallelControlDailyStats(string $token, string $date, bool $force = false): array {
    $token = trim($token);
    if ($token === '') return ['ok' => false, 'msg' => '缺少控制 token'];
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) $date = date('Y-m-d');

    $account = decodedExtensionFindAccountByParallelControlToken($token);
    if (!$account) return ['ok' => false, 'msg' => '控制链接无效或已重置'];

    $taskAccounts = decodedExtensionNormalizeTaskAccounts($account, false);
    $enabled = array_values(array_filter($taskAccounts, fn($a) => !empty($a['enabled']) && trim((string)($a['username'] ?? '')) !== ''));
    $allowed = [];
    foreach ($enabled as $taskAccount) {
        $username = trim((string)($taskAccount['username'] ?? ''));
        if ($username === '') continue;
        $allowed[$username] = [
            'username' => $username,
            'remark' => (string)($taskAccount['remark'] ?? ''),
        ];
    }

    $loaded = decodedExtensionLoadCxPayloadForDate($date, $force);
    if (empty($loaded['ok'])) {
        return ['ok' => false, 'msg' => (string)($loaded['msg'] ?? '当日任务统计读取失败')];
    }

    $payload = is_array($loaded['payload'] ?? null) ? $loaded['payload'] : [];
    $rowsByUsername = [];
    foreach (['batchItems', 'items'] as $section) {
        $sourceRows = is_array($payload[$section] ?? null) ? $payload[$section] : [];
        foreach ($sourceRows as $row) {
            if (!is_array($row)) continue;
            $username = trim((string)($row['username'] ?? ''));
            if ($username === '' || !isset($allowed[$username]) || isset($rowsByUsername[$username])) continue;
            $rowsByUsername[$username] = $row;
        }
    }

    $summary = ['take' => 0, 'complete' => 0, 'success' => 0, 'fail' => 0];
    $rows = [];
    foreach ($allowed as $username => $meta) {
        $row = is_array($rowsByUsername[$username] ?? null) ? $rowsByUsername[$username] : [];
        $take = (int)($row['takeCount'] ?? 0);
        $complete = (int)($row['completeCount'] ?? 0);
        $success = (int)($row['checkSuccessCount'] ?? 0);
        $fail = (int)($row['checkFailCount'] ?? 0);
        $summary['take'] += $take;
        $summary['complete'] += $complete;
        $summary['success'] += $success;
        $summary['fail'] += $fail;
        $rows[] = [
            'username' => $username,
            'remark' => (string)($row['_remark'] ?? $meta['remark'] ?? ''),
            'take' => $take,
            'complete' => $complete,
            'success' => $success,
            'fail' => $fail,
            'completeRate' => (string)($row['completeRate'] ?? ''),
            'successRate' => (string)($row['checkSuccessRate'] ?? ''),
            'active' => ($take + $complete + $success + $fail) > 0,
        ];
    }
    usort($rows, fn($a, $b) => ((int)$b['success'] <=> (int)$a['success']) ?: ((int)$b['take'] <=> (int)$a['take']));

    $activeCount = count(array_filter($rows, fn($row) => !empty($row['active'])));
    $cxAuthorizedCount = count(is_array($payload['authorizedAccounts'] ?? null) ? $payload['authorizedAccounts'] : []);
    $cxItemCount = count(is_array($payload['items'] ?? null) ? $payload['items'] : []);
    $cxBatchCount = count(is_array($payload['batchItems'] ?? null) ? $payload['batchItems'] : []);
    $matchedCount = count($rowsByUsername);
    $warning = (string)($payload['warning'] ?? '');
    if ($warning === '' && count($allowed) > 0 && ($cxItemCount + $cxBatchCount) > 0 && $matchedCount === 0) {
        $warning = 'cx.php 已更新，但当前并发控制绑定的任务账号没有匹配到对应数据，请检查控制链接是否对应新账号';
    }
    return [
        'ok' => true,
        'data' => [
            'date' => $date,
            'accountId' => (string)($account['accountId'] ?? ''),
            'remark' => (string)($account['remark'] ?? ''),
            'task_count' => count($allowed),
            'allowed_count' => count($allowed),
            'active_count' => $activeCount,
            'matched_count' => $matchedCount,
            'missing_count' => max(0, count($allowed) - $activeCount),
            'summary' => $summary,
            'rows' => $rows,
            'fromCache' => !empty($payload['fromCache']),
            'cacheAge' => (int)($payload['cacheAge'] ?? 0),
            'warning' => $warning,
            'force_refresh' => $force,
            'cx_authorized_count' => $cxAuthorizedCount,
            'cx_item_count' => $cxItemCount,
            'cx_batch_count' => $cxBatchCount,
            'cx_using_last_good' => !empty($payload['usingLastGood']),
            'cx_loaded_via' => (string)($payload['_loaded_via'] ?? 'include'),
            'generatedAt' => date('Y-m-d H:i:s'),
        ],
    ];
}

function decodedExtensionParallelControlSave(string $token, $parallelism): array {
    global $DECODED_EXTENSION_ACCOUNTS_FILE;
    $token = trim($token);
    if ($token === '') return ['ok' => false, 'msg' => '缺少控制 token'];
    $accounts = decodedExtensionReadAccounts($DECODED_EXTENSION_ACCOUNTS_FILE);
    foreach ($accounts as &$account) {
        if (!is_array($account) || !hash_equals((string)($account['parallel_control_token'] ?? ''), $token)) continue;
        if (empty($account['enabled'])) return ['ok' => false, 'msg' => '该账号已停用，不能修改并发'];
        $taskAccounts = decodedExtensionNormalizeTaskAccounts($account, true);
        $enabledCount = count(array_filter($taskAccounts, fn($a) => !empty($a['enabled'])));
        $maxParallelism = max(1, $enabledCount ?: count($taskAccounts));
        $account['task_mode'] = 'concurrent';
        $account['task_parallelism'] = decodedExtensionNormalizeTaskParallelism($parallelism, $maxParallelism);
        $account['updated_at'] = date('Y-m-d H:i:s');
        $savedAccount = $account;
        unset($account);
        decodedExtensionSaveAccounts($accounts);
        return ['ok' => true, 'msg' => '并发数量已保存', 'data' => decodedExtensionParallelControlPublicData($savedAccount)];
    }
    unset($account);
    return ['ok' => false, 'msg' => '控制链接无效或已重置'];
}

function decodedExtensionFindAccount(string $accountId, string $token): ?array {
    global $DECODED_EXTENSION_ACCOUNTS_FILE;
    $accounts = decodedExtensionReadAccounts($DECODED_EXTENSION_ACCOUNTS_FILE);
    if (!$accounts) return null;
    foreach ($accounts as $account) {
        if (empty($account['enabled'])) continue;
        if (hash_equals((string)$account['accountId'], $accountId) && hash_equals((string)$account['token'], $token)) {
            return $account;
        }
    }
    return null;
}

function decodedExtensionFindAccountByToken(string $token): ?array {
    global $DECODED_EXTENSION_ACCOUNTS_FILE;
    $token = trim($token);
    if ($token === '') return null;
    $accounts = decodedExtensionReadAccounts($DECODED_EXTENSION_ACCOUNTS_FILE);
    foreach ($accounts as $account) {
        if (empty($account['enabled'])) continue;
        if (hash_equals((string)($account['token'] ?? ''), $token)) {
            return $account;
        }
    }
    return null;
}

function decodedExtensionApi1AuthForAccount(array $account): array {
    global $API1_AUTH;
    return [
        'login_url' => trim((string)($account['api1_login_url'] ?? $account['login_url'] ?? $API1_AUTH['login_url'] ?? '')),
        'username' => trim((string)($account['api1_username'] ?? $account['task_username'] ?? $account['upstream_username'] ?? $account['server_username'] ?? $API1_AUTH['username'] ?? '')),
        'password' => (string)($account['api1_password'] ?? $account['task_password'] ?? $account['upstream_password'] ?? $account['server_password'] ?? $API1_AUTH['password'] ?? ''),
    ];
}

function decodedExtensionApi1AuthForTaskAccount(array $pluginAccount, array $taskAccount): array {
    global $API1_AUTH;
    return [
        'login_url' => trim((string)($pluginAccount['api1_login_url'] ?? $pluginAccount['login_url'] ?? $API1_AUTH['login_url'] ?? '')),
        'username' => trim((string)($taskAccount['username'] ?? '')),
        'password' => (string)($taskAccount['password'] ?? ''),
    ];
}

function decodedExtensionApi1TokenFileForAccount(array $account, array $api1Auth): string {
    global $API1_TOKEN_FILE;
    $key = (string)($account['accountId'] ?? '') . '|' . (string)($api1Auth['username'] ?? '');
    return dirname($API1_TOKEN_FILE) . '/api1_token_decoded_' . substr(md5($key), 0, 16) . '.json';
}

function decodedExtensionLoadState(?array $pluginAccount = null): array {
    $stateFile = decodedExtensionStateFileForAccount($pluginAccount);
    if (!is_file($stateFile)) return ['rotation' => [], 'leases' => []];
    $data = json_decode((string)@file_get_contents($stateFile), true);
    if (!is_array($data)) return ['rotation' => [], 'leases' => []];
    if (!isset($data['rotation']) || !is_array($data['rotation'])) $data['rotation'] = [];
    if (!isset($data['leases']) || !is_array($data['leases'])) $data['leases'] = [];
    return $data;
}

function decodedExtensionSaveState(array $state, ?array $pluginAccount = null): void {
    global $DECODED_EXTENSION_LEASE_TTL;
    $stateFile = decodedExtensionStateFileForAccount($pluginAccount);
    $now = time();
    foreach (($state['leases'] ?? []) as $key => $lease) {
        $created = (int)($lease['created_ts'] ?? 0);
        if ($created > 0 && $DECODED_EXTENSION_LEASE_TTL > 0 && $created < $now - $DECODED_EXTENSION_LEASE_TTL) unset($state['leases'][$key]);
    }
    atomicWrite($stateFile, json_encode($state, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

function decodedExtensionLeaseBelongsToAccount(array $lease, array $pluginAccount): bool {
    $leaseAccountId = (string)($lease['plugin_account_id'] ?? '');
    $accountId = (string)($pluginAccount['accountId'] ?? '');
    return $leaseAccountId === '' || $accountId === '' || hash_equals($leaseAccountId, $accountId);
}

function decodedExtensionLeaseMatchesTask(array $lease, array $pluginAccount, string $taskId, string $url): bool {
    if (!decodedExtensionLeaseBelongsToAccount($lease, $pluginAccount)) return false;
    $sameTask = $taskId !== '' && (string)($lease['task_id'] ?? '') === $taskId;
    $sameUrl = $url !== '' && (string)($lease['url'] ?? '') === $url;
    return $sameTask || $sameUrl;
}

function decodedExtensionStateFilesForAccount(array $pluginAccount, string $preferredFile = ''): array {
    global $DECODED_EXTENSION_STATE_FILE;
    $files = [];
    $add = function (string $file) use (&$files) {
        if ($file === '' || !is_file($file)) return;
        $real = realpath($file) ?: $file;
        $files[$real] = $file;
    };

    $add($preferredFile);
    $add(decodedExtensionStateFileForAccount($pluginAccount));
    $baseAccount = $pluginAccount;
    unset($baseAccount['__storage_scope'], $baseAccount['__device_id']);
    $add(decodedExtensionStateFileForAccount($baseAccount));

    $pattern = dirname($DECODED_EXTENSION_STATE_FILE) . '/.decoded_extension_state*.json';
    foreach ((glob($pattern) ?: []) as $file) {
        $add($file);
    }
    return array_values($files);
}

function decodedExtensionFindTaskLeaseInState(array $state, array $pluginAccount, string $taskId, string $url): ?array {
    $lease = $state['leases'][decodedExtensionLeaseKey($pluginAccount, $taskId, $url)] ?? null;
    if (is_array($lease) && decodedExtensionLeaseMatchesTask($lease, $pluginAccount, $taskId, $url)) {
        return $lease;
    }

    $best = null;
    foreach (($state['leases'] ?? []) as $candidate) {
        if (!is_array($candidate)) continue;
        if (!decodedExtensionLeaseMatchesTask($candidate, $pluginAccount, $taskId, $url)) continue;
        if (!is_array($best) || (int)($candidate['created_ts'] ?? 0) >= (int)($best['created_ts'] ?? 0)) {
            $best = $candidate;
        }
    }
    return is_array($best) ? $best : null;
}

function decodedExtensionFindTaskLeaseAcrossStates(array $pluginAccount, string $taskId, string $url, string $preferredFile = ''): ?array {
    global $DECODED_EXTENSION_LEASE_TTL;
    $now = time();
    $best = null;
    foreach (decodedExtensionStateFilesForAccount($pluginAccount, $preferredFile) as $stateFile) {
        $data = json_decode((string)@file_get_contents($stateFile), true);
        if (!is_array($data) || !is_array($data['leases'] ?? null)) continue;
        $lease = decodedExtensionFindTaskLeaseInState($data, $pluginAccount, $taskId, $url);
        if (!is_array($lease)) continue;
        $created = (int)($lease['created_ts'] ?? 0);
        if ($created > 0 && $DECODED_EXTENSION_LEASE_TTL > 0 && $created < $now - $DECODED_EXTENSION_LEASE_TTL) continue;
        $lease['__state_file'] = $stateFile;
        if (!is_array($best) || $created >= (int)($best['created_ts'] ?? 0)) {
            $best = $lease;
        }
    }
    return is_array($best) ? $best : null;
}

function decodedExtensionMutateState(callable $mutator, ?array $pluginAccount = null) {
    $stateFile = decodedExtensionStateFileForAccount($pluginAccount);
    $lockFile = $stateFile . '.lock';
    $fh = @fopen($lockFile, 'c');
    if (!$fh) {
        $state = decodedExtensionLoadState($pluginAccount);
        $result = $mutator($state);
        decodedExtensionSaveState($state, $pluginAccount);
        return $result;
    }
    flock($fh, LOCK_EX);
    $state = decodedExtensionLoadState($pluginAccount);
    $result = $mutator($state);
    decodedExtensionSaveState($state, $pluginAccount);
    flock($fh, LOCK_UN);
    fclose($fh);
    return $result;
}

function decodedExtensionOrderedTaskAccounts(array $pluginAccount): array {
    $taskAccounts = decodedExtensionEnabledTaskAccounts($pluginAccount);
    if (!$taskAccounts) return [];
    return decodedExtensionMutateState(function (&$state) use ($pluginAccount, $taskAccounts) {
        $accountId = (string)($pluginAccount['accountId'] ?? '');
        $start = (int)($state['rotation'][$accountId] ?? 0);
        $count = count($taskAccounts);
        $ordered = [];
        for ($i = 0; $i < $count; $i++) {
            $ordered[] = $taskAccounts[($start + $i) % $count];
        }
        $state['rotation'][$accountId] = ($start + 1) % max(1, $count);
        return $ordered;
    }, $pluginAccount);
}

function decodedExtensionTakeTaskFromApi1Pool(string $takeUrl, array $pluginAccount, array $orderedAccounts): array {
    $attempts = [];
    $prepared = [];
    $foundTasks = [];
    $lastMsg = 'no task';

    foreach ($orderedAccounts as $taskAccount) {
        $api1Auth = decodedExtensionApi1AuthForTaskAccount($pluginAccount, $taskAccount);
        $tokenInfo = getApi1Token($api1Auth, decodedExtensionApi1TokenFileForAccount($pluginAccount, $api1Auth));
        if (empty($tokenInfo['ok'])) {
            $attempts[] = [
                'api1_username' => $api1Auth['username'] ?? '',
                'error' => (string)($tokenInfo['msg'] ?? 'api1 login failed'),
            ];
            $lastMsg = (string)($tokenInfo['msg'] ?? 'api1 login failed');
            continue;
        }
        $prepared[] = [
            'task_account' => $taskAccount,
            'api1_auth' => $api1Auth,
            'token' => (string)$tokenInfo['token'],
        ];
    }

    if (!$prepared) return ['task' => null, 'task_account' => null, 'attempts' => $attempts, 'last_msg' => $lastMsg];

    if (!function_exists('curl_multi_init')) {
        foreach ($prepared as $entry) {
            $stageMark = microtime(true);
            $result = forwardGetToServer($takeUrl, ['Authorization: Bearer ' . $entry['token']]);
            $serverResp = json_decode((string)$result['response'], true);
            $task = decodedExtensionTaskFromApi1Response($serverResp);
            $attempts[] = forwardAttemptSummary($result, $serverResp) + [
                'api1_username' => $entry['api1_auth']['username'] ?? '',
                'attempt' => count($attempts) + 1,
                'total_ms' => elapsedMs($stageMark),
                'token_hash' => substr(hash('sha256', (string)$entry['token']), 0, 16),
            ];
            if ($result['error']) {
                $lastMsg = 'take task forward failed: ' . $result['error'];
                continue;
            }
            if ($task) {
                $foundTasks[] = [
                    'task' => $task,
                    'task_account' => $entry['task_account'],
                    'api1_token' => $entry['token'],
                    'api1_username' => $entry['api1_auth']['username'] ?? '',
                ];
                $lastMsg = 'ok';
                continue;
            }
            $lastMsg = is_array($serverResp) ? (string)($serverResp['msg'] ?? $serverResp['data']['msg'] ?? 'no task') : 'no task';
        }
        if ($foundTasks) {
            $first = array_shift($foundTasks);
            return [
                'task' => $first['task'],
                'task_account' => $first['task_account'],
                'api1_token' => (string)($first['api1_token'] ?? ''),
                'api1_username' => (string)($first['api1_username'] ?? ''),
                'extra_tasks' => $foundTasks,
                'attempts' => $attempts,
                'last_msg' => 'ok',
            ];
        }
        return ['task' => null, 'task_account' => null, 'attempts' => $attempts, 'last_msg' => $lastMsg];
    }

    $mh = curl_multi_init();
    $handles = [];
    foreach ($prepared as $idx => $entry) {
        $ch = decodedExtensionCreateTakeCurl($takeUrl, $entry['token']);
        $handles[$idx] = $entry + ['ch' => $ch, 'start' => microtime(true)];
        curl_multi_add_handle($mh, $ch);
    }

    $active = null;
    do {
        do {
            $status = curl_multi_exec($mh, $active);
        } while ($status === CURLM_CALL_MULTI_PERFORM);

        while ($info = curl_multi_info_read($mh)) {
            $ch = $info['handle'];
            $idx = null;
            foreach ($handles as $candidateIdx => $entry) {
                if ($entry['ch'] === $ch) {
                    $idx = $candidateIdx;
                    break;
                }
            }
            if ($idx === null) {
                curl_multi_remove_handle($mh, $ch);
                curl_close($ch);
                continue;
            }

            $entry = $handles[$idx];
            $response = curl_multi_getcontent($ch);
            $result = [
                'response' => $response,
                'error' => curl_error($ch),
                'http_code' => (int)curl_getinfo($ch, CURLINFO_HTTP_CODE),
                'headers' => [],
                'curl_total_ms' => (int)round(((float)curl_getinfo($ch, CURLINFO_TOTAL_TIME)) * 1000),
            ];
            $serverResp = json_decode((string)$response, true);
            $task = decodedExtensionTaskFromApi1Response($serverResp);
            $attempts[] = forwardAttemptSummary($result, $serverResp) + [
                'api1_username' => $entry['api1_auth']['username'] ?? '',
                'attempt' => count($attempts) + 1,
                'total_ms' => elapsedMs($entry['start']),
                'parallel' => true,
                'token_hash' => substr(hash('sha256', (string)$entry['token']), 0, 16),
            ];
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
            unset($handles[$idx]);

            if ($result['error']) {
                $lastMsg = 'take task forward failed: ' . $result['error'];
            } elseif ($task) {
                $foundTasks[] = [
                    'task' => $task,
                    'task_account' => $entry['task_account'],
                    'api1_token' => $entry['token'],
                    'api1_username' => $entry['api1_auth']['username'] ?? '',
                ];
                $lastMsg = 'ok';
            } else {
                $lastMsg = is_array($serverResp) ? (string)($serverResp['msg'] ?? $serverResp['data']['msg'] ?? 'no task') : 'no task';
            }
        }

        if ($active) {
            $ready = curl_multi_select($mh, 0.2);
            if ($ready === -1) usleep(20000);
        }
    } while ($active && $status === CURLM_OK);

    foreach ($handles as $pending) {
        curl_multi_remove_handle($mh, $pending['ch']);
        curl_close($pending['ch']);
    }
    curl_multi_close($mh);

    if ($foundTasks) {
        $first = array_shift($foundTasks);
        return [
            'task' => $first['task'],
            'task_account' => $first['task_account'],
            'api1_token' => (string)($first['api1_token'] ?? ''),
            'api1_username' => (string)($first['api1_username'] ?? ''),
            'extra_tasks' => $foundTasks,
            'attempts' => $attempts,
            'last_msg' => 'ok',
        ];
    }
    return ['task' => null, 'task_account' => null, 'attempts' => $attempts, 'last_msg' => $lastMsg ?: 'no task'];
}

function decodedExtensionLeaseKey(array $pluginAccount, string $taskId, string $url): string {
    $identity = $taskId !== '' ? $taskId : $url;
    return md5((string)($pluginAccount['accountId'] ?? '') . '|' . (string)($pluginAccount['__storage_scope'] ?? '') . '|' . $identity);
}

function decodedExtensionDbLeaseFromRow(array $row): array {
    return [
        'plugin_account_id' => (string)($row['account_id'] ?? ''),
        'task_account_key' => (string)($row['task_account_key'] ?? ''),
        'task_account_username' => (string)($row['task_account_username'] ?? ''),
        'task_id' => (string)($row['task_id'] ?? ''),
        'url' => (string)($row['task_url'] ?? ''),
        'api1_token' => (string)($row['api1_token'] ?? ''),
        'api1_token_hash' => (string)($row['api1_token_hash'] ?? ''),
        'api1_token_expires_at' => (int)($row['api1_token_expires_at'] ?? 0),
        'created_ts' => (int)($row['created_ts'] ?? 0),
        'created_at' => (string)($row['created_at'] ?? ''),
        '__storage' => 'sqlite',
        '__runtime_scope' => (string)($row['runtime_scope'] ?? ''),
    ];
}

function decodedExtensionFindTaskLeaseFromDb(array $pluginAccount, string $taskId, string $url): ?array {
    global $DECODED_EXTENSION_LEASE_TTL;
    $pdo = decodedExtensionDb();
    $accountId = decodedExtensionDbAccountId($pluginAccount);
    if (!$pdo instanceof PDO || $accountId === '') return null;

    $clauses = [];
    $params = [':account_id' => $accountId];
    if ($taskId !== '') {
        $clauses[] = 'task_id = :task_id';
        $params[':task_id'] = $taskId;
    }
    if ($url !== '') {
        $clauses[] = 'task_url = :task_url';
        $params[':task_url'] = $url;
    }
    if (!$clauses) return null;
    $minCreated = $DECODED_EXTENSION_LEASE_TTL > 0 ? time() - $DECODED_EXTENSION_LEASE_TTL : 0;
    $params[':min_created'] = $minCreated;

    try {
        $stmt = $pdo->prepare("
            SELECT *
            FROM task_leases
            WHERE account_id = :account_id
              AND created_ts >= :min_created
              AND (" . implode(' OR ', $clauses) . ")
            ORDER BY CASE WHEN runtime_scope = :runtime_scope THEN 0 ELSE 1 END, created_ts DESC, id DESC
            LIMIT 1
        ");
        $params[':runtime_scope'] = decodedExtensionDbRuntimeScope($pluginAccount);
        $stmt->execute($params);
        $row = $stmt->fetch();
        return is_array($row) ? decodedExtensionDbLeaseFromRow($row) : null;
    } catch (\Throwable $_) {
        return null;
    }
}

function decodedExtensionForgetTaskLeaseFromDb(array $pluginAccount, string $taskId, string $url): int {
    $pdo = decodedExtensionDb();
    $accountId = decodedExtensionDbAccountId($pluginAccount);
    if (!$pdo instanceof PDO || $accountId === '') return 0;

    $clauses = [];
    $params = [':account_id' => $accountId];
    if ($taskId !== '') {
        $clauses[] = 'task_id = :task_id';
        $params[':task_id'] = $taskId;
    }
    if ($url !== '') {
        $clauses[] = 'task_url = :task_url';
        $params[':task_url'] = $url;
    }
    if (!$clauses) return 0;

    try {
        $stmt = $pdo->prepare('DELETE FROM task_leases WHERE account_id = :account_id AND (' . implode(' OR ', $clauses) . ')');
        $stmt->execute($params);
        return $stmt->rowCount();
    } catch (\Throwable $_) {
        return 0;
    }
}

function decodedExtensionClearTaskLeasesFromDb(?array $pluginAccount = null): int {
    $pdo = decodedExtensionDb();
    $accountId = decodedExtensionDbAccountId($pluginAccount);
    if (!$pdo instanceof PDO || $accountId === '') return 0;

    try {
        $stmt = $pdo->prepare('DELETE FROM task_leases WHERE account_id = :account_id AND runtime_scope = :runtime_scope');
        $stmt->execute([
            ':account_id' => $accountId,
            ':runtime_scope' => decodedExtensionDbRuntimeScope($pluginAccount),
        ]);
        return $stmt->rowCount();
    } catch (\Throwable $_) {
        return 0;
    }
}

function decodedExtensionActiveTaskLeaseCount(array $pluginAccount, bool $sameRuntimeOnly = true): int {
    global $DECODED_EXTENSION_LEASE_TTL;
    $pdo = decodedExtensionDb();
    $accountId = decodedExtensionDbAccountId($pluginAccount);
    $runtimeScope = decodedExtensionDbRuntimeScope($pluginAccount);
    $minCreated = $DECODED_EXTENSION_LEASE_TTL > 0 ? time() - $DECODED_EXTENSION_LEASE_TTL : 0;
    if ($pdo instanceof PDO && $accountId !== '') {
        try {
            $sql = 'SELECT COUNT(*) FROM task_leases WHERE account_id = :account_id AND created_ts >= :min_created';
            $params = [':account_id' => $accountId, ':min_created' => $minCreated];
            if ($sameRuntimeOnly) {
                $sql .= ' AND runtime_scope = :runtime_scope';
                $params[':runtime_scope'] = $runtimeScope;
            }
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            return (int)$stmt->fetchColumn();
        } catch (\Throwable $_) {}
    }

    $seen = [];
    foreach (decodedExtensionStateFilesForAccount($pluginAccount) as $stateFile) {
        if ($sameRuntimeOnly && $runtimeScope !== '') {
            $expectedStateFile = decodedExtensionStateFileForAccount($pluginAccount);
            $expectedReal = realpath($expectedStateFile) ?: $expectedStateFile;
            $stateReal = realpath($stateFile) ?: $stateFile;
            if ($stateReal !== $expectedReal) continue;
        }
        $data = json_decode((string)@file_get_contents($stateFile), true);
        if (!is_array($data) || !is_array($data['leases'] ?? null)) continue;
        foreach ($data['leases'] as $lease) {
            if (!is_array($lease)) continue;
            if (!decodedExtensionLeaseBelongsToAccount($lease, $pluginAccount)) continue;
            $created = (int)($lease['created_ts'] ?? 0);
            if ($created > 0 && $created < $minCreated) continue;
            $key = (string)($lease['task_id'] ?? '') . '|' . (string)($lease['url'] ?? '');
            if ($key === '|') $key = md5(json_encode($lease, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            $seen[$key] = true;
        }
    }
    return count($seen);
}

function decodedExtensionRecordTaskLease(array $pluginAccount, array $task, array $taskAccount, string $api1Token = ''): void {
    $taskId = decodedExtensionTaskDealId($task);
    $url = decodedExtensionTaskUrl($task);
    if ($taskId === '' && $url === '') return;
    $pdo = decodedExtensionDb();
    $accountId = decodedExtensionDbAccountId($pluginAccount);
    if ($pdo instanceof PDO && $accountId !== '') {
        $runtimeScope = decodedExtensionDbRuntimeScope($pluginAccount);
        $leaseKey = decodedExtensionLeaseKey($pluginAccount, $taskId, $url);
        $api1Token = trim($api1Token);
        if ($api1Token === '') {
            try {
                $stmt = $pdo->prepare('SELECT api1_token FROM task_leases WHERE account_id = :account_id AND runtime_scope = :runtime_scope AND lease_key = :lease_key LIMIT 1');
                $stmt->execute([':account_id' => $accountId, ':runtime_scope' => $runtimeScope, ':lease_key' => $leaseKey]);
                $api1Token = trim((string)$stmt->fetchColumn());
            } catch (\Throwable $_) {}
        }
        try {
            $stmt = $pdo->prepare("
                INSERT OR REPLACE INTO task_leases (
                    account_id, runtime_scope, lease_key, task_id, task_url,
                    task_account_key, task_account_username,
                    api1_token, api1_token_hash, api1_token_expires_at,
                    created_ts, created_at
                ) VALUES (
                    :account_id, :runtime_scope, :lease_key, :task_id, :task_url,
                    :task_account_key, :task_account_username,
                    :api1_token, :api1_token_hash, :api1_token_expires_at,
                    :created_ts, :created_at
                )
            ");
            $stmt->execute([
                ':account_id' => $accountId,
                ':runtime_scope' => $runtimeScope,
                ':lease_key' => $leaseKey,
                ':task_id' => $taskId,
                ':task_url' => $url,
                ':task_account_key' => (string)($taskAccount['key'] ?? ''),
                ':task_account_username' => (string)($taskAccount['username'] ?? ''),
                ':api1_token' => $api1Token,
                ':api1_token_hash' => $api1Token !== '' ? substr(hash('sha256', $api1Token), 0, 16) : '',
                ':api1_token_expires_at' => $api1Token !== '' ? jwtExp($api1Token) : 0,
                ':created_ts' => time(),
                ':created_at' => date('Y-m-d H:i:s'),
            ]);
            return;
        } catch (\Throwable $_) {}
    }

    decodedExtensionMutateState(function (&$state) use ($pluginAccount, $taskId, $url, $taskAccount, $api1Token) {
        $leaseKey = decodedExtensionLeaseKey($pluginAccount, $taskId, $url);
        $existingLease = is_array($state['leases'][$leaseKey] ?? null) ? $state['leases'][$leaseKey] : [];
        $lease = [
            'plugin_account_id' => (string)($pluginAccount['accountId'] ?? ''),
            'task_account_key' => (string)($taskAccount['key'] ?? ''),
            'task_account_username' => (string)($taskAccount['username'] ?? ''),
            'task_id' => $taskId,
            'url' => $url,
            'created_ts' => time(),
            'created_at' => date('Y-m-d H:i:s'),
        ];
        $api1Token = trim($api1Token);
        if ($api1Token === '' && trim((string)($existingLease['api1_token'] ?? '')) !== '') {
            $api1Token = trim((string)$existingLease['api1_token']);
        }
        if ($api1Token !== '') {
            $lease['api1_token'] = $api1Token;
            $lease['api1_token_hash'] = substr(hash('sha256', $api1Token), 0, 16);
            $lease['api1_token_expires_at'] = jwtExp($api1Token);
        }
        $state['leases'][$leaseKey] = $lease;
        return true;
    }, $pluginAccount);
}

function decodedExtensionTaskWithAccountMeta(array $task, array $taskAccount): array {
    $key = (string)($taskAccount['key'] ?? '');
    $username = (string)($taskAccount['username'] ?? '');
    if ($key !== '') {
        $task['task_account_key'] = $key;
        $task['taskAccountKey'] = $key;
    }
    if ($username !== '') {
        $task['task_account_username'] = $username;
        $task['taskAccountUsername'] = $username;
    }
    return $task;
}

function decodedExtensionTaskWithTakeTokenMeta(array $task, string $api1Token = ''): array {
    $api1Token = trim($api1Token);
    if ($api1Token !== '') {
        $task['api1_take_token'] = $api1Token;
        $task['api1TakeToken'] = $api1Token;
        $task['api1_take_token_hash'] = substr(hash('sha256', $api1Token), 0, 16);
    }
    return $task;
}

function decodedExtensionTaskAccountByKey(array $pluginAccount, string $key, string $username = ''): ?array {
    $key = trim($key);
    $username = trim($username);
    if ($key === '' && $username === '') return null;
    foreach (decodedExtensionEnabledTaskAccounts($pluginAccount) as $taskAccount) {
        if ($key !== '' && (string)($taskAccount['key'] ?? '') === $key) return $taskAccount;
        if ($username !== '' && (string)($taskAccount['username'] ?? '') === $username) return $taskAccount;
    }
    return null;
}

function decodedExtensionFindTaskLease(array $pluginAccount, string $taskId, string $url): ?array {
    $dbLease = decodedExtensionFindTaskLeaseFromDb($pluginAccount, $taskId, $url);
    if (is_array($dbLease)) return $dbLease;

    $stateFile = decodedExtensionStateFileForAccount($pluginAccount);
    $state = decodedExtensionLoadState($pluginAccount);
    $lease = decodedExtensionFindTaskLeaseInState($state, $pluginAccount, $taskId, $url);
    if (is_array($lease)) {
        $lease['__state_file'] = $stateFile;
        return $lease;
    }
    return decodedExtensionFindTaskLeaseAcrossStates($pluginAccount, $taskId, $url, $stateFile);
}

function decodedExtensionForgetTaskLease(array $pluginAccount, string $taskId, string $url): int {
    $removed = decodedExtensionForgetTaskLeaseFromDb($pluginAccount, $taskId, $url);
    $currentFile = decodedExtensionStateFileForAccount($pluginAccount);
    $hasLegacyState = is_file($currentFile);
    if ($hasLegacyState) {
        $removed += (int)decodedExtensionMutateState(function (&$state) use ($pluginAccount, $taskId, $url) {
        $removed = 0;
        $keys = [];
        $keys[] = decodedExtensionLeaseKey($pluginAccount, $taskId, $url);
        if ($url !== '') $keys[] = decodedExtensionLeaseKey($pluginAccount, '', $url);
        foreach (array_unique($keys) as $key) {
            if (isset($state['leases'][$key])) {
                unset($state['leases'][$key]);
                $removed++;
            }
        }
        foreach (($state['leases'] ?? []) as $key => $lease) {
            if (!is_array($lease)) continue;
            $sameTask = $taskId !== '' && (string)($lease['task_id'] ?? '') === $taskId;
            $sameUrl = $url !== '' && (string)($lease['url'] ?? '') === $url;
            if ($sameTask || $sameUrl) {
                unset($state['leases'][$key]);
                $removed++;
            }
        }
        return $removed;
        }, $pluginAccount);
    }

    foreach (decodedExtensionStateFilesForAccount($pluginAccount, $currentFile) as $stateFile) {
        $currentReal = realpath($currentFile) ?: $currentFile;
        $candidateReal = realpath($stateFile) ?: $stateFile;
        if ($candidateReal === $currentReal) continue;
        $lockFile = $stateFile . '.lock';
        $fh = @fopen($lockFile, 'c');
        if ($fh) flock($fh, LOCK_EX);
        $data = json_decode((string)@file_get_contents($stateFile), true);
        if (!is_array($data)) $data = ['rotation' => [], 'leases' => []];
        if (!is_array($data['leases'] ?? null)) $data['leases'] = [];
        $changed = false;
        foreach ($data['leases'] as $key => $lease) {
            if (!is_array($lease)) continue;
            if (!decodedExtensionLeaseMatchesTask($lease, $pluginAccount, $taskId, $url)) continue;
            unset($data['leases'][$key]);
            $removed++;
            $changed = true;
        }
        if ($changed) {
            atomicWrite($stateFile, json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        }
        if ($fh) {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }
    return $removed;
}

function decodedExtensionClearTaskRuntimeState(array $pluginAccount): array {
    $queueRemoved = decodedExtensionClearLocalTasks($pluginAccount);
    $leaseRemoved = decodedExtensionClearTaskLeasesFromDb($pluginAccount);
    $stateFile = decodedExtensionStateFileForAccount($pluginAccount);
    if (is_file($stateFile)) {
        $leaseRemoved += (int)decodedExtensionMutateState(function (&$state) {
            $count = is_array($state['leases'] ?? null) ? count($state['leases']) : 0;
            $state['leases'] = [];
            return $count;
        }, $pluginAccount);
    }
    return ['queue_removed' => $queueRemoved, 'lease_removed' => $leaseRemoved];
}

function decodedExtensionTaskAccountForSubmit(array $pluginAccount, string $taskId, string $url): ?array {
    $taskAccounts = decodedExtensionEnabledTaskAccounts($pluginAccount);
    if (!$taskAccounts) return null;
    $byKey = [];
    foreach ($taskAccounts as $taskAccount) $byKey[(string)($taskAccount['key'] ?? '')] = $taskAccount;

    $lease = decodedExtensionFindTaskLease($pluginAccount, $taskId, $url);
    $key = is_array($lease) ? (string)($lease['task_account_key'] ?? '') : '';
    if ($key !== '' && isset($byKey[$key])) return $byKey[$key];
    return $taskAccounts[0];
}

function decodedExtensionDeviceContext(array $input, string $pluginUsername): array {
    $deviceId = trim((string)($input['device_id'] ?? ''));
    return [
        'api_type' => 1,
        'username' => $pluginUsername,
        'group_id' => trim((string)($input['group_id'] ?? $pluginUsername)),
        'device_id' => $deviceId,
        'fingerprint_key' => trim((string)($input['fingerprint_key'] ?? '')),
        'fingerprint_id' => trim((string)($input['fingerprint_id'] ?? '')),
        'fingerprint_name' => trim((string)($input['fingerprint_name'] ?? '')),
        'client_instance_id' => trim((string)($input['client_instance_id'] ?? $input['clientInstanceId'] ?? '')),
        'platform' => trim((string)($input['platform'] ?? 'extension')),
        'device_type' => trim((string)($input['device_type'] ?? 'extension')),
        'device_label' => trim((string)($input['device_label'] ?? '浏览器插件')) ?: '浏览器插件',
        'client' => trim((string)($input['client'] ?? 'gejie-extension')) ?: 'gejie-extension',
    ];
}

function handleDecodedExtensionApi(): bool {
    global $API1_TAKE_URL, $TARGETS, $LOG_FILE, $MAX_LOGS;
    global $DECODED_EXTENSION_SUBMIT_LOG_FILE, $MAX_LOG_RESPONSE_BYTES, $DEVICE_FILE;
    global $PLUGIN_UPDATE_FILE;

    $path = decodedExtensionApiPath();
    if ($path === '') return false;

    decodedExtensionCorsHeaders();
    if (strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? '')) === 'OPTIONS') {
        http_response_code(204);
        exit;
    }
    if (strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? '')) !== 'POST') {
        http_response_code(405);
        jsonResp(['success' => false, 'error' => 'method not allowed']);
    }

    $input = decodedExtensionReadJsonBody();
    $bearer = decodedExtensionBearerToken();
    $pluginUsername = trim((string)($input['username'] ?? $input['accountId'] ?? ''));
    $pluginToken = trim((string)($input['token'] ?? $input['auth_token'] ?? $bearer));
    if ($pluginUsername === '' && $pluginToken !== '') {
        $pluginUsername = resolveApi1UsernameFromToken($pluginToken);
    }
    $pluginAccount = ($pluginUsername !== '' && $pluginToken !== '') ? decodedExtensionFindAccount($pluginUsername, $pluginToken) : null;
    if (!$pluginAccount && $pluginToken !== '') {
        $pluginAccount = decodedExtensionFindAccountByToken($pluginToken);
        if (is_array($pluginAccount)) $pluginUsername = (string)($pluginAccount['accountId'] ?? $pluginUsername);
    }
    if (!$pluginAccount) {
        http_response_code(403);
        jsonResp(['success' => false, 'error' => 'account not allowed']);
    }
    $deviceContext = decodedExtensionDeviceContext($input, $pluginUsername);
    if (($deviceContext['device_id'] ?? '') === '') {
        http_response_code(400);
        jsonResp(['success' => false, 'error' => 'device_id is empty']);
    }
    $deviceCheck = checkDeviceAllowed($DEVICE_FILE, $deviceContext);
    if (!$deviceCheck['allowed']) {
        http_response_code(403);
        jsonResp(['success' => false, 'error' => $deviceCheck['msg'] ?? 'device disabled']);
    }
    $runtimeAccount = decodedExtensionRuntimeAccount($pluginAccount, $deviceContext);
    $taskAccountPool = is_array($pluginAccount) ? decodedExtensionEnabledTaskAccounts($pluginAccount) : [];

    if ($path === '/api/login') {
        if ($pluginUsername === '' || $pluginToken === '') {
            http_response_code(400);
            jsonResp(['success' => false, 'error' => 'username or token is empty']);
        }
        if (!$pluginAccount) {
            appendLog($LOG_FILE, [
                'time' => date('Y-m-d H:i:s'),
                'api_type' => 1,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
                'username' => $pluginUsername,
                'status' => 'login_rejected',
                'source' => 'decoded_extension_login',
                'error' => 'decoded extension account not allowed',
            ], $MAX_LOGS);
            http_response_code(403);
            jsonResp(['success' => false, 'error' => 'account not allowed']);
        }
        if (!$taskAccountPool) {
            http_response_code(500);
            jsonResp(['success' => false, 'error' => 'task account pool is empty']);
        }
        $loginOk = null;
        $loginAttempts = [];
        $api1Auth = [];
        foreach ($taskAccountPool as $loginTaskAccount) {
            $tryAuth = decodedExtensionApi1AuthForTaskAccount($pluginAccount, $loginTaskAccount);
            $tryTokenInfo = getApi1Token($tryAuth, decodedExtensionApi1TokenFileForAccount($pluginAccount, $tryAuth));
            $loginAttempts[] = [
                'api1_username' => $tryAuth['username'] ?? '',
                'ok' => !empty($tryTokenInfo['ok']),
                'cached' => !empty($tryTokenInfo['cached']),
                'msg' => (string)($tryTokenInfo['msg'] ?? ''),
            ];
            if (!empty($tryTokenInfo['ok'])) {
                if (!$loginOk) {
                    $loginOk = $tryTokenInfo;
                    $api1Auth = $tryAuth;
                }
            }
        }
        if (!$loginOk) {
            http_response_code(502);
            jsonResp(['success' => false, 'error' => 'all task accounts login failed']);
        }
        cacheApi1TokenUsername($pluginToken, $pluginUsername, time() + 86400 * 7);
        $taskMode = decodedExtensionNormalizeTaskMode($pluginAccount['task_mode'] ?? 'poll');
        $taskParallelism = $taskMode === 'concurrent' ? decodedExtensionNormalizeTaskParallelism($pluginAccount['task_parallelism'] ?? null, count($taskAccountPool)) : 1;
        appendLog($LOG_FILE, [
            'time' => date('Y-m-d H:i:s'),
            'api_type' => 1,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'username' => $pluginUsername,
            'api1_username' => $api1Auth['username'] ?? '',
            'api1_pool_count' => count($taskAccountPool),
            'task_mode' => $taskMode,
            'task_parallelism' => $taskParallelism,
            'task_parallelism_configured' => decodedExtensionNormalizeTaskParallelism($pluginAccount['task_parallelism'] ?? null, count($taskAccountPool)),
            'api1_login_attempts' => $loginAttempts,
            'api1_token_cached' => !empty($loginOk['cached']),
            'status' => 'success',
            'source' => 'decoded_extension_login',
        ], $MAX_LOGS);
        jsonResp(['success' => true, 'msg' => 'ok', 'data' => [
            'accountId' => $pluginUsername,
            'task_mode' => $taskMode,
            'task_parallelism' => $taskParallelism,
            'task_account_count' => count($taskAccountPool),
        ]]);
    }

    if ($path === '/api/task') {
        if (!$pluginAccount) {
            http_response_code(403);
            jsonResp(['success' => false, 'error' => 'account not allowed']);
        }
        if (!$taskAccountPool) {
            http_response_code(500);
            jsonResp(['success' => false, 'error' => 'task account pool is empty']);
        }

        $taskMode = decodedExtensionNormalizeTaskMode($pluginAccount['task_mode'] ?? 'poll');
        $configuredParallelism = decodedExtensionNormalizeTaskParallelism($pluginAccount['task_parallelism'] ?? null, count($taskAccountPool));
        $maxRequestCount = $taskMode === 'concurrent' ? min(count($taskAccountPool), $configuredParallelism) : 1;
        $requestedCount = $taskMode === 'concurrent' ? max(1, (int)($input['batch_size'] ?? $input['request_count'] ?? $maxRequestCount)) : 1;
        $requestedCount = min(max(1, $requestedCount), $maxRequestCount);
        $takeLock = decodedExtensionAcquireTakeLock($runtimeAccount);
        $runtimeActiveLeaseCount = decodedExtensionActiveTaskLeaseCount($runtimeAccount, true);
        $remainingRuntimeSlots = $taskMode === 'concurrent' ? max(0, $maxRequestCount - $runtimeActiveLeaseCount) : 1;
        $blockUpstreamTake = $taskMode === 'concurrent' && $remainingRuntimeSlots <= 0;
        if ($taskMode === 'concurrent') {
            $requestedCount = min($requestedCount, max(0, $remainingRuntimeSlots));
        }
        $packets = [];
        $attempts = [];
        $lastMsg = 'no task';
        $seenPacketKeys = [];

        $appendPacket = function(array $task, ?array $taskAccount = null, string $api1Token = '') use (&$packets, &$seenPacketKeys, $pluginAccount, $runtimeAccount, $taskAccountPool) {
            if ($api1Token === '') {
                $api1Token = trim((string)($task['api1_take_token'] ?? $task['api1TakeToken'] ?? ''));
            }
            $taskId = decodedExtensionTaskDealId($task);
            $taskUrl = decodedExtensionTaskUrl($task);
            $dedupeKey = ($taskId !== '' ? $taskId : md5($taskUrl)) . '|' . $taskUrl;
            if (isset($seenPacketKeys[$dedupeKey])) return false;
            $seenPacketKeys[$dedupeKey] = true;
            $resolvedTaskAccount = is_array($taskAccount) ? $taskAccount : (decodedExtensionTaskAccountByKey($pluginAccount, (string)($task['task_account_key'] ?? $task['taskAccountKey'] ?? ''), (string)($task['task_account_username'] ?? $task['taskAccountUsername'] ?? '')) ?? decodedExtensionTaskAccountForSubmit($runtimeAccount, $taskId, $taskUrl) ?? decodedExtensionOrderedTaskAccounts($pluginAccount)[0] ?? $taskAccountPool[0]);
            if (is_array($resolvedTaskAccount)) {
                decodedExtensionRecordTaskLease($runtimeAccount, $task, $resolvedTaskAccount, $api1Token);
                $task = decodedExtensionTaskWithAccountMeta($task, $resolvedTaskAccount);
                $task = decodedExtensionTaskWithTakeTokenMeta($task, $api1Token);
                $task['task_runtime_scope'] = (string)($runtimeAccount['__storage_scope'] ?? '');
                $task['taskRuntimeScope'] = (string)($runtimeAccount['__storage_scope'] ?? '');
            }
            $packets[] = [
                'task' => $task,
                'task_account' => is_array($resolvedTaskAccount) ? $resolvedTaskAccount : $taskAccountPool[0],
            ];
            return true;
        };

        if ($requestedCount > 0) {
            foreach (decodedExtensionPopLocalTasks($requestedCount, $runtimeAccount) as $task) {
                $appendPacket($task);
            }
        }

        $fetchRounds = 0;
        while (!$blockUpstreamTake && count($packets) < $requestedCount && $fetchRounds < max(1, $requestedCount)) {
            $fetchRounds++;
            $beforePacketCount = count($packets);
            $missingForRound = max(1, $requestedCount - count($packets));
            $orderedTaskAccounts = decodedExtensionOrderedTaskAccounts($pluginAccount);
            if ($taskMode === 'poll') {
                $orderedTaskAccounts = array_slice($orderedTaskAccounts, 0, 1);
            } else {
                $orderedTaskAccounts = array_slice($orderedTaskAccounts, 0, min($configuredParallelism, $missingForRound));
            }
            $takeResult = decodedExtensionTakeTaskFromApi1Pool($API1_TAKE_URL, $pluginAccount, $orderedTaskAccounts);
            $attempts = array_merge($attempts, is_array($takeResult['attempts'] ?? null) ? $takeResult['attempts'] : []);
            $lastMsg = (string)($takeResult['last_msg'] ?? 'no task');
            $fetchedPackets = [];
            if (is_array($takeResult['task'] ?? null)) {
                $fetchedPackets[] = [
                    'task' => $takeResult['task'],
                    'task_account' => is_array($takeResult['task_account'] ?? null) ? $takeResult['task_account'] : null,
                    'api1_token' => (string)($takeResult['api1_token'] ?? ''),
                ];
            }
            foreach (($takeResult['extra_tasks'] ?? []) as $extra) {
                if (!is_array($extra) || !is_array($extra['task'] ?? null)) continue;
                $fetchedPackets[] = [
                    'task' => $extra['task'],
                    'task_account' => is_array($extra['task_account'] ?? null) ? $extra['task_account'] : null,
                    'api1_token' => (string)($extra['api1_token'] ?? ''),
                ];
            }

            $missing = max(0, $requestedCount - count($packets));
            foreach ($fetchedPackets as $idx => $packet) {
                if (!is_array($packet['task'] ?? null)) continue;
                if ($idx < $missing) {
                    $appendPacket($packet['task'], $packet['task_account'] ?? null, (string)($packet['api1_token'] ?? ''));
                    continue;
                }
                $queuedTask = $packet['task'];
                if (is_array($packet['task_account'] ?? null)) {
                    decodedExtensionRecordTaskLease($runtimeAccount, $packet['task'], $packet['task_account'], (string)($packet['api1_token'] ?? ''));
                    $queuedTask = decodedExtensionTaskWithAccountMeta($packet['task'], $packet['task_account']);
                    $queuedTask = decodedExtensionTaskWithTakeTokenMeta($queuedTask, (string)($packet['api1_token'] ?? ''));
                }
                decodedExtensionAppendLocalTasks([ $queuedTask ], $runtimeAccount);
            }
            if (count($packets) <= $beforePacketCount) break;
        }

        if (!$packets) {
            if ($blockUpstreamTake) {
                $lastMsg = '当前插件并发额度已满，服务器已暂停拉取新任务';
            }
            appendLog($LOG_FILE, [
                'time' => date('Y-m-d H:i:s'),
                'api_type' => 1,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
                'username' => $pluginUsername,
                'device_id' => $deviceContext['device_id'] ?? '',
                'runtime_scope' => (string)($runtimeAccount['__storage_scope'] ?? ''),
                'status' => $blockUpstreamTake ? 'active_tasks_pending' : 'no_task',
                'source' => 'decoded_extension_task',
            'task_mode' => $taskMode,
            'task_parallelism' => $configuredParallelism,
            'runtime_active_lease_count' => $runtimeActiveLeaseCount,
            'remaining_runtime_slots' => $remainingRuntimeSlots,
            'upstream_take_paused' => $blockUpstreamTake,
            'forward_url' => $API1_TAKE_URL,
                'forward_attempts' => $attempts,
            ], $MAX_LOGS);
            jsonResp(['success' => false, 'msg' => $lastMsg ?: 'no task', 'data' => ['msg' => $lastMsg ?: 'no task', 'runtime_active_lease_count' => $runtimeActiveLeaseCount, 'remaining_runtime_slots' => $remainingRuntimeSlots, 'upstream_take_paused' => $blockUpstreamTake, 'pool' => ['accounts' => count($taskAccountPool), 'task_parallelism' => $configuredParallelism]]]);
        }

        $lastMsg = 'ok';
        $firstPacket = $packets[0];
        $task = $firstPacket['task'];
        $taskAccount = $firstPacket['task_account'];
        $responseTasks = array_map(fn($packet) => $packet['task'], $packets);
        $taskCount = count($responseTasks);
        $api1Username = is_array($taskAccount) ? (string)($taskAccount['username'] ?? '') : '';
        appendLog($LOG_FILE, [
            'time' => date('Y-m-d H:i:s'),
            'api_type' => 1,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'username' => $pluginUsername,
            'api1_username' => $api1Username,
            'device_id' => $deviceContext['device_id'] ?? '',
            'runtime_scope' => (string)($runtimeAccount['__storage_scope'] ?? ''),
            'status' => 'success',
            'source' => $taskCount > 1 ? 'decoded_extension_task_batch' : 'decoded_extension_task_local',
            'task_mode' => $taskMode,
            'task_parallelism' => $configuredParallelism,
            'requested_count' => $requestedCount,
            'fetch_rounds' => $fetchRounds,
            'batch_size' => $taskCount,
            'runtime_active_lease_count_before_take' => $runtimeActiveLeaseCount,
            'remaining_runtime_slots_before_take' => $remainingRuntimeSlots,
            'upstream_take_paused' => $blockUpstreamTake,
            'forward_url' => $API1_TAKE_URL,
            'forward_attempts' => $attempts,
            'task_id' => $task['taskId'] ?? '',
            'task_url' => $task['url'] ?? '',
        ], $MAX_LOGS);

        if ($requestedCount > 1 || $taskCount > 1) {
            jsonResp([
                'success' => true,
                'tasks' => $responseTasks,
                'task' => $task,
                'msg' => 'ok',
                'data' => [
                    'tasks' => $responseTasks,
                    'task' => $task,
                    'requested_count' => $requestedCount,
                    'batch_size' => $taskCount,
                    'runtime_active_lease_count' => $runtimeActiveLeaseCount,
                    'remaining_runtime_slots' => $remainingRuntimeSlots,
                    'upstream_take_paused' => $blockUpstreamTake,
                    'pool' => ['accounts' => count($taskAccountPool), 'task_parallelism' => $configuredParallelism],
                ],
            ]);
        }

        jsonResp(['success' => true, 'task' => $task]);
    }

    if ($path === '/api/submit') {
        if (!$pluginAccount) {
            http_response_code(403);
            jsonResp(['success' => false, 'error' => 'account not allowed']);
        }
        if (!$taskAccountPool) {
            http_response_code(500);
            jsonResp(['success' => false, 'error' => 'task account pool is empty']);
        }

        $submitStart = microtime(true);
        $taskId = trim((string)($input['deal_id'] ?? $input['dealId'] ?? $input['taskId'] ?? $input['task_id'] ?? $input['tid'] ?? $input['trace_id'] ?? ''));
        $submitOk = array_key_exists('success', $input) ? (bool)$input['success'] : true;
        $taskAccountKey = trim((string)($input['taskAccountKey'] ?? $input['task_account_key'] ?? $input['__task_account_key'] ?? ''));
        $taskAccountUsername = trim((string)($input['taskAccountUsername'] ?? $input['task_account_username'] ?? $input['api1_username'] ?? ''));
        $leaseUrl = trim((string)($input['productUrl'] ?? $input['pageUrl'] ?? $input['taskUrl'] ?? $input['task_url'] ?? $input['url'] ?? $input['rawResponseUrl'] ?? $input['apiUrl'] ?? ''));
        $taskRuntimeScope = trim((string)($input['taskRuntimeScope'] ?? $input['task_runtime_scope'] ?? ''));
        if ($taskRuntimeScope !== '') {
            $runtimeAccount = decodedExtensionRuntimeAccount($pluginAccount, $deviceContext, $taskRuntimeScope);
        }
        $submitLease = decodedExtensionFindTaskLease($runtimeAccount, $taskId, $leaseUrl);
        $leaseTaskAccount = is_array($submitLease)
            ? decodedExtensionTaskAccountByKey($pluginAccount, (string)($submitLease['task_account_key'] ?? ''), (string)($submitLease['task_account_username'] ?? ''))
            : null;
        $inputTaskAccount = decodedExtensionTaskAccountByKey($pluginAccount, $taskAccountKey, $taskAccountUsername);
        $submitTaskAccount = $leaseTaskAccount ?? $inputTaskAccount ?? decodedExtensionTaskAccountForSubmit($runtimeAccount, $taskId, $leaseUrl) ?? $taskAccountPool[0];
        $api1Auth = decodedExtensionApi1AuthForTaskAccount($pluginAccount, $submitTaskAccount);

        if (!$submitOk) {
            $purged = is_array($submitLease)
                ? decodedExtensionClearTaskRuntimeState($runtimeAccount)
                : ['queue_removed' => 0, 'lease_removed' => 0, 'skipped' => 'lease_missing'];
            $entry = [
                'time' => date('Y-m-d H:i:s'),
                'api_type' => 1,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
                'username' => $pluginUsername,
                'api1_username' => $api1Auth['username'] ?? '',
                'device_id' => $deviceContext['device_id'] ?? '',
                'runtime_scope' => (string)($runtimeAccount['__storage_scope'] ?? ''),
                'task_runtime_scope' => $taskRuntimeScope,
                'status' => 'client_task_failed',
                'source' => 'decoded_extension_submit',
                'task_id' => $taskId,
                'task_url' => $input['productUrl'] ?? $input['pageUrl'] ?? '',
                'error' => $input['error'] ?? '',
                'purged_runtime' => $purged,
            ];
            appendLog($LOG_FILE, $entry, $MAX_LOGS);
            appendLog($DECODED_EXTENSION_SUBMIT_LOG_FILE, $entry, 1000);
            jsonResp(['success' => true, 'msg' => 'failure recorded', 'data' => ['raw' => decodedExtensionRawSuccess()]]);
        }

        $submitUrl = trim((string)($input['url'] ?? $input['rawResponseUrl'] ?? $input['apiUrl'] ?? $input['productUrl'] ?? $input['pageUrl'] ?? ''));
        $submitResult = $input['rawResponseText'] ?? $input['result'] ?? '';
        if (is_array($submitResult) || is_object($submitResult)) {
            $submitResult = json_encode($submitResult, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        }
        $submitResult = (string)$submitResult;

        if ($submitUrl === '' || trim($submitResult) === '') {
            http_response_code(400);
            jsonResp(['success' => false, 'error' => 'submit url or result is empty']);
        }

        $inputTakeToken = trim((string)($input['api1_take_token'] ?? $input['api1TakeToken'] ?? ''));
        $leaseToken = is_array($submitLease) ? trim((string)($submitLease['api1_token'] ?? '')) : '';
        $leaseTokenSource = $leaseToken !== '' ? 'lease_take_token' : '';
        if ($leaseToken === '' && $inputTakeToken !== '') {
            $leaseToken = $inputTakeToken;
            $leaseTokenSource = is_array($submitLease) ? 'input_take_token' : 'input_take_token_without_lease';
        }
        if ($leaseToken === '') {
            $purged = ['queue_removed' => 0, 'lease_removed' => 0, 'skipped' => !is_array($submitLease) ? 'lease_missing' : 'token_missing'];
            $entry = [
                'time' => date('Y-m-d H:i:s'),
                'api_type' => 1,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
                'username' => $pluginUsername,
                'api1_username' => $api1Auth['username'] ?? '',
                'task_account_key' => (string)($submitTaskAccount['key'] ?? ''),
                'input_task_account_key' => $taskAccountKey,
                'lease_task_account_key' => is_array($submitLease) ? (string)($submitLease['task_account_key'] ?? '') : '',
                'lease_found' => is_array($submitLease),
                'token_source' => 'missing_take_token',
                'task_runtime_scope' => $taskRuntimeScope,
                'status' => 'local_lease_missing',
                'source' => 'decoded_extension_submit',
                'task_id' => $taskId,
                'task_url' => $submitUrl,
                'forward_url' => $TARGETS[1]['url'],
                'error' => 'missing active take lease, submit blocked to avoid stale deal_id/token mismatch; please fetch a fresh task',
                'purged_runtime' => $purged,
                'timing_ms' => ['forward' => 0, 'total' => elapsedMs($submitStart)],
            ];
            appendLog($LOG_FILE, $entry, $MAX_LOGS);
            appendLog($DECODED_EXTENSION_SUBMIT_LOG_FILE, $entry, 1000);
            http_response_code(409);
            jsonResp([
                'success' => false,
                'error' => 'missing active take lease, submit blocked to avoid stale deal_id/token mismatch; please fetch a fresh task',
                'retryable' => false,
                'leaseMissing' => true,
                '_proxy' => ['submit_accepted' => false, 'status' => 'local_lease_missing'],
            ]);
        }
        if (!is_array($submitLease) && $leaseTokenSource === 'input_take_token_without_lease') {
            $leaseRecordUrl = $leaseUrl !== '' ? $leaseUrl : $submitUrl;
            decodedExtensionRecordTaskLease($runtimeAccount, [
                'deal_id' => $taskId,
                'dealId' => $taskId,
                'taskId' => $taskId,
                'url' => $leaseRecordUrl,
                'taskUrl' => $leaseRecordUrl,
            ], $submitTaskAccount, $leaseToken);
        }
        $tokenInfo = $leaseToken !== '' ? [
            'ok' => true,
            'token' => $leaseToken,
            'cached' => true,
            'expires_at' => jwtExp($leaseToken),
            'source' => 'lease',
        ] : getApi1Token($api1Auth, decodedExtensionApi1TokenFileForAccount($pluginAccount, $api1Auth));
        if (empty($tokenInfo['ok'])) {
            http_response_code(502);
            jsonResp(['success' => false, 'error' => (string)($tokenInfo['msg'] ?? 'api1 login failed')]);
        }
        $submitToken = (string)($tokenInfo['token'] ?? '');
        $submitTokenSource = $leaseToken !== '' ? $leaseTokenSource : 'account_cache';
        $submitTokenHash = $submitToken !== '' ? substr(hash('sha256', $submitToken), 0, 16) : '';

        $candidateSubmitUrls = array_values(array_unique(array_filter([$submitUrl], fn($u) => trim((string)$u) !== '')));
        $forwardAttempts = [];
        $forwardBody = '';
        $result = ['response' => '', 'error' => 'no submit attempt', 'http_code' => 0];
        $serverResp = null;
        $forwardMs = 0;
        $isForwardSuccess = false;
        foreach ($candidateSubmitUrls as $candidateSubmitUrl) {
            $submitUrl = $candidateSubmitUrl;
            $forwardBody = json_encode([
                'appVersion' => (string)($input['appVersion'] ?? 'vv2'),
                'url' => $submitUrl,
                'result' => $submitResult,
            ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

            $stageMark = microtime(true);
            $result = forwardToServer($TARGETS[1]['url'], (string)$forwardBody, false, ['Authorization: Bearer ' . $submitToken]);
            $serverResp = json_decode((string)$result['response'], true);
            $forwardMs = durationMs($stageMark, microtime(true));
            $isForwardSuccess = api1ForwardSuccess($serverResp);
            $forwardAttempts[] = forwardAttemptSummary($result, $serverResp) + [
                'attempt' => count($forwardAttempts) + 1,
                'total_ms' => $forwardMs,
                'submit_url' => $submitUrl,
                'api1_username' => $api1Auth['username'] ?? '',
                'token_source' => $submitTokenSource,
                'token_hash' => $submitTokenHash,
            ];
            if ($result['error'] || $isForwardSuccess || !api1SubmitDealNotFound($serverResp)) break;
        }

        $postSubmitCleanup = ['lease_removed' => 0, 'runtime_purged' => null];
        if ($isForwardSuccess) {
            $postSubmitCleanup['lease_removed'] = decodedExtensionForgetTaskLease($runtimeAccount, $taskId, $leaseUrl);
        } elseif (api1SubmitDealNotFound($serverResp)) {
            $postSubmitCleanup['lease_removed'] = decodedExtensionForgetTaskLease($runtimeAccount, $taskId, $leaseUrl);
            $postSubmitCleanup['runtime_purged'] = decodedExtensionClearTaskRuntimeState($runtimeAccount);
        }

        $entry = [
            'time' => date('Y-m-d H:i:s'),
            'api_type' => 1,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'username' => $pluginUsername,
            'api1_username' => $api1Auth['username'] ?? '',
            'device_id' => $deviceContext['device_id'] ?? '',
            'platform' => $deviceContext['platform'] ?? '',
            'device_type' => $deviceContext['device_type'] ?? '',
            'device_label' => $deviceContext['device_label'] ?? '',
            'client' => $deviceContext['client'] ?? '',
            'client_label' => resolveClientLabel($deviceContext),
            'runtime_scope' => (string)($runtimeAccount['__storage_scope'] ?? ''),
            'task_runtime_scope' => $taskRuntimeScope,
            'task_account_key' => (string)($submitTaskAccount['key'] ?? ''),
            'input_task_account_key' => $taskAccountKey,
            'lease_task_account_key' => is_array($submitLease) ? (string)($submitLease['task_account_key'] ?? '') : '',
            'lease_found' => is_array($submitLease),
            'token_source' => $submitTokenSource,
            'token_hash' => $submitTokenHash,
            'post_submit_cleanup' => $postSubmitCleanup,
            'status' => $result['error'] ? 'forward_fail' : ($isForwardSuccess ? 'success' : 'task_server_error'),
            'source' => 'decoded_extension_submit',
            'task_id' => $taskId,
            'task_url' => $submitUrl,
            'forward_url' => $TARGETS[1]['url'],
            'forward_result_len' => strlen($submitResult),
            'forward_attempts' => $forwardAttempts,
            'response' => compactLogResponse($serverResp ?? $result['response'], $MAX_LOG_RESPONSE_BYTES),
            'timing_ms' => ['forward' => $forwardMs, 'total' => elapsedMs($submitStart)],
        ];
        if ($result['error']) $entry['error'] = $result['error'];
        appendLog($LOG_FILE, $entry, $MAX_LOGS);
        appendLog($DECODED_EXTENSION_SUBMIT_LOG_FILE, $entry, 1000);
        saveUploadDump(date('Ymd_His') . '_' . substr(md5($submitUrl . '|' . $taskId), 0, 8), [
            'time' => date('Y-m-d H:i:s'),
            'api_type' => 1,
            'source' => 'decoded_extension_submit',
            'target_url' => $TARGETS[1]['url'],
            'request_body' => json_decode((string)$forwardBody, true),
            'http_code' => $result['http_code'] ?? 0,
            'response_json' => is_array($serverResp) ? $serverResp : null,
            'response_raw' => $result['response'],
            'error' => $result['error'],
            'task_id' => $taskId,
            'api1_username' => $api1Auth['username'] ?? '',
            'task_account_key' => (string)($submitTaskAccount['key'] ?? ''),
            'input_task_account_key' => $taskAccountKey,
            'lease_task_account_key' => is_array($submitLease) ? (string)($submitLease['task_account_key'] ?? '') : '',
            'lease_found' => is_array($submitLease),
            'token_source' => $submitTokenSource,
            'token_hash' => $submitTokenHash,
            'post_submit_cleanup' => $postSubmitCleanup,
        ]);

        if ($result['error']) {
            http_response_code(502);
            jsonResp(['success' => false, 'error' => 'submit forward failed: ' . $result['error'], 'retryable' => true]);
        }
        if ($isForwardSuccess) {
            jsonResp(['success' => true, 'data' => ['raw' => $serverResp ?: decodedExtensionRawSuccess()], '_proxy' => ['submit_accepted' => true, 'status' => $entry['status']]]);
        }

        $upstreamError = api1SubmitFailureMessage($serverResp ?: $result['response']);
        http_response_code(400);
        jsonResp([
            'success' => false,
            'error' => $upstreamError,
            'upstreamSubmitFailed' => true,
            'retryable' => false,
            'data' => ['raw' => $serverResp ?: $result['response']],
            '_proxy' => ['submit_accepted' => false, 'status' => $entry['status']],
        ]);
    }

    if ($path === '/api/heartbeat') {
        $currentPluginVersion = trim((string)($input['extension_version'] ?? $input['plugin_version'] ?? $input['version'] ?? ''));
        $currentPluginCode = (int)($input['extension_version_code'] ?? $input['plugin_version_code'] ?? $input['version_code'] ?? 0);
        jsonResp([
            'success' => true,
            'msg' => 'ok',
            'data' => [
                'allowed' => true,
                'device_key' => $deviceCheck['device_key'] ?? '',
                'last_seen' => date('Y-m-d H:i:s'),
                'plugin_update' => buildPluginUpdateResponse($PLUGIN_UPDATE_FILE, $currentPluginVersion, $currentPluginCode),
            ],
        ]);
    }

    return true;
}

function saveDecryptDump(string $encryptedData, string $plain, int $apiType, $decrypted, $productData = null, $forwardPayload = null): string {
    $dumpDir = __DIR__ . '/decrypt_dumps';
    if (!is_dir($dumpDir)) @mkdir($dumpDir, 0755, true);

    $dumpId = date('Ymd_His') . '_' . substr(md5($encryptedData), 0, 8);
    $dumpData = [
        'dump_time' => date('Y-m-d H:i:s'),
        'api_type' => $apiType,
        'encrypted_len' => strlen($encryptedData),
        'decrypted_len' => strlen($plain),
        'decrypted_full' => $decrypted,
        'decrypted_keys' => is_array($decrypted) ? array_keys($decrypted) : 'not_array',
        'product_data' => $productData,
        'forward_payload' => $forwardPayload,
    ];

    if (is_array($decrypted) && isset($decrypted['responseContent']) && is_array($decrypted['responseContent'])) {
        $rc = $decrypted['responseContent'];
        $dumpData['responseContent_keys'] = array_keys($rc);
        $rb = $rc['response_body'] ?? null;
        $dumpData['response_body_type'] = gettype($rb);
        $dumpData['response_body_len'] = is_string($rb) ? strlen($rb) : null;
        if (is_string($rb) && $rb !== '') {
            $parsed = jsonDecodeAssoc($rb);
            $dumpData['response_body_parsed'] = $parsed;
            $dumpData['response_body_parse_ok'] = is_array($parsed);
        }
    }

    @file_put_contents("$dumpDir/$dumpId.json", json_encode($dumpData, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));

    if (mt_rand(1, 30) === 1) {
        $dumps = glob("$dumpDir/*.json");
        if (is_array($dumps) && count($dumps) > 20) {
            usort($dumps, fn($a, $b) => filemtime($a) - filemtime($b));
            for ($i = 0; $i < count($dumps) - 20; $i++) @unlink($dumps[$i]);
        }
    }

    return $dumpId;
}

function saveUploadDump(string $dumpId, array $detail): string {
    global $ENABLE_UPLOAD_DETAIL_DUMPS;
    if (!$ENABLE_UPLOAD_DETAIL_DUMPS) {
        return '';
    }
    $dumpDir = __DIR__ . '/upload_dumps';
    if (!is_dir($dumpDir)) @mkdir($dumpDir, 0755, true);

    $uploadId = $dumpId !== '' ? $dumpId : date('Ymd_His') . '_' . substr(md5(json_encode($detail)), 0, 8);
    @file_put_contents("$dumpDir/$uploadId.json", json_encode($detail, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));

    if (mt_rand(1, 50) === 1) {
        $dumps = glob("$dumpDir/*.json");
        if (is_array($dumps) && count($dumps) > 50) {
            usort($dumps, fn($a, $b) => filemtime($a) - filemtime($b));
            for ($i = 0; $i < count($dumps) - 50; $i++) @unlink($dumps[$i]);
        }
    }

    return $uploadId;
}

function maybeSaveSuccessDecryptDump(string $encryptedData, string $plain, int $apiType, $decrypted, $productData = null, $forwardPayload = null): string {
    global $SAVE_SUCCESS_DECRYPT_DUMPS;
    if (!$SAVE_SUCCESS_DECRYPT_DUMPS) {
        return '';
    }
    return saveDecryptDump($encryptedData, $plain, $apiType, $decrypted, $productData, $forwardPayload);
}

// ===== 统计函数 =====
function getStatsFile(string $dir, string $date = ''): string {
    if ($date === '') $date = date('Y-m-d');
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    return $dir . '/' . $date . '.json';
}

function readDayStats(string $dir, string $date = ''): array {
    $file = getStatsFile($dir, $date);
    if (!is_file($file)) return [];
    $data = json_decode((string)@file_get_contents($file), true);
    return is_array($data) ? $data : [];
}

function fingerprintInfoFromInput(array $input): array {
    $username = trim((string)($input['username'] ?? $input['用户名'] ?? 'unknown'));
    $groupId = trim((string)($input['group_id'] ?? $input['组ID'] ?? ''));
    $deviceId = trim((string)($input['device_id'] ?? $input['设备ID'] ?? ''));
    $fpKey = trim((string)($input['fingerprint_key'] ?? ''));
    $fpId = trim((string)($input['fingerprint_id'] ?? ''));
    $fpName = trim((string)($input['fingerprint_name'] ?? ''));

    if ($fpKey === '') $fpKey = $fpId;
    if ($fpKey === '') $fpKey = $fpName;
    if ($fpKey === '') $fpKey = $deviceId;
    if ($fpKey === '') $fpKey = 'unknown-' . substr(md5($username . '|' . ($_SERVER['REMOTE_ADDR'] ?? '')), 0, 10);

    return [
        'key' => md5($username . '|' . $fpKey),
        'fingerprint_key' => $fpKey,
        'fingerprint_id' => $fpId,
        'fingerprint_name' => $fpName,
        'username' => $username,
        'group_id' => $groupId,
        'device_id' => $deviceId,
    ];
}

function recordStats(string $dir, array $input, int $apiType, string $status, string $taskId = ''): void {
    global $MAX_STAT_RECORDS_PER_DEVICE, $ENABLE_SUBMIT_STATS, $STATS_DIR;
    if (!$ENABLE_SUBMIT_STATS && str_replace('\\', '/', $dir) === str_replace('\\', '/', $STATS_DIR)) {
        return;
    }
    $date = date('Y-m-d');
    $file = getStatsFile($dir, $date);
    $stats = readDayStats($dir, $date);
    $fp = fingerprintInfoFromInput($input);
    $key = $fp['key'];
    $accountRemark = displayAccountRemark($apiType, $fp['username'], $fp['group_id']);

    if (!isset($stats[$key])) {
        $stats[$key] = [
            'fingerprint_key' => $fp['fingerprint_key'],
            'fingerprint_id' => $fp['fingerprint_id'],
            'fingerprint_name' => $fp['fingerprint_name'],
            'username' => $fp['username'],
            'account_remark' => $accountRemark,
            'group_id' => $fp['group_id'],
            'device_id' => $fp['device_id'],
            'total' => 0,
            'success' => 0,
            'fail' => 0,
            'records' => [],
        ];
    }
    $stats[$key]['fingerprint_key'] = $fp['fingerprint_key'];
    $stats[$key]['fingerprint_id'] = $fp['fingerprint_id'];
    $stats[$key]['fingerprint_name'] = $fp['fingerprint_name'];
    $stats[$key]['username'] = $fp['username'];
    if ($accountRemark !== '') $stats[$key]['account_remark'] = $accountRemark;
    $stats[$key]['group_id'] = $fp['group_id'];
    $stats[$key]['device_id'] = $fp['device_id'];
    $stats[$key]['last_seen'] = date('Y-m-d H:i:s');
    $stats[$key]['total']++;
    if ($status === 'success') {
        $stats[$key]['success']++;
    } else {
        $stats[$key]['fail']++;
    }
    $record = ['time' => date('H:i:s'), 'api' => $apiType, 'status' => $status];
    if ($taskId !== '') $record['task'] = $taskId;
    $stats[$key]['records'][] = $record;
    if (count($stats[$key]['records']) > $MAX_STAT_RECORDS_PER_DEVICE) {
        $stats[$key]['records'] = array_slice($stats[$key]['records'], -$MAX_STAT_RECORDS_PER_DEVICE);
    }

    atomicWrite($file, json_encode($stats, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
}

function recordFingerprintEnvEvent(string $dir, array $input): array {
    $event = trim((string)($input['event'] ?? ''));
    if (!in_array($event, ['generate', 'write'], true)) {
        return ['ok' => false, 'msg' => '未知指纹事件，仅支持 generate/write'];
    }

    $date = date('Y-m-d');
    $file = getStatsFile($dir, $date);
    $stats = readDayStats($dir, $date);
    $fp = fingerprintInfoFromInput($input);
    $key = $fp['key'];
    $accountRemark = displayAccountRemark((int)($input['api_type'] ?? 0), $fp['username'], $fp['group_id']);

    if (!isset($stats[$key])) {
        $stats[$key] = [
            'fingerprint_key' => $fp['fingerprint_key'],
            'fingerprint_id' => $fp['fingerprint_id'],
            'fingerprint_name' => $fp['fingerprint_name'],
            'username' => $fp['username'],
            'account_remark' => $accountRemark,
            'group_id' => $fp['group_id'],
            'device_id' => $fp['device_id'],
            'total' => 0,
            'generate' => 0,
            'write' => 0,
            'records' => [],
        ];
    }

    if (isset($stats[$key]['use']) && !isset($stats[$key]['write'])) {
        $stats[$key]['write'] = (int)$stats[$key]['use'];
        unset($stats[$key]['use']);
    }

    $stats[$key]['fingerprint_key'] = $fp['fingerprint_key'];
    $stats[$key]['fingerprint_id'] = $fp['fingerprint_id'];
    $stats[$key]['fingerprint_name'] = $fp['fingerprint_name'];
    $stats[$key]['username'] = $fp['username'];
    if ($accountRemark !== '') $stats[$key]['account_remark'] = $accountRemark;
    $stats[$key]['group_id'] = $fp['group_id'];
    $stats[$key]['device_id'] = $fp['device_id'];
    $stats[$key]['last_seen'] = date('Y-m-d H:i:s');
    $stats[$key]['total']++;
    $stats[$key][$event] = (int)($stats[$key][$event] ?? 0) + 1;
    $stats[$key]['records'][] = ['time' => date('H:i:s'), 'event' => $event];
    if (count($stats[$key]['records']) > 200) {
        $stats[$key]['records'] = array_slice($stats[$key]['records'], -200);
    }

    atomicWrite($file, json_encode($stats, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    return ['ok' => true, 'msg' => 'ok'];
}

function getStatsDateList(string $dir, int $limit = 30): array {
    if (!is_dir($dir)) return [];
    $files = glob("$dir/*.json");
    if (!is_array($files)) return [];
    $dates = [];
    foreach ($files as $f) {
        $dates[] = basename($f, '.json');
    }
    rsort($dates);
    return array_slice($dates, 0, $limit);
}

function cachePathSummary(string $path, string $label, bool $isDir = false): array {
    $files = 0;
    $bytes = 0;
    if ($isDir) {
        if (is_dir($path)) {
            foreach ((glob(rtrim($path, '/\\') . '/*') ?: []) as $item) {
                if (is_file($item)) {
                    $files++;
                    $bytes += (int)@filesize($item);
                }
            }
        }
    } else {
        if (is_file($path)) {
            $files = 1;
            $bytes = (int)@filesize($path);
        }
    }
    return [
        'label' => $label,
        'path' => $path,
        'files' => $files,
        'bytes' => $bytes,
    ];
}

function cacheOverview(): array {
    global $LOG_FILE, $STATS_DIR, $FP_ENV_STATS_DIR, $API1_TOKEN_FILE, $API1_TOKEN_MAP_FILE, $DEVICE_FILE;
    return [
        cachePathSummary($LOG_FILE, '转发日志', false),
        cachePathSummary(__DIR__ . '/decrypt_dumps', '解密数据缓存', true),
        cachePathSummary(__DIR__ . '/upload_dumps', '上传详情缓存', true),
        cachePathSummary($STATS_DIR, '数量统计缓存', true),
        cachePathSummary($FP_ENV_STATS_DIR, '指纹统计缓存', true),
        cachePathSummary($DEVICE_FILE, '设备状态缓存', false),
        cachePathSummary($API1_TOKEN_FILE, '接口1 token缓存', false),
        cachePathSummary($API1_TOKEN_MAP_FILE, 'token映射缓存', false),
    ];
}

function jsonMonitorFilePurpose(string $name): array {
    $map = [
        '.decoded_extension_accounts.json' => ['label' => '插件用户账号、token、任务账号池', 'category' => '插件账号', 'risk' => '高敏感'],
        '.decoded_extension_state.json' => ['label' => '插件任务轮询位置、任务租约、账号绑定', 'category' => '任务状态', 'risk' => '敏感'],
        'decoded_extension_tasks.json' => ['label' => '服务端本地预取任务队列', 'category' => '任务队列', 'risk' => '敏感'],
        'decoded_extension_submits.jsonl' => ['label' => '插件任务提交日志', 'category' => '提交日志', 'risk' => '敏感'],
        'decrypt_proxy_logs.jsonl' => ['label' => '代理转发总日志', 'category' => '日志', 'risk' => '敏感'],
        'device_controls.json' => ['label' => '设备心跳、在线状态、禁用控制', 'category' => '设备权限', 'risk' => '敏感'],
        'api1_allowed_accounts.json' => ['label' => '聚星账号白名单和备注', 'category' => '账号白名单', 'risk' => '普通'],
        'api1_token.json' => ['label' => '默认接口1 token缓存', 'category' => 'Token缓存', 'risk' => '高敏感'],
        'api1_token_map.json' => ['label' => 'token到用户名映射缓存', 'category' => 'Token缓存', 'risk' => '敏感'],
        'api2_number_remarks.json' => ['label' => '调速编号备注', 'category' => '备注', 'risk' => '普通'],
        'app_update.json' => ['label' => 'App在线更新配置', 'category' => '更新', 'risk' => '普通'],
        'version_controls.json' => ['label' => '版本停用和接口2编号范围', 'category' => '版本控制', 'risk' => '普通'],
        'plugin_update.json' => ['label' => '浏览器插件更新配置和下载地址', 'category' => '插件更新', 'risk' => '普通'],
        'config.json' => ['label' => '浏览器插件本地配置样例', 'category' => '插件配置', 'risk' => '敏感'],
        'manifest.json' => ['label' => '浏览器插件清单', 'category' => '插件源码', 'risk' => '普通'],
        'rules.json' => ['label' => '插件规则配置', 'category' => '插件源码', 'risk' => '普通'],
    ];
    if (isset($map[$name])) return $map[$name];
    if (preg_match('/^decoded_extension_tasks_.+\.json$/', $name)) {
        return ['label' => '单个插件用户的本地预取任务队列', 'category' => '任务队列', 'risk' => '敏感'];
    }
    if (preg_match('/^\.decoded_extension_state_.+\.json$/', $name)) {
        return ['label' => '单个插件用户的轮询状态和任务租约', 'category' => '任务状态', 'risk' => '敏感'];
    }
    if (preg_match('/^api1_token_decoded_[a-f0-9]+\.json$/', $name)) {
        return ['label' => '插件任务账号独立token缓存', 'category' => 'Token缓存', 'risk' => '高敏感'];
    }
    if (preg_match('/\.jsonl$/i', $name)) return ['label' => 'JSON Lines日志文件', 'category' => '日志', 'risk' => '敏感'];
    return ['label' => '未标注JSON数据文件', 'category' => '其他', 'risk' => '未知'];
}

function jsonMonitorFormatBytes(int $bytes): string {
    $units = ['B', 'KB', 'MB', 'GB'];
    $value = max(0, $bytes);
    $idx = 0;
    while ($value >= 1024 && $idx < count($units) - 1) {
        $value /= 1024;
        $idx++;
    }
    return ($idx === 0 ? (string)$value : number_format($value, 2)) . ' ' . $units[$idx];
}

function jsonMonitorMask($value) {
    if (is_array($value)) {
        $out = [];
        foreach ($value as $key => $item) {
            $keyText = strtolower((string)$key);
            if (preg_match('/password|passwd|token|auth|secret|bearer|hash/', $keyText)) {
                $text = is_scalar($item) ? (string)$item : json_encode($item, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                $out[$key] = $text === '' ? '' : (substr($text, 0, 4) . '***' . substr($text, -4));
            } else {
                $out[$key] = jsonMonitorMask($item);
            }
        }
        return $out;
    }
    return $value;
}

function jsonMonitorAnalyzeFile(string $path): array {
    $name = basename($path);
    $size = is_file($path) ? (int)@filesize($path) : 0;
    $info = jsonMonitorFilePurpose($name);
    $summary = ['records' => 0, 'top_keys' => [], 'updated_at' => '', 'preview' => null, 'parse_ok' => null, 'parse_error' => ''];

    if (preg_match('/\.jsonl$/i', $name)) {
        $fh = @fopen($path, 'r');
        $preview = [];
        if ($fh) {
            while (($line = fgets($fh)) !== false) {
                $line = trim($line);
                if ($line === '') continue;
                $summary['records']++;
                if (count($preview) < 3) {
                    $decoded = json_decode($line, true);
                    $preview[] = is_array($decoded) ? jsonMonitorMask($decoded) : substr($line, 0, 500);
                }
            }
            fclose($fh);
        }
        $summary['parse_ok'] = true;
        $summary['preview'] = $preview;
        return $summary + $info;
    }

    if ($size > 5 * 1024 * 1024) {
        $summary['preview'] = '文件较大，已跳过预览';
        return $summary + $info;
    }
    $raw = is_file($path) ? (string)@file_get_contents($path) : '';
    if (trim($raw) === '') {
        $summary['parse_ok'] = true;
        return $summary + $info;
    }
    $json = json_decode($raw, true);
    if (!is_array($json)) {
        $summary['parse_ok'] = false;
        $summary['parse_error'] = json_last_error_msg();
        $summary['preview'] = substr($raw, 0, 500);
        return $summary + $info;
    }

    $summary['parse_ok'] = true;
    $summary['top_keys'] = array_slice(array_map('strval', array_keys($json)), 0, 12);
    $summary['updated_at'] = (string)($json['updated_at'] ?? $json['updatedAt'] ?? '');
    if (isset($json['accounts']) && is_array($json['accounts'])) $summary['records'] = count($json['accounts']);
    elseif (isset($json['tasks']) && is_array($json['tasks'])) $summary['records'] = count($json['tasks']);
    elseif (isset($json['leases']) && is_array($json['leases'])) $summary['records'] = count($json['leases']);
    elseif (isset($json['devices']) && is_array($json['devices'])) $summary['records'] = count($json['devices']);
    else $summary['records'] = count($json);
    $preview = $json;
    if (isset($preview['accounts']) && is_array($preview['accounts'])) $preview['accounts'] = array_slice($preview['accounts'], 0, 5);
    if (isset($preview['tasks']) && is_array($preview['tasks'])) $preview['tasks'] = array_slice($preview['tasks'], 0, 5);
    if (isset($preview['leases']) && is_array($preview['leases'])) $preview['leases'] = array_slice($preview['leases'], 0, 5, true);
    if (isset($preview['devices']) && is_array($preview['devices'])) $preview['devices'] = array_slice($preview['devices'], 0, 5, true);
    $summary['preview'] = jsonMonitorMask($preview);
    return $summary + $info;
}

function jsonMonitorOverview(): array {
    $files = [];
    foreach ((scandir(__DIR__) ?: []) as $name) {
        if ($name === '.' || $name === '..') continue;
        if (!preg_match('/\.jsonl?$/i', $name)) continue;
        $path = __DIR__ . '/' . $name;
        if (!is_file($path)) continue;
        $analysis = jsonMonitorAnalyzeFile($path);
        $risk = (string)($analysis['risk'] ?? '');
        $riskLevel = $risk === '高敏感' ? 'high' : ($risk === '敏感' ? 'sensitive' : ($risk === '普通' ? 'normal' : 'unknown'));
        $files[] = [
            'name' => $name,
            'path' => $path,
            'bytes' => (int)@filesize($path),
            'size_text' => jsonMonitorFormatBytes((int)@filesize($path)),
            'mtime' => (int)@filemtime($path),
            'mtime_text' => date('Y-m-d H:i:s', (int)@filemtime($path)),
            'writable' => is_writable($path),
            'risk_level' => $riskLevel,
        ] + $analysis;
    }
    usort($files, fn($a, $b) => ((int)$b['mtime']) <=> ((int)$a['mtime']));
    return $files;
}

function cleanupJsonDir(string $dir, bool $deleteAll = false, int $keepLatest = 0, int $olderThanDays = 0): array {
    $result = ['path' => $dir, 'deleted_files' => 0, 'freed_bytes' => 0];
    if (!is_dir($dir)) return $result;
    $files = glob(rtrim($dir, '/\\') . '/*.json') ?: [];
    if (!$files) return $result;
    usort($files, fn($a, $b) => (@filemtime($b) ?: 0) <=> (@filemtime($a) ?: 0));
    $cutoff = $olderThanDays > 0 ? (time() - $olderThanDays * 86400) : 0;
    foreach ($files as $idx => $file) {
        $delete = $deleteAll;
        if (!$delete && $keepLatest > 0 && $idx >= $keepLatest) $delete = true;
        if (!$delete && $cutoff > 0 && (@filemtime($file) ?: 0) < $cutoff) $delete = true;
        if (!$delete) continue;
        $size = (int)@filesize($file);
        if (@unlink($file)) {
            $result['deleted_files']++;
            $result['freed_bytes'] += $size;
        }
    }
    return $result;
}

function cleanupLogFile(string $file): array {
    $result = ['path' => $file, 'deleted_files' => 0, 'freed_bytes' => 0];
    if (!is_file($file)) return $result;
    $size = (int)@filesize($file);
    if (@unlink($file)) {
        $result['deleted_files'] = 1;
        $result['freed_bytes'] = $size;
    }
    return $result;
}

function pruneDeviceCache(string $file, int $retentionDays): array {
    $result = ['path' => $file, 'deleted_files' => 0, 'freed_bytes' => 0];
    if (!is_file($file)) return $result;
    $devices = readDeviceControls($file);
    if (!is_array($devices) || !$devices) return $result;
    $before = count($devices);
    $cutoff = time() - max(1, $retentionDays) * 86400;
    foreach ($devices as $key => $device) {
        $lastSeen = strtotime((string)($device['last_seen'] ?? '')) ?: 0;
        if ($lastSeen > 0 && $lastSeen < $cutoff) {
            unset($devices[$key]);
        }
    }
    $after = count($devices);
    if ($after === $before) return $result;
    $oldSize = (int)@filesize($file);
    saveDeviceControls($file, $devices);
    $newSize = (int)@filesize($file);
    $result['deleted_files'] = $before - $after;
    $result['freed_bytes'] = max(0, $oldSize - $newSize);
    return $result;
}

function pruneTokenCaches(string $tokenFile, string $tokenMapFile): array {
    $result = ['deleted_files' => 0, 'freed_bytes' => 0];
    $now = time();

    if (is_file($tokenFile)) {
        $raw = json_decode((string)@file_get_contents($tokenFile), true);
        $exp = is_array($raw) ? (int)($raw['expires_at'] ?? 0) : 0;
        if ($exp > 0 && $exp < ($now - 300)) {
            $size = (int)@filesize($tokenFile);
            if (@unlink($tokenFile)) {
                $result['deleted_files']++;
                $result['freed_bytes'] += $size;
            }
        }
    }

    if (is_file($tokenMapFile)) {
        $map = json_decode((string)@file_get_contents($tokenMapFile), true);
        if (is_array($map)) {
            $oldSize = (int)@filesize($tokenMapFile);
            foreach ($map as $key => $entry) {
                $exp = is_array($entry) ? (int)($entry['expires_at'] ?? 0) : 0;
                if ($exp > 0 && $exp < ($now - 300)) unset($map[$key]);
            }
            atomicWrite($tokenMapFile, json_encode($map, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            $newSize = (int)@filesize($tokenMapFile);
            $result['freed_bytes'] += max(0, $oldSize - $newSize);
        }
    }
    return $result;
}

function runCacheCleanup(string $mode = 'unused'): array {
    global $LOG_FILE, $STATS_DIR, $FP_ENV_STATS_DIR, $API1_TOKEN_FILE, $API1_TOKEN_MAP_FILE, $DEVICE_FILE;
    global $CACHE_DEVICE_RETENTION_DAYS, $CACHE_FP_STATS_RETENTION_DAYS, $CACHE_DECRYPT_DUMP_KEEP;

    $mode = $mode === 'deep' ? 'deep' : 'unused';
    $steps = [];

    $steps[] = ['label' => '上传详情缓存', 'result' => cleanupJsonDir(__DIR__ . '/upload_dumps', true)];
    $steps[] = ['label' => '数量统计缓存', 'result' => cleanupJsonDir($STATS_DIR, true)];
    $steps[] = ['label' => '解密数据缓存', 'result' => $mode === 'deep'
        ? cleanupJsonDir(__DIR__ . '/decrypt_dumps', true)
        : cleanupJsonDir(__DIR__ . '/decrypt_dumps', false, $CACHE_DECRYPT_DUMP_KEEP)];
    $steps[] = ['label' => '指纹统计缓存', 'result' => $mode === 'deep'
        ? cleanupJsonDir($FP_ENV_STATS_DIR, true)
        : cleanupJsonDir($FP_ENV_STATS_DIR, false, 0, $CACHE_FP_STATS_RETENTION_DAYS)];
    $steps[] = ['label' => '设备状态缓存', 'result' => pruneDeviceCache($DEVICE_FILE, $CACHE_DEVICE_RETENTION_DAYS)];
    $steps[] = ['label' => 'token缓存', 'result' => pruneTokenCaches($API1_TOKEN_FILE, $API1_TOKEN_MAP_FILE)];
    if ($mode === 'deep') {
        $steps[] = ['label' => '转发日志', 'result' => cleanupLogFile($LOG_FILE)];
    }

    $deletedFiles = 0;
    $freedBytes = 0;
    foreach ($steps as &$step) {
        $deletedFiles += (int)($step['result']['deleted_files'] ?? 0);
        $freedBytes += (int)($step['result']['freed_bytes'] ?? 0);
    }
    unset($step);

    return [
        'ok' => true,
        'mode' => $mode,
        'deleted_files' => $deletedFiles,
        'freed_bytes' => $freedBytes,
        'steps' => $steps,
        'overview' => cacheOverview(),
        'msg' => $mode === 'deep' ? '深度清理完成' : '缓存清理完成',
    ];
}

// ===== 前端页面 =====
function sqliteMonitorFileInfo(string $path): array {
    return [
        'name' => basename($path),
        'path' => $path,
        'exists' => is_file($path),
        'bytes' => is_file($path) ? (int)@filesize($path) : 0,
        'size_text' => is_file($path) ? jsonMonitorFormatBytes((int)@filesize($path)) : '0 B',
        'updated_at' => is_file($path) ? date('Y-m-d H:i:s', (int)@filemtime($path)) : '',
    ];
}

function sqliteMonitorOverview(): array {
    global $DECODED_EXTENSION_SQLITE_FILE, $DECODED_EXTENSION_QUEUE_TTL, $DECODED_EXTENSION_LEASE_TTL;

    $files = [
        sqliteMonitorFileInfo($DECODED_EXTENSION_SQLITE_FILE),
        sqliteMonitorFileInfo($DECODED_EXTENSION_SQLITE_FILE . '-wal'),
        sqliteMonitorFileInfo($DECODED_EXTENSION_SQLITE_FILE . '-shm'),
    ];
    $pdo = decodedExtensionDb();
    if (!$pdo instanceof PDO) {
        return [
            'ok' => false,
            'msg' => 'PDO SQLite unavailable',
            'files' => $files,
            'tables' => [],
            'metrics' => [],
            'recent_queue' => [],
            'recent_leases' => [],
            'lease_groups' => [],
        ];
    }

    $now = time();
    $metrics = [];
    foreach (['journal_mode', 'page_count', 'page_size', 'freelist_count', 'quick_check'] as $pragma) {
        try {
            $metrics[$pragma] = $pdo->query('PRAGMA ' . $pragma)->fetchColumn();
        } catch (\Throwable $_) {
            $metrics[$pragma] = '';
        }
    }
    $metrics['queue_ttl_seconds'] = $DECODED_EXTENSION_QUEUE_TTL;
    $metrics['lease_ttl_seconds'] = $DECODED_EXTENSION_LEASE_TTL;

    $tables = [];
    foreach (['task_queue', 'task_leases'] as $table) {
        try {
            $tables[$table] = ['rows' => (int)$pdo->query('SELECT COUNT(*) FROM ' . $table)->fetchColumn()];
        } catch (\Throwable $e) {
            $tables[$table] = ['rows' => 0, 'error' => $e->getMessage()];
        }
    }
    try {
        $tables['task_queue']['expired_rows'] = $DECODED_EXTENSION_QUEUE_TTL > 0
            ? (int)$pdo->query('SELECT COUNT(*) FROM task_queue WHERE queued_ts > 0 AND queued_ts < ' . (int)($now - $DECODED_EXTENSION_QUEUE_TTL))->fetchColumn()
            : 0;
    } catch (\Throwable $_) {}
    try {
        $tables['task_leases']['expired_rows'] = $DECODED_EXTENSION_LEASE_TTL > 0
            ? (int)$pdo->query('SELECT COUNT(*) FROM task_leases WHERE created_ts > 0 AND created_ts < ' . (int)($now - $DECODED_EXTENSION_LEASE_TTL))->fetchColumn()
            : 0;
    } catch (\Throwable $_) {}

    $recentQueue = [];
    try {
        $recentQueue = $pdo->query("
            SELECT id, account_id, runtime_scope, task_key, queued_ts, queued_at
            FROM task_queue
            ORDER BY id DESC
            LIMIT 20
        ")->fetchAll();
    } catch (\Throwable $_) {}

    $recentLeases = [];
    try {
        $recentLeases = $pdo->query("
            SELECT id, account_id, runtime_scope, task_id, task_url,
                   task_account_key, task_account_username,
                   api1_token_hash, api1_token_expires_at, created_ts, created_at
            FROM task_leases
            ORDER BY created_ts DESC, id DESC
            LIMIT 20
        ")->fetchAll();
    } catch (\Throwable $_) {}

    $leaseGroups = [];
    try {
        $leaseGroups = $pdo->query("
            SELECT account_id, runtime_scope, COUNT(*) AS lease_count, MAX(created_ts) AS latest_ts
            FROM task_leases
            GROUP BY account_id, runtime_scope
            ORDER BY latest_ts DESC
            LIMIT 50
        ")->fetchAll();
    } catch (\Throwable $_) {}

    foreach ($recentQueue as &$row) {
        $row['age_seconds'] = max(0, $now - (int)($row['queued_ts'] ?? 0));
    }
    unset($row);
    foreach ($recentLeases as &$row) {
        $row['age_seconds'] = max(0, $now - (int)($row['created_ts'] ?? 0));
        $exp = (int)($row['api1_token_expires_at'] ?? 0);
        $row['api1_token_expires_at_text'] = $exp > 0 ? date('Y-m-d H:i:s', $exp) : '';
    }
    unset($row);
    foreach ($leaseGroups as &$row) {
        $latest = (int)($row['latest_ts'] ?? 0);
        $row['latest_at'] = $latest > 0 ? date('Y-m-d H:i:s', $latest) : '';
    }
    unset($row);

    return [
        'ok' => true,
        'generated_at' => date('Y-m-d H:i:s'),
        'files' => $files,
        'tables' => $tables,
        'metrics' => $metrics,
        'recent_queue' => $recentQueue,
        'recent_leases' => $recentLeases,
        'lease_groups' => $leaseGroups,
    ];
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' && decodedExtensionIsParallelControlPrettyRoute()) {
    renderParallelControlPage();
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['act'])) {
    $act = $_GET['act'];

    if ($act === 'view') {
        renderPage();
        exit;
    }

    if ($act === 'h5') {
        $_GET['h5_mode'] = '1';
        renderPage();
        exit;
    }

    if ($act === 'change_password_page') {
        renderPasswordPage();
        exit;
    }

    if ($act === 'parallel_control') {
        renderParallelControlPage();
        exit;
    }

    if ($act === 'parallel_control_info') {
        jsonResp(decodedExtensionParallelControlInfo((string)($_GET['t'] ?? '')));
    }

    if ($act === 'parallel_control_daily_stats') {
        jsonResp(decodedExtensionParallelControlDailyStats(
            (string)($_GET['t'] ?? ''),
            (string)($_GET['date'] ?? date('Y-m-d')),
            true
        ));
    }

    if ($act === 'parallel_control_live_stats') {
        jsonResp(decodedExtensionParallelControlLiveStats((string)($_GET['t'] ?? '')));
    }

    if ($act === 'check_update') {
        $currentCode = (int)($_GET['version_code'] ?? 0);
        $resp = buildUpdateResponse($UPDATE_FILE, $currentCode);
        $vCheck = checkVersionBlocked($VERSION_CTRL_FILE, $currentCode);
        $resp['blocked'] = !empty($vCheck['blocked']);
        $resp['blocked_msg'] = $vCheck['message'] ?? '';
        if ($resp['blocked']) $resp['force'] = true;
        jsonResp($resp);
    }

    if ($act === 'check_plugin_update') {
        $currentVersion = trim((string)($_GET['version'] ?? $_GET['current_version'] ?? ''));
        $currentCode = (int)($_GET['version_code'] ?? $_GET['current_code'] ?? 0);
        jsonResp(buildPluginUpdateResponse($PLUGIN_UPDATE_FILE, $currentVersion, $currentCode));
    }

    $key = getAuthKeyFromRequest();
    if (!verifyAuthKey($key)) jsonResp(['ok' => false, 'msg' => '密码错误']);

    if ($act === 'logs') {
        $limit = min(200, max(1, (int)($_GET['limit'] ?? 50)));
        $logs = readLogs($LOG_FILE, $MAX_LOGS);
        $logs = array_values(array_filter($logs, function ($log) {
            $source = strtolower(trim((string)($log['source'] ?? '')));
            $status = strtolower(trim((string)($log['status'] ?? '')));
            if (in_array($source, ['web_take', 'api1_take', 'ctrl_take', 'decoded_extension_task', 'decoded_extension_task_local'], true)) {
                return false;
            }
            if ($source === 'decoded_extension_submit' && $status === 'client_task_failed') {
                return false;
            }
            return true;
        }));
        $logs = array_slice($logs, 0, $limit);
        foreach ($logs as &$log) {
            if (!empty($log['username'])) {
                $u = (string)$log['username'];
                $remark = displayAccountRemark((int)($log['api_type'] ?? 0), $u, (string)($log['group_id'] ?? ''));
                $source = strtolower(trim((string)($log['source'] ?? '')));
                if ($remark === '' && strpos($source, 'decoded_extension_') === 0) {
                    $remark = displayDecodedExtensionAccountRemark($u);
                }
                $log['account_remark'] = $remark !== '' ? $remark : ($log['account_remark'] ?? '');
            }
            $clientLabel = resolveClientLabel($log);
            if ($clientLabel !== '') {
                $log['client_label'] = $clientLabel;
            } elseif (($log['client_label'] ?? '') !== '') {
                unset($log['client_label']);
            }
        }
        unset($log);
        jsonResp(['ok' => true, 'data' => $logs]);
    }

    if ($act === 'devices') {
        $devices = array_values(readDeviceControls($DEVICE_FILE));
        foreach ($devices as &$device) {
            $u = (string)($device['username'] ?? '');
            $remark = displayAccountRemark((int)($device['api_type'] ?? 0), $u, (string)($device['group_id'] ?? ''));
            if ($remark === '') $remark = displayDecodedExtensionAccountRemark($u);
            $device['account_remark'] = $remark ?: ($device['account_remark'] ?? '');
        }
        unset($device);
        $now = time();
        $onlineThreshold = 120;
        $onlineCount = 0;
        foreach ($devices as &$device) {
            $lastSeen = strtotime($device['last_seen'] ?? '') ?: 0;
            $device['online'] = $lastSeen && ($now - $lastSeen) <= $onlineThreshold;
            if ($device['online']) $onlineCount++;
        }
        unset($device);
        $devices = array_filter($devices, function($d) use ($now, $onlineThreshold) {
            $lastSeen = strtotime($d['last_seen'] ?? '');
            return !empty($d['disabled']) || ($lastSeen && ($now - $lastSeen) <= $onlineThreshold);
        });
        $devices = array_values($devices);
        usort($devices, fn($a, $b) => strcmp((string)($b['last_seen'] ?? ''), (string)($a['last_seen'] ?? '')));
        jsonResp(['ok' => true, 'data' => $devices, 'online_count' => $onlineCount]);
    }

    if ($act === 'device_toggle') {
        $deviceKey = (string)($_GET['device_key'] ?? '');
        $disabled = (int)($_GET['disabled'] ?? 0) === 1;
        $reason = trim((string)($_GET['reason'] ?? ''));
        jsonResp(updateDeviceControl($DEVICE_FILE, $deviceKey, $disabled, $reason));
    }



    if ($act === 'android_device_command') {
        $deviceKey = (string)($_GET['device_key'] ?? '');
        $command = trim((string)($_GET['command'] ?? 'run'));
        $interval = (int)($_GET['interval'] ?? 0);
        jsonResp(updateAndroidDeviceCommand($DEVICE_FILE, $deviceKey, $command, $interval));
    }

    if ($act === 'device_toggle_user') {
        $username = trim((string)($_GET['username'] ?? ''));
        $disabled = (int)($_GET['disabled'] ?? 0) === 1;
        $reason = trim((string)($_GET['reason'] ?? ''));
        if ($username === '') jsonResp(['ok' => false, 'msg' => '缺少用户名']);
        $devices = readDeviceControls($DEVICE_FILE);
        $count = 0;
        foreach ($devices as $key => &$dev) {
            if (($dev['username'] ?? '') === $username) {
                $dev['disabled'] = $disabled;
                $dev['disabled_reason'] = $disabled ? $reason : '';
                $dev['updated_at'] = date('Y-m-d H:i:s');
                $count++;
            }
        }
        unset($dev);
        saveDeviceControls($DEVICE_FILE, $devices);
        jsonResp(['ok' => true, 'msg' => ($disabled ? '已禁用' : '已启用') . " {$username} 的 {$count} 个设备"]);
    }

    if ($act === 'update_config') {
        jsonResp(['ok' => true, 'data' => readUpdateConfig($UPDATE_FILE)]);
    }

    if ($act === 'plugin_update_config') {
        jsonResp(['ok' => true, 'data' => readPluginUpdateConfig($PLUGIN_UPDATE_FILE)]);
    }

    if ($act === 'save_update') {
        jsonResp(saveUpdateConfig($UPDATE_FILE, $_GET));
    }

    if ($act === 'version_controls') {
        jsonResp(['ok' => true, 'data' => readVersionControls($VERSION_CTRL_FILE)]);
    }

    if ($act === 'save_version_controls') {
        $input = [
            'min_version_code' => (int)($_GET['min_version_code'] ?? 0),
            'min_version_msg' => trim((string)($_GET['min_version_msg'] ?? '')),
            'api2_login_min' => (int)($_GET['api2_login_min'] ?? 0),
            'api2_login_max' => (int)($_GET['api2_login_max'] ?? 10000),
        ];
        $blockedJson = (string)($_GET['blocked_versions'] ?? '');
        if ($blockedJson !== '') {
            $parsed = json_decode($blockedJson, true);
            if (is_array($parsed)) $input['blocked_versions'] = $parsed;
        }
        jsonResp(saveVersionControls($VERSION_CTRL_FILE, $input));
    }

    if ($act === 'api1_accounts') {
        decodedExtensionSyncAllTaskAccountsToApi1Whitelist();
        jsonResp(['ok' => true, 'data' => readApi1AllowedAccounts($API1_ACCOUNTS_FILE)]);
    }

    if ($act === 'save_api1_accounts') {
        jsonResp(saveApi1AllowedAccounts($API1_ACCOUNTS_FILE, (string)($_GET['accounts'] ?? '')));
    }

    if ($act === 'decoded_ext_accounts') {
        $whitelistSync = decodedExtensionSyncAllTaskAccountsToApi1Whitelist();
        $accounts = decodedExtensionReadAccounts($DECODED_EXTENSION_ACCOUNTS_FILE);
        if ($accounts) $accounts = decodedExtensionSaveAccounts($accounts);
        jsonResp([
            'ok' => true,
            'data' => decodedExtensionPublicAccounts($accounts),
            'serverBaseUrl' => decodedExtensionGeneratedServerBaseUrl(),
            'whitelist_sync' => $whitelistSync,
        ]);
    }

    if ($act === 'decoded_ext_account_delete') {
        jsonResp(decodedExtensionAdminDeleteAccount(trim((string)($_GET['accountId'] ?? ''))));
    }

    if ($act === 'decoded_ext_account_toggle') {
        jsonResp(decodedExtensionAdminToggleAccount(trim((string)($_GET['accountId'] ?? '')), (int)($_GET['enabled'] ?? 1) === 1));
    }

    if ($act === 'decoded_ext_account_token') {
        jsonResp(decodedExtensionAdminResetToken(trim((string)($_GET['accountId'] ?? ''))));
    }

    if ($act === 'decoded_ext_account_parallel_token') {
        jsonResp(decodedExtensionAdminResetParallelControlToken(trim((string)($_GET['accountId'] ?? ''))));
    }

    if ($act === 'api2_numbers') {
        jsonResp(['ok' => true, 'data' => readApi1AllowedAccounts($API2_NUMBERS_FILE)]);
    }

    if ($act === 'save_api2_numbers') {
        jsonResp(saveApiAccounts($API2_NUMBERS_FILE, parseAccountLines((string)($_GET['accounts'] ?? ''))));
    }

    if ($act === 'stats') {
        $date = trim((string)($_GET['date'] ?? date('Y-m-d')));
        $stats = readDayStats($FP_ENV_STATS_DIR, $date);
        $summary = [];
        foreach ($stats as $key => $info) {
            $username = (string)($info['username'] ?? (string)$key);
            $accountRemark = (string)($info['account_remark'] ?? '');
            $dynamicRemark = displayAccountRemark((int)($info['api_type'] ?? 0), $username, (string)($info['group_id'] ?? ''));
            if ($dynamicRemark !== '') $accountRemark = $dynamicRemark;
            $summary[] = [
                'key' => (string)$key,
                'username' => $username,
                'account_remark' => $accountRemark,
                'group_id' => $info['group_id'] ?? '',
                'device_id' => $info['device_id'] ?? '',
                'fingerprint_key' => $info['fingerprint_key'] ?? '',
                'fingerprint_id' => $info['fingerprint_id'] ?? '',
                'fingerprint_name' => $info['fingerprint_name'] ?? '',
                'last_seen' => $info['last_seen'] ?? '',
                'total' => $info['total'] ?? 0,
                'generate' => $info['generate'] ?? 0,
                'write' => $info['write'] ?? $info['use'] ?? 0,
                'records' => $info['records'] ?? [],
            ];
        }
        usort($summary, fn($a, $b) => $b['total'] - $a['total']);
        jsonResp(['ok' => true, 'date' => $date, 'dates' => getStatsDateList($FP_ENV_STATS_DIR), 'data' => $summary]);
    }

    if ($act === 'submit_stats') {
        if (!$ENABLE_SUBMIT_STATS) {
            jsonResp(['ok' => false, 'msg' => '数量查看功能已停用']);
        }
        $date = trim((string)($_GET['date'] ?? date('Y-m-d')));
        $stats = readDayStats($STATS_DIR, $date);
        $byUser = [];
        foreach ($stats as $info) {
            $username = (string)($info['username'] ?? 'unknown');
            $groupId = (string)($info['group_id'] ?? '');
            if (!isset($byUser[$username])) {
                $byUser[$username] = [
                    'username' => $username, 'account_remark' => '',
                    'group_id' => $groupId,
                    'total' => 0, 'success' => 0, 'fail' => 0,
                    'api1_total' => 0, 'api1_success' => 0, 'api1_fail' => 0,
                    'api2_total' => 0, 'api2_success' => 0, 'api2_fail' => 0,
                ];
            }
            if ($groupId !== '') $byUser[$username]['group_id'] = $groupId;
            foreach (($info['records'] ?? []) as $rec) {
                $api = (int)($rec['api'] ?? 0);
                $isOk = ($rec['status'] ?? '') === 'success';
                if ($api === 1) {
                    $byUser[$username]['api1_total']++;
                    if ($isOk) $byUser[$username]['api1_success']++;
                    else $byUser[$username]['api1_fail']++;
                } elseif ($api === 2) {
                    $byUser[$username]['api2_total']++;
                    if ($isOk) $byUser[$username]['api2_success']++;
                    else $byUser[$username]['api2_fail']++;
                }
            }
            $byUser[$username]['total'] += (int)($info['total'] ?? 0);
            $byUser[$username]['success'] += (int)($info['success'] ?? 0);
            $byUser[$username]['fail'] += (int)($info['fail'] ?? 0);
        }
        foreach ($byUser as &$u) {
            $remark = displayAccountRemark((int)(($u['api2_total'] ?? 0) > 0 ? 2 : 1), $u['username'], (string)($u['group_id'] ?? ''));
            if ($remark !== '') $u['account_remark'] = $remark;
        }
        unset($u);
        $result = array_values($byUser);
        usort($result, fn($a, $b) => $b['success'] - $a['success']);
        jsonResp(['ok' => true, 'date' => $date, 'dates' => getStatsDateList($STATS_DIR), 'data' => $result]);
    }

    if ($act === 'cache_overview') {
        jsonResp(['ok' => true, 'data' => cacheOverview()]);
    }

    if ($act === 'json_monitor') {
        jsonResp(['ok' => true, 'data' => jsonMonitorOverview()]);
    }

    if ($act === 'sqlite_monitor') {
        jsonResp(['ok' => true, 'data' => sqliteMonitorOverview()]);
    }

    if ($act === 'cleanup_cache') {
        $mode = trim((string)($_GET['mode'] ?? 'unused'));
        jsonResp(runCacheCleanup($mode));
    }

    if ($act === 'clear_stats') {
        $date = trim((string)($_GET['date'] ?? date('Y-m-d')));
        $file = getStatsFile($FP_ENV_STATS_DIR, $date);
        if (is_file($file)) @unlink($file);
        jsonResp(['ok' => true, 'msg' => '统计已清除', 'date' => $date]);
    }

    if ($act === 'clear') {
        if (is_file($LOG_FILE)) @unlink($LOG_FILE);
        $dumpDir = __DIR__ . '/decrypt_dumps';
        if (is_dir($dumpDir)) { array_map('unlink', glob("$dumpDir/*.json")); }
        $uploadDumpDir = __DIR__ . '/upload_dumps';
        if (is_dir($uploadDumpDir)) { array_map('unlink', glob("$uploadDumpDir/*.json")); }
        if (is_dir($STATS_DIR)) { array_map('unlink', glob("$STATS_DIR/*.json")); }
        jsonResp(['ok' => true, 'msg' => '日志和数据已清空']);
    }

    // 查看解密后的完整数据
    if ($act === 'dump') {
        $id = $_GET['id'] ?? '';
        $dumpFile = __DIR__ . '/decrypt_dumps/' . basename($id) . '.json';
        if (!$id || !is_file($dumpFile)) jsonResp(['ok' => false, 'msg' => '数据不存在']);
        header('Content-Type: application/json; charset=utf-8');
        readfile($dumpFile);
        exit;
    }

    // 查看上传任务接口详情
    if ($act === 'upload') {
        if (!$ENABLE_UPLOAD_DETAIL_DUMPS) jsonResp(['ok' => false, 'msg' => '上传详情功能已停用']);
        $id = $_GET['id'] ?? '';
        $dumpFile = __DIR__ . '/upload_dumps/' . basename($id) . '.json';
        if (!$id || !is_file($dumpFile)) jsonResp(['ok' => false, 'msg' => '上传详情不存在']);
        header('Content-Type: application/json; charset=utf-8');
        $detail = json_decode((string)@file_get_contents($dumpFile), true);
        if (!is_array($detail)) jsonResp(['ok' => false, 'msg' => '上传详情格式异常']);
        if (($_GET['field'] ?? '') === 'response') {
            $response = $detail['response_json'] ?? null;
            if ($response === null && array_key_exists('response_raw', $detail)) {
                $decoded = json_decode((string)$detail['response_raw'], true);
                $response = (json_last_error() === JSON_ERROR_NONE) ? $decoded : (string)$detail['response_raw'];
            }
            echo json_encode([
                'time' => $detail['time'] ?? '',
                'api_type' => $detail['api_type'] ?? null,
                'target_url' => $detail['target_url'] ?? '',
                'http_code' => $detail['http_code'] ?? 0,
                'error' => $detail['error'] ?? '',
                'response' => $response,
            ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        } elseif (isset($_GET['full'])) {
            echo json_encode($detail, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        } else {
            echo json_encode($detail['request_body'] ?? $detail, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        }
        exit;
    }

    // 列出所有dump文件
    if ($act === 'dumps') {
        $dumpDir = __DIR__ . '/decrypt_dumps';
        $files = [];
        if (is_dir($dumpDir)) {
            foreach (glob("$dumpDir/*.json") as $f) {
                $files[] = ['id' => basename($f, '.json'), 'size' => filesize($f), 'time' => date('Y-m-d H:i:s', filemtime($f))];
            }
            usort($files, fn($a, $b) => strcmp($b['time'], $a['time']));
        }
        jsonResp(['ok' => true, 'data' => array_slice($files, 0, 20)]);
    }

    jsonResp(['ok' => false, 'msg' => '未知操作']);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['act'] ?? '') === 'upload_update') {
    $key = getAuthKeyFromRequest();
    if (!verifyAuthKey($key)) jsonResp(['ok' => false, 'msg' => '密码错误']);
    jsonResp(uploadUpdateApk($UPDATE_FILE, $APK_DIR, $_POST, $_FILES));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['act'] ?? '') === 'change_password') {
    $key = getAuthKeyFromRequest();
    if (!verifyAuthKey($key)) jsonResp(['ok' => false, 'msg' => '密码错误']);
    jsonResp(changeAuthPassword(
        (string)($_POST['current_password'] ?? ''),
        (string)($_POST['new_password'] ?? ''),
        (string)($_POST['confirm_password'] ?? '')
    ));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['act'] ?? '') === 'upload_plugin_update') {
    $key = getAuthKeyFromRequest();
    if (!verifyAuthKey($key)) jsonResp(['ok' => false, 'msg' => '密码错误']);
    jsonResp(uploadPluginUpdatePackage($PLUGIN_UPDATE_FILE, $PLUGIN_UPDATE_DIR, $_POST, $_FILES));
}

// ===== 代理转发逻辑 =====
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['act']) && strpos((string)$_GET['act'], 'decoded_ext_account_') === 0) {
    $key = getAuthKeyFromRequest();
    if (!verifyAuthKey($key)) jsonResp(['ok' => false, 'msg' => '瀵嗙爜閿欒']);
    $rawAdminBody = (string)file_get_contents('php://input');
    $adminInput = json_decode($rawAdminBody, true);
    if (!is_array($adminInput)) $adminInput = $_POST;
    $act = (string)$_GET['act'];
    if ($act === 'decoded_ext_account_save') {
        jsonResp(decodedExtensionAdminSaveAccount($adminInput));
    }
    if ($act === 'decoded_ext_account_batch') {
        jsonResp(decodedExtensionAdminBatchAccounts((string)($adminInput['batch'] ?? '')));
    }
    jsonResp(['ok' => false, 'msg' => 'unknown decoded extension account action']);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['act']) && (string)$_GET['act'] === 'parallel_control_save') {
    $rawControlBody = (string)file_get_contents('php://input');
    $controlInput = json_decode($rawControlBody, true);
    if (!is_array($controlInput)) $controlInput = $_POST;
    jsonResp(decodedExtensionParallelControlSave(
        (string)($_GET['t'] ?? $controlInput['t'] ?? ''),
        $controlInput['task_parallelism'] ?? $controlInput['parallelism'] ?? null
    ));
}

handleDecodedExtensionApi();

header('Content-Type: application/json; charset=utf-8');

$requestStart = microtime(true);
$stageMark = $requestStart;
$rawBody = file_get_contents('php://input');
if (!$rawBody) jsonResp(['ok' => false, 'msg' => '空请求体']);
$rawReadMs = durationMs($stageMark, microtime(true));

$stageMark = microtime(true);
$input = json_decode($rawBody, true);
if (!$input) jsonResp(['ok' => false, 'msg' => 'JSON解析失败']);
$input = normalizeWebPluginPayload($input);
$requestJsonMs = durationMs($stageMark, microtime(true));

$postAct = (string)($input['act'] ?? '');

if ($postAct === 'android_session_sync') {
    jsonResp(syncAndroidSession($ANDROID_SESSION_FILE, $DEVICE_FILE, $input));
}

if ($postAct === 'android_session_clear') {
    jsonResp(clearAndroidSession($ANDROID_SESSION_FILE, $DEVICE_FILE, $input));
}

if ($postAct === 'android_device_poll') {
    jsonResp(pollAndroidDevice($DEVICE_FILE, $ANDROID_SESSION_FILE, $input));
}

if ($postAct === 'android_task_take') {
    $takeStart = microtime(true);
    $username = trim((string)($input['username'] ?? '')) ?: 'android';
    $deviceCheck = checkDeviceAllowed($DEVICE_FILE, $input + ['username' => $username, 'api_type' => 1, 'platform' => 'android']);
    if (empty($deviceCheck['allowed'])) jsonResp(['ok' => false, 'success' => false, 'code' => '403', 'msg' => $deviceCheck['msg'] ?? 'device disabled']);

    $tokenInfo = getApi1Token($API1_AUTH, $API1_TOKEN_FILE);
    if (empty($tokenInfo['ok']) || empty($tokenInfo['token'])) {
        jsonResp(['ok' => false, 'success' => false, 'code' => '502', 'msg' => (string)($tokenInfo['msg'] ?? 'task server login failed')]);
    }
    $stageMark = microtime(true);
    $result = forwardGetToServer($API1_TAKE_URL, ['Authorization: Bearer ' . (string)$tokenInfo['token']]);
    $serverResp = json_decode((string)$result['response'], true);
    $forwardMs = durationMs($stageMark, microtime(true));
    $takeOk = is_array($serverResp) && (string)($serverResp['code'] ?? '') === '200' && !empty($serverResp['data']['taskUrl']);
    appendLog($LOG_FILE, [
        'time' => date('Y-m-d H:i:s'),
        'api_type' => 1,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
        'username' => $username,
        'device_id' => $input['device_id'] ?? '',
        'fingerprint_key' => $input['fingerprint_key'] ?? '',
        'status' => $result['error'] ? 'forward_fail' : ($takeOk ? 'success' : 'task_server_error'),
        'source' => 'android_managed_take',
        'forward_url' => $API1_TAKE_URL,
        'response' => compactLogResponse($serverResp ?? $result['response'], $MAX_LOG_RESPONSE_BYTES),
        'timing_ms' => ['raw_read' => $rawReadMs, 'request_json' => $requestJsonMs, 'forward' => $forwardMs, 'total' => elapsedMs($takeStart)],
    ], $MAX_LOGS);
    if ($result['error']) jsonResp(['ok' => false, 'success' => false, 'code' => '500', 'msg' => 'take forward failed: ' . $result['error']]);
    if (is_array($serverResp)) {
        $serverResp['_proxy'] = ['source' => 'android_managed_take', 'token_source' => !empty($tokenInfo['cached']) ? 'cache' : 'login'];
        jsonResp($serverResp);
    }
    jsonResp(['ok' => false, 'success' => false, 'code' => '500', 'msg' => 'task server abnormal', 'raw' => $result['response']]);
}

if ($postAct === 'api1_login') {
    $username = trim((string)($input['username'] ?? ''));
    $password = (string)($input['password'] ?? '');
    if ($username === '' || $password === '') {
        jsonResp(['code' => '400', 'data' => null, 'msg' => '账号或密码为空']);
    }

    decodedExtensionSyncAllTaskAccountsToApi1Whitelist();
    $allowed = readApi1AllowedAccounts($API1_ACCOUNTS_FILE);
    if (!in_array($username, accountNames($allowed), true)) {
        appendLog($LOG_FILE, [
            'time' => date('Y-m-d H:i:s'),
            'api_type' => 1,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'username' => $username,
            'status' => 'login_rejected',
            'error' => '账号未在后台聚星白名单',
        ], $MAX_LOGS);
        jsonResp(['code' => '403', 'data' => null, 'msg' => '账号未授权，请联系管理员']);
    }

    $deviceCheck = checkDeviceAllowed($DEVICE_FILE, $input + ['api_type' => 1]);
    if (empty($deviceCheck['allowed'])) {
        appendLog($LOG_FILE, [
            'time' => date('Y-m-d H:i:s'),
            'api_type' => 1,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'username' => $username,
            'device_id' => $input['device_id'] ?? '',
            'fingerprint_key' => $input['fingerprint_key'] ?? '',
            'status' => 'device_disabled',
                'source' => resolveLogSource($input, 'api1_login', 'web_login', 'ctrl_login'),
            'error' => $deviceCheck['msg'] ?? '设备已被禁用',
        ], $MAX_LOGS);
        jsonResp(['code' => '403', 'data' => null, 'msg' => $deviceCheck['msg'] ?? '设备已被禁用']);
    }

    $loginResult = api1LoginWithPassword($API1_AUTH['login_url'], $username, $password);
    if (!empty($loginResult['error'])) {
        jsonResp(['code' => '500', 'data' => null, 'msg' => '登录转发失败: ' . $loginResult['error']]);
    }
    $loginJson = json_decode((string)$loginResult['response'], true);
    $loginToken = is_array($loginJson) ? trim((string)($loginJson['data']['token'] ?? '')) : '';
    if ($loginToken !== '') {
        cacheApi1TokenUsername($loginToken, $username, jwtExp($loginToken));
    }
    header('Content-Type: application/json; charset=utf-8');
    echo (string)$loginResult['response'];
    exit;
}

if ($postAct === 'api2_login') {
    global $API2_FIXED_USERNAME, $VERSION_CTRL_FILE;
    $username = trim((string)($input['username'] ?? ''));
    $password = (string)($input['password'] ?? '');
    if ($username === '' || $password === '') {
        jsonResp(['code' => '400', 'data' => null, 'msg' => '账号或密码为空']);
    }
    if ($username !== $API2_FIXED_USERNAME) {
        jsonResp(['code' => '403', 'data' => null, 'msg' => '接口2账号固定为米乐米乐']);
    }
    $versionConfig = readVersionControls($VERSION_CTRL_FILE);
    $api2Min = max(0, (int)($versionConfig['api2_login_min'] ?? 0));
    $api2Max = max($api2Min, (int)($versionConfig['api2_login_max'] ?? 10000));
    if (!preg_match('/^\d+$/', $password) || (int)$password < $api2Min || (int)$password > $api2Max) {
        jsonResp(['code' => '403', 'data' => null, 'msg' => "接口2编号需在 {$api2Min}-{$api2Max} 范围内"]);
    }

    jsonResp([
        'code' => '200',
        'data' => [
            'token' => 'api2_' . md5($username . '|' . $password . '|' . date('Ymd')),
            'groupId' => $username,
        ],
        'msg' => null,
    ]);
}
if ($postAct === 'api1_take') {
    global $API1_TAKE_URL;
    $takeStart = microtime(true);
    $username = trim((string)($input['username'] ?? ''));
    $takeToken = trim((string)($input['auth_token'] ?? $input['token'] ?? ''));
    if ($takeToken === '') {
        $authHeader = (string)($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
        if (stripos($authHeader, 'Bearer ') === 0) {
            $takeToken = trim(substr($authHeader, 7));
        }
    }
    if ($username === '' && $takeToken !== '') {
        $username = resolveApi1UsernameFromToken($takeToken);
        if ($username !== '') $input['username'] = $username;
    }

    if ($username === '') {
        jsonResp(['code' => '400', 'data' => null, 'msg' => '账号为空']);
    }

    decodedExtensionSyncAllTaskAccountsToApi1Whitelist();
    $allowed = readApi1AllowedAccounts($API1_ACCOUNTS_FILE);
    if (!in_array($username, accountNames($allowed), true)) {
        appendLog($LOG_FILE, [
            'time' => date('Y-m-d H:i:s'),
            'api_type' => 1,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'username' => $username,
            'status' => 'take_rejected',
            'source' => resolveLogSource($input, 'api1_take', 'web_take', 'ctrl_take'),
            'error' => '账号未在后台聚星白名单',
        ], $MAX_LOGS);
        jsonResp(['code' => '403', 'data' => null, 'msg' => '账号未授权，请联系管理员']);
    }

    $deviceCheck = checkDeviceAllowed($DEVICE_FILE, $input + ['api_type' => 1]);
    if (empty($deviceCheck['allowed'])) {
        appendLog($LOG_FILE, [
            'time' => date('Y-m-d H:i:s'),
            'api_type' => 1,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'username' => $username,
            'device_id' => $input['device_id'] ?? '',
            'fingerprint_key' => $input['fingerprint_key'] ?? '',
            'status' => 'device_disabled',
            'source' => resolveLogSource($input, 'api1_take', 'web_take', 'ctrl_take'),
            'error' => $deviceCheck['msg'] ?? '设备已被禁用',
        ], $MAX_LOGS);
        jsonResp(['code' => '403', 'data' => null, 'msg' => $deviceCheck['msg'] ?? '设备已被禁用']);
    }

    if ($takeToken === '') {
        jsonResp(['code' => '401', 'data' => null, 'msg' => '登录已失效，请重新登录']);
    }

    $stageMark = microtime(true);
    $result = forwardGetToServer($API1_TAKE_URL, ['Authorization: Bearer ' . $takeToken]);
    $serverResp = json_decode((string)$result['response'], true);
    $forwardMs = durationMs($stageMark, microtime(true));
    $takeOk = is_array($serverResp) && (string)($serverResp['code'] ?? '') === '200' && !empty($serverResp['data']['taskUrl']);
    appendLog($LOG_FILE, [
        'time' => date('Y-m-d H:i:s'),
        'api_type' => 1,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
        'username' => $username,
        'account_remark' => displayAccountRemark(1, $username),
        'device_id' => $input['device_id'] ?? '',
        'fingerprint_key' => $input['fingerprint_key'] ?? '',
        'status' => $result['error'] ? 'forward_fail' : ($takeOk ? 'success' : 'task_server_error'),
        'source' => resolveLogSource($input, 'api1_take', 'web_take', 'ctrl_take'),
        'forward_url' => $API1_TAKE_URL,
        'forward_attempts' => [forwardAttemptSummary($result, $serverResp) + ['attempt' => 1, 'total_ms' => $forwardMs]],
        'response' => compactLogResponse($serverResp ?? $result['response'], $MAX_LOG_RESPONSE_BYTES),
        'timing_ms' => [
            'raw_read' => $rawReadMs,
            'request_json' => $requestJsonMs,
            'forward' => $forwardMs,
            'total' => elapsedMs($takeStart),
        ],
    ], $MAX_LOGS);

    if ($result['error']) {
        jsonResp(['code' => '500', 'data' => null, 'msg' => '取任务转发失败: ' . $result['error']]);
    }
    jsonResp($serverResp ?: ['code' => '500', 'data' => null, 'msg' => '任务服务器响应异常', 'raw' => $result['response']]);
}

if ($postAct === 'android_session_fetch_submit') {
    $submitStart = microtime(true);
    $username = trim((string)($input['username'] ?? ''));
    $taskUrl = trim((string)($input['url'] ?? $input['task_url'] ?? ''));
    $taskId = trim((string)($input['task_id'] ?? $input['trace_id'] ?? ''));
    $cookies = trim((string)($input['cookies'] ?? $input['cookie'] ?? ''));
    $userAgent = trim((string)($input['user_agent'] ?? $input['ua'] ?? ''));
    $submitToken = trim((string)($input['auth_token'] ?? $input['token'] ?? ''));
    if ($submitToken === '') {
        $authHeader = (string)($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
        if (stripos($authHeader, 'Bearer ') === 0) $submitToken = trim(substr($authHeader, 7));
    }
    if ($username === '' && $submitToken !== '') {
        $username = resolveApi1UsernameFromToken($submitToken);
        if ($username !== '') $input['username'] = $username;
    }

    if ($username === '') jsonResp(['ok' => false, 'msg' => 'username empty']);
    if ($taskUrl === '') jsonResp(['ok' => false, 'msg' => 'task url empty']);
    if ($cookies === '') jsonResp(['ok' => false, 'msg' => 'webview cookie empty']);
    if (!androidSessionAllowedTaskUrl($taskUrl)) jsonResp(['ok' => false, 'msg' => 'task url host not allowed']);

    $isManagedAndroid = strtolower(trim((string)($input['client'] ?? ''))) === 'ajie-android';
    if (!$isManagedAndroid) {
        decodedExtensionSyncAllTaskAccountsToApi1Whitelist();
        $allowed = readApi1AllowedAccounts($API1_ACCOUNTS_FILE);
        if (!in_array($username, accountNames($allowed), true)) {
            appendLog($LOG_FILE, [
                'time' => date('Y-m-d H:i:s'),
                'api_type' => 1,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
                'username' => $username,
                'status' => 'android_session_rejected',
                'source' => 'android_session_fetch_submit',
                'error' => 'account not whitelisted',
            ], $MAX_LOGS);
            jsonResp(['code' => '403', 'data' => null, 'msg' => 'account not authorized']);
        }
    }

    $deviceCheck = checkDeviceAllowed($DEVICE_FILE, $input + ['api_type' => 1]);
    if (empty($deviceCheck['allowed'])) {
        appendLog($LOG_FILE, [
            'time' => date('Y-m-d H:i:s'),
            'api_type' => 1,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'username' => $username,
            'device_id' => $input['device_id'] ?? '',
            'fingerprint_key' => $input['fingerprint_key'] ?? '',
            'status' => 'device_disabled',
            'source' => 'android_session_fetch_submit',
            'error' => $deviceCheck['msg'] ?? 'device disabled',
        ], $MAX_LOGS);
        recordStats($STATS_DIR, $input + ['api_type' => 1], 1, 'device_disabled', $taskId);
        jsonResp(['code' => '403', 'data' => null, 'msg' => $deviceCheck['msg'] ?? 'device disabled']);
    }

    $stageMark = microtime(true);
    $fetchResult = androidFetchUrlWithSession($taskUrl, $cookies, $userAgent);
    $fetchMs = durationMs($stageMark, microtime(true));
    $responseBodyRaw = (string)($fetchResult['response'] ?? '');
    $responseJson = json_decode($responseBodyRaw, true);
    $fetchOk = !$fetchResult['error'] && (int)$fetchResult['http_code'] >= 200 && (int)$fetchResult['http_code'] < 300 && $responseBodyRaw !== '';

    if (!$fetchOk) {
        $uploadId = date('Ymd_His') . '_' . substr(md5($rawBody . '|android_session_fetch_fail'), 0, 8);
        appendLog($LOG_FILE, [
            'time' => date('Y-m-d H:i:s'),
            'api_type' => 1,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'username' => $username,
            'device_id' => $input['device_id'] ?? '',
            'fingerprint_key' => $input['fingerprint_key'] ?? '',
            'platform' => $input['platform'] ?? 'android',
            'client' => $input['client'] ?? 'android_plugin',
            'client_label' => resolveClientLabel($input),
            'status' => 'android_fetch_fail',
            'source' => 'android_session_fetch_submit',
            'task_url' => $taskUrl,
            'task_id' => $taskId,
            'forward_url' => $taskUrl,
            'http_code' => $fetchResult['http_code'] ?? 0,
            'error' => $fetchResult['error'] ?: ('http ' . ($fetchResult['http_code'] ?? 0)),
            'response' => compactLogResponse($responseJson ?? $responseBodyRaw, $MAX_LOG_RESPONSE_BYTES),
            'upload_id' => $uploadId,
            'timing_ms' => ['raw_read' => $rawReadMs, 'request_json' => $requestJsonMs, 'fetch' => $fetchMs, 'total' => elapsedMs($submitStart)],
        ], $MAX_LOGS);
        saveUploadDump($uploadId, [
            'time' => date('Y-m-d H:i:s'),
            'api_type' => 1,
            'source' => 'android_session_fetch_submit',
            'target_url' => $taskUrl,
            'method' => 'GET',
            'http_code' => $fetchResult['http_code'] ?? 0,
            'content_type' => $fetchResult['content_type'] ?? '',
            'response_json' => is_array($responseJson) ? $responseJson : null,
            'response_raw' => $responseBodyRaw,
            'error' => $fetchResult['error'],
        ]);
        jsonResp(['ok' => false, 'msg' => 'android session fetch failed', 'fetch' => [
            'http_code' => $fetchResult['http_code'] ?? 0,
            'error' => $fetchResult['error'] ?? '',
            'content_type' => $fetchResult['content_type'] ?? '',
        ]]);
    }

    $forwardBody = json_encode([
        'appVersion' => (string)($input['appVersion'] ?? 'vv2'),
        'url' => $taskUrl,
        'result' => $responseBodyRaw,
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($submitToken === '') {
        $tokenInfo = getApi1Token($API1_AUTH, $API1_TOKEN_FILE);
        if (!empty($tokenInfo['ok']) && !empty($tokenInfo['token'])) $submitToken = (string)$tokenInfo['token'];
    }
    $forwardHeaders = [];
    if ($submitToken !== '') $forwardHeaders[] = 'Authorization: Bearer ' . $submitToken;

    $stageMark = microtime(true);
    $submitResult = forwardToServer($TARGETS[1]['url'], (string)$forwardBody, false, $forwardHeaders);
    $serverResp = json_decode((string)$submitResult['response'], true);
    $forwardMs = durationMs($stageMark, microtime(true));
    $isForwardSuccess = api1ForwardSuccess($serverResp);
    $uploadId = date('Ymd_His') . '_' . substr(md5($rawBody . '|android_session_submit'), 0, 8);
    $logEntry = [
        'time' => date('Y-m-d H:i:s'),
        'api_type' => 1,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
        'username' => $username,
        'account_remark' => displayAccountRemark(1, $username),
        'device_id' => $input['device_id'] ?? '',
        'fingerprint_key' => $input['fingerprint_key'] ?? '',
        'platform' => $input['platform'] ?? 'android',
        'device_type' => $input['device_type'] ?? '',
        'client' => $input['client'] ?? 'android_plugin',
        'client_label' => resolveClientLabel($input),
        'status' => $submitResult['error'] ? 'forward_fail' : ($isForwardSuccess ? 'success' : 'task_server_error'),
        'source' => 'android_session_fetch_submit',
        'task_url' => $taskUrl,
        'task_id' => $taskId,
        'forward_url' => $TARGETS[1]['url'],
        'fetch_http_code' => $fetchResult['http_code'] ?? 0,
        'fetch_result_len' => strlen($responseBodyRaw),
        'forward_result_len' => strlen($responseBodyRaw),
        'forward_attempts' => [forwardAttemptSummary($submitResult, $serverResp) + ['attempt' => 1, 'total_ms' => $forwardMs]],
        'response' => compactLogResponse($serverResp ?? $submitResult['response'], $MAX_LOG_RESPONSE_BYTES),
        'upload_id' => $uploadId,
        'timing_ms' => ['raw_read' => $rawReadMs, 'request_json' => $requestJsonMs, 'fetch' => $fetchMs, 'forward' => $forwardMs, 'total' => elapsedMs($submitStart)],
    ];
    if ($submitResult['error']) $logEntry['error'] = $submitResult['error'];
    appendLog($LOG_FILE, $logEntry, $MAX_LOGS);
    recordStats($STATS_DIR, $input + ['api_type' => 1], 1, $logEntry['status'], $taskId);
    saveUploadDump($uploadId, [
        'time' => date('Y-m-d H:i:s'),
        'api_type' => 1,
        'source' => 'android_session_fetch_submit',
        'target_url' => $TARGETS[1]['url'],
        'method' => 'POST',
        'request_body' => json_decode((string)$forwardBody, true),
        'fetch' => [
            'url' => $taskUrl,
            'http_code' => $fetchResult['http_code'] ?? 0,
            'content_type' => $fetchResult['content_type'] ?? '',
            'response_json' => is_array($responseJson) ? $responseJson : null,
        ],
        'http_code' => $submitResult['http_code'] ?? 0,
        'response_json' => is_array($serverResp) ? $serverResp : null,
        'response_raw' => $submitResult['response'],
        'error' => $submitResult['error'],
    ]);
    if ($submitResult['error']) jsonResp(['ok' => false, 'msg' => 'submit forward failed: ' . $submitResult['error']]);
    if ($serverResp) {
        $serverResp['_proxy'] = [
            'source' => 'android_session_fetch_submit',
            'task_id' => $taskId,
            'fetch_http_code' => $fetchResult['http_code'] ?? 0,
            'submit_accepted' => $isForwardSuccess,
            'status' => $logEntry['status'],
        ];
        jsonResp($serverResp);
    }
    jsonResp(['ok' => false, 'msg' => 'submit server abnormal', 'raw' => $submitResult['response']]);
}

if ($postAct === 'api1_submit') {
    $submitStart = microtime(true);
    $username = trim((string)($input['username'] ?? ''));
    $submitUrl = trim((string)($input['url'] ?? ''));
    $submitResult = (string)($input['result'] ?? '');
    $submitId = trim((string)($input['submit_id'] ?? ''));
    $taskId = trim((string)($input['task_id'] ?? $input['trace_id'] ?? ''));
    $itemId = trim((string)($input['item_id'] ?? ''));
    $shopId = trim((string)($input['shop_id'] ?? ''));
    $productUrl = trim((string)($input['product_url'] ?? ''));
    $pdpUrl = trim((string)($input['pdp_url'] ?? ''));
    $submitToken = trim((string)($input['auth_token'] ?? $input['token'] ?? ''));
    if ($submitToken === '') {
        $authHeader = (string)($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
        if (stripos($authHeader, 'Bearer ') === 0) {
            $submitToken = trim(substr($authHeader, 7));
        }
    }
    if ($username === '' && $submitToken !== '') {
        $username = resolveApi1UsernameFromToken($submitToken);
        if ($username !== '') $input['username'] = $username;
    }

    if ($username !== '') {
        decodedExtensionSyncAllTaskAccountsToApi1Whitelist();
        $allowed = readApi1AllowedAccounts($API1_ACCOUNTS_FILE);
        if (!in_array($username, accountNames($allowed), true)) {
            appendLog($LOG_FILE, [
                'time' => date('Y-m-d H:i:s'),
                'api_type' => 1,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
                'username' => $username,
                'status' => 'submit_rejected',
                'source' => resolveLogSource($input, 'api1_submit', 'web_submit', 'ctrl_submit'),
                'error' => '账号未在后台聚星白名单',
            ], $MAX_LOGS);
            jsonResp(['code' => '403', 'data' => null, 'msg' => '账号未授权，请联系管理员']);
        }
    }

    $deviceCheck = checkDeviceAllowed($DEVICE_FILE, $input + ['api_type' => 1]);
    if (empty($deviceCheck['allowed'])) {
        appendLog($LOG_FILE, [
            'time' => date('Y-m-d H:i:s'),
            'api_type' => 1,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'username' => $username,
            'device_id' => $input['device_id'] ?? '',
            'fingerprint_key' => $input['fingerprint_key'] ?? '',
            'status' => 'device_disabled',
            'source' => resolveLogSource($input, 'api1_submit', 'web_submit', 'ctrl_submit'),
            'error' => $deviceCheck['msg'] ?? '设备已被禁用',
        ], $MAX_LOGS);
        recordStats($STATS_DIR, $input + ['api_type' => 1], 1, 'device_disabled', $taskId);
        jsonResp(['code' => '403', 'data' => null, 'msg' => $deviceCheck['msg'] ?? '设备已被禁用']);
    }

    if ($submitUrl === '' || $submitResult === '') {
        jsonResp(['code' => '400', 'data' => null, 'msg' => '提交数据为空']);
    }

    $forwardBody = json_encode([
        'appVersion' => (string)($input['appVersion'] ?? 'vv2'),
        'url' => $submitUrl,
        'result' => $submitResult,
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

    $forwardHeaders = [];
    if ($submitToken !== '') {
        $forwardHeaders[] = 'Authorization: Bearer ' . $submitToken;
    }

    $stageMark = microtime(true);
    $result = forwardToServer($TARGETS[1]['url'], (string)$forwardBody, false, $forwardHeaders);
    $serverResp = json_decode((string)$result['response'], true);
    $forwardMs = durationMs($stageMark, microtime(true));
    $isForwardSuccess = api1ForwardSuccess($serverResp);
    if (!$isForwardSuccess && api1ParseTimeoutResponse($serverResp, (string)$result['response'])) {
        $isForwardSuccess = false;
    }
    $respData = is_array($serverResp['data'] ?? null) ? $serverResp['data'] : null;
    $serverTaskId = is_array($respData) ? trim((string)($respData['task_id'] ?? $respData['taskId'] ?? $respData['trace_id'] ?? $respData['traceId'] ?? $respData['id'] ?? '')) : '';
    $serverReceivedId = is_array($respData) ? trim((string)($respData['submit_id'] ?? '')) : '';
    $proxyContextMatch = true;
    if ($taskId !== '' && $serverTaskId !== '') {
        $proxyContextMatch = $serverTaskId === $taskId;
    } elseif ($submitId !== '' && $serverReceivedId !== '') {
        $proxyContextMatch = $serverReceivedId === $submitId;
    }
    if (!$proxyContextMatch) {
        $isForwardSuccess = false;
    }

    $sourceLabel = resolveLogSource($input, 'ios_submit', 'web_submit', 'ctrl_submit');
    $uploadId = date('Ymd_His') . '_' . substr(md5($rawBody . '|' . $sourceLabel), 0, 8);
    $logEntry = [
        'time' => date('Y-m-d H:i:s'),
        'api_type' => 1,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
        'username' => $username,
        'account_remark' => displayAccountRemark(1, $username),
        'device_id' => $input['device_id'] ?? '',
        'fingerprint_key' => $input['fingerprint_key'] ?? '',
        'device_type' => $input['device_type'] ?? '',
        'platform' => $input['platform'] ?? '',
        'client' => $input['client'] ?? '',
        'client_label' => resolveClientLabel($input),
        'status' => $result['error'] ? 'forward_fail' : ($isForwardSuccess ? 'success' : 'task_server_error'),
        'source' => $sourceLabel,
        'task_url' => $submitUrl,
        'forward_url' => $TARGETS[1]['url'],
        'forward_result_len' => strlen($submitResult),
        'submit_id' => $submitId,
        'task_id' => $taskId,
        'shop_id' => $shopId,
        'item_id' => $itemId,
        'server_task_id' => $serverTaskId,
        'server_submit_id' => $serverReceivedId,
        'proxy_context_match' => $proxyContextMatch,
        'forward_attempts' => [forwardAttemptSummary($result, $serverResp) + ['attempt' => 1, 'total_ms' => $forwardMs]],
        'response' => compactLogResponse($serverResp ?? $result['response'], $MAX_LOG_RESPONSE_BYTES),
        'upload_id' => $uploadId,
        'timing_ms' => [
            'raw_read' => $rawReadMs,
            'request_json' => $requestJsonMs,
            'build_forward_body' => 0,
            'forward' => $forwardMs,
            'total' => elapsedMs($submitStart),
        ],
    ];
    if ($result['error']) {
        $logEntry['error'] = $result['error'];
    }

    $uploadDetail = [
        'time' => date('Y-m-d H:i:s'),
        'api_type' => 1,
        'source' => $sourceLabel,
        'target_url' => $TARGETS[1]['url'],
        'method' => 'POST',
        'content_type' => 'application/json; charset=utf-8',
        'content_encoding' => 'identity',
        'request_body' => json_decode((string)$forwardBody, true),
        'http_code' => $result['http_code'] ?? 0,
        'response_json' => is_array($serverResp) ? $serverResp : null,
        'response_raw' => $result['response'],
        'error' => $result['error'],
        'submit_id' => $submitId,
        'task_id' => $taskId,
        'shop_id' => $shopId,
        'item_id' => $itemId,
        'server_task_id' => $serverTaskId,
        'server_submit_id' => $serverReceivedId,
        'proxy_context_match' => $proxyContextMatch,
        'forward_attempts' => $logEntry['forward_attempts'],
    ];

    appendLog($LOG_FILE, $logEntry, $MAX_LOGS);
    recordStats($STATS_DIR, $input, 1, $logEntry['status']);
    saveUploadDump($uploadId, $uploadDetail);

    if ($result['error']) {
        jsonResp(['ok' => false, 'msg' => '转发失败: ' . $result['error']]);
    }
    if ($serverResp && $proxyContextMatch) {
        $serverResp['_proxy'] = [
            'submit_id' => $submitId,
            'task_id' => $taskId,
            'server_task_id' => $serverTaskId,
            'server_submit_id' => $serverReceivedId,
            'context_match' => $proxyContextMatch,
            'submit_accepted' => $isForwardSuccess,
            'counted' => $isForwardSuccess,
            'status' => $logEntry['status'],
        ];
        jsonResp($serverResp);
    }
    if ($serverResp && !$proxyContextMatch) {
        jsonResp([
            'ok' => false,
            'msg' => '上游未返回当前任务回执',
            'upstream' => $serverResp,
            '_proxy' => [
                'submit_id' => $submitId,
                'task_id' => $taskId,
                'server_task_id' => $serverTaskId,
                'server_submit_id' => $serverReceivedId,
                'context_match' => false,
            ],
        ]);
    }
    jsonResp(['ok' => false, 'msg' => '任务服务器响应异常', 'raw' => $result['response']]);
}

if ($postAct === 'api2_submit_plain') {
    $submitStart = microtime(true);
    $username = trim((string)($input['username'] ?? ''));
    $groupId = trim((string)($input['group_id'] ?? ''));
    $taskInfo = $input['task_info'] ?? null;
    $plainData = $input['data'] ?? $input['result'] ?? '';
    $submitId = trim((string)($input['submit_id'] ?? ''));
    $taskId = trim((string)($input['task_id'] ?? $input['trace_id'] ?? ''));
    $itemId = trim((string)($input['item_id'] ?? ''));
    $shopId = trim((string)($input['shop_id'] ?? ''));
    if ($username === '' || $groupId === '' || !is_array($taskInfo) || $plainData === '') {
        jsonResp(['ok' => false, 'msg' => '接口2提交缺少字段']);
    }

    $deviceCheck = checkDeviceAllowed($DEVICE_FILE, $input + ['api_type' => 2]);
    if (empty($deviceCheck['allowed'])) {
        recordStats($STATS_DIR, $input, 2, 'device_disabled');
        jsonResp(['ok' => false, 'msg' => $deviceCheck['msg'] ?? '设备已禁用']);
    }

    $actualData = is_string($plainData) ? json_decode($plainData, true) : $plainData;
    if (!is_array($actualData)) {
        jsonResp(['ok' => false, 'msg' => '接口2提交data不是JSON对象']);
    }

    /* $unusedPayload = [
        '鐢ㄦ埛鍚?' => $username,
        '缁処D' => $groupId,
        '浠诲姟鏁版嵁' => $taskInfo,
        '鐢ㄦ埛鍚?' => $username, '缁処D' => $groupId,
        '浠诲姟鏁版嵁' => $taskInfo, 'data' => $actualData,
    ]; */
    $payload = [];
    $payload['鐢ㄦ埛鍚?'] = $username;
    $payload['缁処D'] = $groupId;
    $payload['浠诲姟鏁版嵁'] = $taskInfo;
    $payload['data'] = $actualData;
    $payload = api2ForwardPayload($username, $groupId, $taskInfo, $actualData);
    $forwardBody = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $stageMark = microtime(true);
    $result = forwardToServer($TARGETS[2]['url'], (string)$forwardBody, true, []);
    $serverResp = json_decode((string)$result['response'], true);
    $forwardMs = durationMs($stageMark, microtime(true));
    $isForwardSuccess = api2ForwardSuccess($serverResp);

    $uploadId = date('Ymd_His') . '_' . substr(md5($rawBody . '|ios_api2_submit'), 0, 8);
    $logEntry = [
        'time' => date('Y-m-d H:i:s'),
        'api_type' => 2,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
        'username' => $username,
        'group_id' => $groupId,
        'account_remark' => displayAccountRemark(2, $username, $groupId),
        'device_id' => $input['device_id'] ?? '',
        'fingerprint_key' => $input['fingerprint_key'] ?? '',
        'status' => $result['error'] ? 'forward_fail' : ($isForwardSuccess ? 'success' : 'task_server_error'),
        'source' => 'ios_api2_submit',
        'submit_id' => $submitId,
        'task_id' => $taskId,
        'shop_id' => $shopId,
        'item_id' => $itemId,
        'task_info' => $taskInfo,
        'forward_url' => $TARGETS[2]['url'],
        'forward_attempts' => [forwardAttemptSummary($result, $serverResp) + ['attempt' => 1, 'total_ms' => $forwardMs]],
        'response' => compactLogResponse($serverResp ?? $result['response'], $MAX_LOG_RESPONSE_BYTES),
        'upload_id' => $uploadId,
        'timing_ms' => [
            'raw_read' => $rawReadMs,
            'request_json' => $requestJsonMs,
            'build_forward_body' => 0,
            'forward' => $forwardMs,
            'total' => elapsedMs($submitStart),
        ],
    ];
    if ($result['error']) $logEntry['error'] = $result['error'];
    $uploadDetail = [
        'time' => date('Y-m-d H:i:s'),
        'api_type' => 2,
        'source' => 'ios_api2_submit',
        'target_url' => $TARGETS[2]['url'],
        'method' => 'POST',
        'content_encoding' => 'gzip',
        'request_body' => $payload,
        'http_code' => $result['http_code'] ?? 0,
        'response_json' => is_array($serverResp) ? $serverResp : null,
        'response_raw' => $result['response'],
        'error' => $result['error'],
    ];
    appendLog($LOG_FILE, $logEntry, $MAX_LOGS);
    recordStats($STATS_DIR, $input + ['api_type' => 2], 2, $logEntry['status'], is_array($taskInfo) ? (string)($taskInfo['ID'] ?? '') : '');
    if ($logEntry['status'] !== 'success' || $SAVE_SUCCESS_UPLOAD_DUMPS) {
        saveUploadDump($uploadId, $uploadDetail);
    }
    if ($result['error']) {
        jsonResp(['ok' => false, 'msg' => '转发失败: ' . $result['error']]);
    }
    jsonResp($serverResp ?: ['ok' => false, 'msg' => '任务服务器响应异常', 'raw' => $result['response']]);
}

if ($postAct === 'heartbeat') {
    jsonResp(updateDeviceHeartbeat($DEVICE_FILE, $input));
}

if ($postAct === 'fingerprint_event') {
    jsonResp(recordFingerprintEnvEvent($FP_ENV_STATS_DIR, $input));
}

$apiType       = (int)($input['api_type'] ?? 0);
$encryptedData = $input['data'] ?? '';

if (!$apiType || !isset($TARGETS[$apiType])) jsonResp(['ok' => false, 'msg' => '无效api_type']);
if (!$encryptedData || !is_string($encryptedData)) jsonResp(['ok' => false, 'msg' => '缺少data']);

$deviceCheck = checkDeviceAllowed($DEVICE_FILE, $input);
if (empty($deviceCheck['allowed'])) {
    $logEntry = [
        'time'       => date('Y-m-d H:i:s'),
        'api_type'   => $apiType,
        'ip'         => $_SERVER['REMOTE_ADDR'] ?? '',
        'username'   => $input['username'] ?? $input['用户名'] ?? '',
        'group_id'   => $input['group_id'] ?? $input['组ID'] ?? '',
        'device_id'  => $input['device_id'] ?? $input['设备ID'] ?? '',
        'platform' => $input['platform'] ?? '',
        'device_type' => $input['device_type'] ?? '',
        'device_label' => $input['device_label'] ?? '',
        'client' => $input['client'] ?? '',
        'client_label' => resolveClientLabel($input),
        'fingerprint_key' => $input['fingerprint_key'] ?? '',
        'fingerprint_id' => $input['fingerprint_id'] ?? '',
        'fingerprint_name' => $input['fingerprint_name'] ?? '',
        'device_key' => $deviceCheck['device_key'] ?? '',
        'encrypted_len' => strlen($encryptedData),
        'raw_body_len' => strlen($rawBody),
        'timing_ms' => [
            'raw_read' => $rawReadMs,
            'request_json' => $requestJsonMs,
            'before_device_check' => elapsedMs($requestStart),
        ],
        'status'     => 'device_disabled',
        'error'      => $deviceCheck['msg'] ?? '设备已被禁用',
    ];
    appendLog($LOG_FILE, $logEntry, $MAX_LOGS);
    recordStats($STATS_DIR, $input, $apiType, 'device_disabled');
    jsonResp(['ok' => false, 'msg' => $deviceCheck['msg'] ?? '设备已被禁用']);
}

$logEntry = [
    'time'       => date('Y-m-d H:i:s'),
    'api_type'   => $apiType,
    'ip'         => $_SERVER['REMOTE_ADDR'] ?? '',
    'username'   => $input['username'] ?? $input['用户名'] ?? '',
    'group_id'   => $input['group_id'] ?? $input['组ID'] ?? '',
    'device_id'  => $input['device_id'] ?? $input['设备ID'] ?? '',
    'platform' => $input['platform'] ?? '',
    'device_type' => $input['device_type'] ?? '',
    'device_label' => $input['device_label'] ?? '',
    'client' => $input['client'] ?? '',
    'client_label' => resolveClientLabel($input),
    'fingerprint_key' => $input['fingerprint_key'] ?? '',
    'fingerprint_id' => $input['fingerprint_id'] ?? '',
    'fingerprint_name' => $input['fingerprint_name'] ?? '',
    'device_key' => $deviceCheck['device_key'] ?? '',
    'encrypted_len' => strlen($encryptedData),
    'raw_body_len' => strlen($rawBody),
    'timing_ms' => [
        'raw_read' => $rawReadMs,
        'request_json' => $requestJsonMs,
        'before_decrypt' => elapsedMs($requestStart),
    ],
];
$logUsername = (string)$logEntry['username'];
$logRemarkMap = accountRemarkMap(readApi1AllowedAccounts($apiType === 2 ? $API2_NUMBERS_FILE : $API1_ACCOUNTS_FILE));
$logEntry['account_remark'] = $logRemarkMap[$logUsername] ?? '';

$plainInputData = json_decode($encryptedData, true);
if (is_array($plainInputData)) {
    $target = $TARGETS[$apiType];
    $forwardHeaders = [];
    $taskInfo = null;
    $statsTaskId = '';

    if ($apiType === 2) {
        $username = (string)($input['username'] ?? '');
        $groupId = (string)($input['group_id'] ?? '');
        $taskInfo = $input['task_info'] ?? null;
        if (!is_array($taskInfo)) {
            $taskId = trim((string)($input['task_id'] ?? $input['trace_id'] ?? ''));
            $taskInfo = $taskId !== '' ? ['ID' => $taskId] : [];
        }
        if ($username === '' || $groupId === '' || !$taskInfo) {
            $logEntry['status'] = 'plain_missing_fields';
            $logEntry['timing_ms']['total'] = elapsedMs($requestStart);
            appendLog($LOG_FILE, $logEntry, $MAX_LOGS);
            jsonResp(['ok' => false, 'msg' => 'plain api2 missing username/group_id/task_info']);
        }
        $payload = api2ForwardPayload($username, $groupId, $taskInfo, $plainInputData);
        $logEntry['username'] = $username;
        $logEntry['group_id'] = $groupId;
        $logEntry['task_info'] = $taskInfo;
        $logEntry['source'] = 'plain_data';
        $statsTaskId = (string)($taskInfo['ID'] ?? '');
    } else {
        $taskUrl = (string)($input['url'] ?? '');
        if ($taskUrl === '') {
            $itemId = (string)($input['item_id'] ?? '');
            $shopId = (string)($input['shop_id'] ?? '');
            if ($itemId !== '' && $shopId !== '') {
                $taskUrl = 'https://shopee.tw/api/v4/pdp/get_pc?display_model_id=0&item_id=' . rawurlencode($itemId) . '&model_selection_logic=3&shop_id=' . rawurlencode($shopId) . '&tz_offset_in_minutes=480&detail_level=0';
            }
        }
        if ($taskUrl === '') {
            $logEntry['status'] = 'plain_missing_url';
            $logEntry['timing_ms']['total'] = elapsedMs($requestStart);
            appendLog($LOG_FILE, $logEntry, $MAX_LOGS);
            jsonResp(['ok' => false, 'msg' => 'plain api1 missing url']);
        }
        $payload = [
            'appVersion' => (string)($input['appVersion'] ?? 'vv2'),
            'url' => $taskUrl,
            'result' => $encryptedData,
        ];
        $api1InputToken = trim((string)($input['auth_token'] ?? $input['token'] ?? ''));
        if ($api1InputToken !== '') {
            $forwardHeaders[] = 'Authorization: Bearer ' . $api1InputToken;
        }
        $logEntry['task_url'] = $taskUrl;
        $logEntry['source'] = 'plain_data';
    }

    $stageMark = microtime(true);
    $forwardBody = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $logEntry['timing_ms']['build_forward_body'] = durationMs($stageMark, microtime(true));
    $stageMark = microtime(true);
    $result = forwardToServer($target['url'], (string)$forwardBody, $target['gzip'], $forwardHeaders);
    $serverResp = json_decode((string)$result['response'], true);
    $forwardMs = durationMs($stageMark, microtime(true));
    $isForwardSuccess = $apiType === 1 ? api1ForwardSuccess($serverResp) : api2ForwardSuccess($serverResp);
    $logEntry['forward_url'] = $target['url'];
    $logEntry['forward_attempts'] = [forwardAttemptSummary($result, $serverResp) + ['attempt' => 1, 'total_ms' => $forwardMs]];
    $logEntry['timing_ms']['forward'] = $forwardMs;
    $logEntry['status'] = $result['error'] ? 'forward_fail' : ($isForwardSuccess ? 'success' : 'task_server_error');
    $logEntry['response'] = compactLogResponse($serverResp ?? $result['response'], $MAX_LOG_RESPONSE_BYTES);
    $logEntry['timing_ms']['total'] = elapsedMs($requestStart);
    if ($result['error']) $logEntry['error'] = $result['error'];
    $uploadId = date('Ymd_His') . '_' . substr(md5($rawBody . '|plain_upload'), 0, 8);
    $logEntry['upload_id'] = $uploadId;
    $uploadDetail = [
        'time' => date('Y-m-d H:i:s'),
        'api_type' => $apiType,
        'source' => 'plain_data',
        'target_url' => $target['url'],
        'method' => 'POST',
        'content_encoding' => $target['gzip'] ? 'gzip' : 'identity',
        'request_body' => $payload,
        'http_code' => $result['http_code'] ?? 0,
        'response_json' => is_array($serverResp) ? $serverResp : null,
        'response_raw' => $result['response'],
        'error' => $result['error'],
    ];
    appendLog($LOG_FILE, $logEntry, $MAX_LOGS);
    recordStats($STATS_DIR, $input, $apiType, $logEntry['status'], $statsTaskId);
    if ($logEntry['status'] !== 'success' || $SAVE_SUCCESS_UPLOAD_DUMPS) {
        saveUploadDump($uploadId, $uploadDetail);
    }
    if ($result['error']) {
        jsonResp(['ok' => false, 'msg' => 'forward failed: ' . $result['error']]);
    }
    jsonResp($serverResp ?: ['ok' => false, 'msg' => 'task server response invalid', 'raw' => $result['response']]);
}

$stageMark = microtime(true);
// 解密
$plain = aesDecrypt($encryptedData, $AES_KEY);
$logEntry['timing_ms']['aes_decrypt'] = durationMs($stageMark, microtime(true));
if ($plain === null) {
    $logEntry['status'] = 'decrypt_fail';
    $logEntry['timing_ms']['total'] = elapsedMs($requestStart);
    appendLog($LOG_FILE, $logEntry, $MAX_LOGS);
    jsonResp(['ok' => false, 'msg' => 'AES解密失败']);
}

$stageMark = microtime(true);
$decrypted = json_decode($plain, true);
$logEntry['timing_ms']['decrypted_json'] = durationMs($stageMark, microtime(true));
if ($decrypted === null && json_last_error() !== JSON_ERROR_NONE) {
    $logEntry['status'] = 'json_fail';
    $stageMark = microtime(true);
    $logEntry['dump_id'] = saveDecryptDump($encryptedData, $plain, $apiType, $decrypted);
    $logEntry['timing_ms']['dump'] = durationMs($stageMark, microtime(true));
    $logEntry['timing_ms']['total'] = elapsedMs($requestStart);
    $logEntry['preview'] = mb_substr($plain, 0, 200);
    appendLog($LOG_FILE, $logEntry, $MAX_LOGS);
    jsonResp(['ok' => false, 'msg' => '解密后非JSON: ' . json_last_error_msg()]);
}

$logEntry['decrypted_len'] = strlen($plain);
$logEntry['decrypted_keys'] = is_array($decrypted) ? array_keys($decrypted) : 'not_array';

// Mars加密的数据是一个wrapper JSON，结构: {requestHeaders, responseHeaders, responseContent, extra}
// 商品完整数据在 responseContent.response_body；它本身是一个 JSON 字符串，内容类似：
// {"bff_meta":null,"error":null,"error_msg":null,"data":{"item":{...完整商品字段...}}}
$responseBodyRaw = null;
$productResponse = null;
$actualData = null;
$stageMark = microtime(true);
if (is_array($decrypted)) {
    if (isset($decrypted['responseContent']) && is_array($decrypted['responseContent'])) {
        $rc = $decrypted['responseContent'];
        $rb = $rc['response_body'] ?? '';
        if (is_string($rb) && $rb !== '') {
            $responseBodyRaw = $rb;
            $parsed = jsonDecodeAssoc($rb);
            if (is_array($parsed)) {
                $productResponse = $parsed;
                // 接口2的 data 传 response_body 解出来的完整对象，不传转义 JSON 字符串。
                $actualData = $parsed;
                $logEntry['extract_from'] = 'responseContent.response_body(object)';
                $logEntry['response_body_keys'] = array_keys($parsed);
                $item = $parsed['data']['item'] ?? $parsed['item'] ?? null;
                $logEntry['item_keys_count'] = is_array($item) ? count($item) : 0;
            } else {
                $logEntry['extract_from'] = 'raw_wrapper(response_body_not_json)';
            }
        } else {
            $logEntry['extract_from'] = 'raw_wrapper(response_body_empty)';
        }
    } else {
        $logEntry['extract_from'] = 'missing_responseContent.response_body';
    }
    $logEntry['response_body_preview'] = mb_substr(
        is_array($decrypted['responseContent'] ?? null) ? ($decrypted['responseContent']['response_body'] ?? '(missing)') : '(missing)',
        0, 200
    );
}
$logEntry['timing_ms']['extract_response_body'] = durationMs($stageMark, microtime(true));

// 构建转发
$target = $TARGETS[$apiType];
$forwardHeaders = [];

if ($apiType === 2) {
    $username = $input['用户名'] ?? '';
    $groupId  = $input['组ID'] ?? '';
    $taskInfo = $input['任务数据'] ?? null;
    if (!$username || !$groupId || !$taskInfo) jsonResp(['ok' => false, 'msg' => '接口2缺少字段']);

    if (!$username && !empty($input['用户名'])) $username = $input['用户名'];
    if (!$groupId && !empty($input['组ID'])) $groupId = $input['组ID'];
    if (!$taskInfo && !empty($input['任务数据'])) $taskInfo = $input['任务数据'];
    if (!$username && !empty($input['username'])) $username = $input['username'];
    if (!$groupId && !empty($input['group_id'])) $groupId = $input['group_id'];
    if (!$taskInfo && !empty($input['task_info'])) $taskInfo = $input['task_info'];
    $logEntry['username'] = $username;
    $logEntry['group_id'] = $groupId;
    $logEntry['account_remark'] = displayAccountRemark(2, (string)$username, (string)$groupId);
    $logEntry['task_info'] = $taskInfo;
    if (!is_array($actualData)) {
        $logEntry['status'] = 'extract_fail';
        $stageMark = microtime(true);
        $logEntry['dump_id'] = saveDecryptDump($encryptedData, $plain, $apiType, $decrypted, $productResponse);
        $logEntry['timing_ms']['dump'] = durationMs($stageMark, microtime(true));
        $logEntry['timing_ms']['total'] = elapsedMs($requestStart);
        appendLog($LOG_FILE, $logEntry, $MAX_LOGS);
        jsonResp(['ok' => false, 'msg' => '未提取到response_body对象，接口2不会上传wrapper或转义字符串']);
    }
    $payload = [
        '用户名' => $username, '组ID' => $groupId,
        '任务数据' => $taskInfo, 'data' => $actualData,
    ];
    $logEntry['forward_data_type'] = gettype($payload['data']);
    $logEntry['forward_data_keys'] = is_array($payload['data']) ? array_slice(array_keys($payload['data']), 0, 30) : null;
    $logEntry['forward_has_response_body_raw'] = is_string($responseBodyRaw) && $responseBodyRaw !== '';
    $stageMark = microtime(true);
    $logEntry['dump_id'] = maybeSaveSuccessDecryptDump($encryptedData, $plain, $apiType, $decrypted, $productResponse, $payload);
    $logEntry['timing_ms']['dump'] = durationMs($stageMark, microtime(true));

    $stageMark = microtime(true);
    $forwardBody = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $logEntry['timing_ms']['build_forward_body'] = durationMs($stageMark, microtime(true));

} elseif ($apiType === 1) {
    $taskUrl = $input['url'] ?? '';
    if (!$taskUrl) jsonResp(['ok' => false, 'msg' => '接口1缺少url']);

    $logEntry['task_url'] = $taskUrl;
    if (!is_string($responseBodyRaw) || $responseBodyRaw === '') {
        $logEntry['status'] = 'extract_fail';
        $stageMark = microtime(true);
        $logEntry['dump_id'] = saveDecryptDump($encryptedData, $plain, $apiType, $decrypted, $productResponse);
        $logEntry['timing_ms']['dump'] = durationMs($stageMark, microtime(true));
        $logEntry['timing_ms']['total'] = elapsedMs($requestStart);
        appendLog($LOG_FILE, $logEntry, $MAX_LOGS);
        jsonResp(['ok' => false, 'msg' => '未提取到responseContent.response_body，接口1不会上传完整wrapper']);
    }

    $payload = [
        'appVersion' => 'vv2', 'url' => $taskUrl, 'result' => $responseBodyRaw,
    ];
    $api1InputToken = trim((string)($input['auth_token'] ?? $input['token'] ?? ''));
    $api1UsingInputToken = $api1InputToken !== '';
    if ($api1UsingInputToken) {
        $forwardHeaders[] = 'Authorization: Bearer ' . $api1InputToken;
        $logEntry['api1_token_source'] = 'app';
        $api1InputTokenExp = jwtExp($api1InputToken);
        $logEntry['api1_token_expires_at'] = $api1InputTokenExp > 0 ? date('Y-m-d H:i:s', $api1InputTokenExp) : '';
    } else {
        $tokenResult = getApi1Token($API1_AUTH, $API1_TOKEN_FILE);
        if (empty($tokenResult['ok'])) {
            $logEntry['status'] = 'api1_login_fail';
            $logEntry['error'] = $tokenResult['msg'] ?? '接口1登录失败';
            $logEntry['timing_ms']['total'] = elapsedMs($requestStart);
            appendLog($LOG_FILE, $logEntry, $MAX_LOGS);
            jsonResp(['ok' => false, 'msg' => $logEntry['error']]);
        }
        $forwardHeaders[] = 'Authorization: Bearer ' . $tokenResult['token'];
        $logEntry['api1_token_source'] = 'proxy';
        $logEntry['api1_token_cached'] = !empty($tokenResult['cached']);
        $logEntry['api1_token_expires_at'] = date('Y-m-d H:i:s', (int)$tokenResult['expires_at']);
    }
    $logEntry['forward_result_from'] = 'responseContent.response_body';
    $logEntry['forward_result_len'] = strlen($responseBodyRaw);
    $stageMark = microtime(true);
    $logEntry['dump_id'] = maybeSaveSuccessDecryptDump($encryptedData, $plain, $apiType, $decrypted, $productResponse, $payload);
    $logEntry['timing_ms']['dump'] = durationMs($stageMark, microtime(true));

    $stageMark = microtime(true);
    $forwardBody = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $logEntry['timing_ms']['build_forward_body'] = durationMs($stageMark, microtime(true));
}

// 转发
$logEntry['forward_url'] = $target['url'];
$logEntry['forward_attempts'] = [];
$forwardMaxAttempts = $apiType === 1 ? $API1_PARSE_TIMEOUT_MAX_ATTEMPTS : 1;
for ($attempt = 1; $attempt <= $forwardMaxAttempts; $attempt++) {
    $stageMark = microtime(true);
    $result = forwardToServer($target['url'], $forwardBody, $target['gzip'], $forwardHeaders);
    $serverResp = json_decode((string)$result['response'], true);
    $attemptSummary = forwardAttemptSummary($result, $serverResp);
    $attemptSummary['attempt'] = $attempt;
    $attemptSummary['total_ms'] = durationMs($stageMark, microtime(true));
    $logEntry['forward_attempts'][] = $attemptSummary;
    if ($apiType !== 1 || !api1ParseTimeoutResponse($serverResp, (string)$result['response']) || api1ForwardSuccess($serverResp)) {
        break;
    }
    if ($attempt < $forwardMaxAttempts) {
        usleep($API1_PARSE_TIMEOUT_RETRY_DELAY_US);
    }
}
$logEntry['timing_ms']['forward'] = array_sum(array_map(fn($a) => (int)($a['total_ms'] ?? 0), $logEntry['forward_attempts']));

if ($apiType === 1 && empty($api1UsingInputToken) && is_array($serverResp) && stripos((string)($serverResp['msg'] ?? ''), 'login') !== false) {
    $tokenResult = getApi1Token($API1_AUTH, $API1_TOKEN_FILE, true);
    if (!empty($tokenResult['ok'])) {
        $forwardHeaders = ['Authorization: Bearer ' . $tokenResult['token']];
        $stageMark = microtime(true);
        $result = forwardToServer($target['url'], $forwardBody, $target['gzip'], $forwardHeaders);
        $serverResp = json_decode((string)$result['response'], true);
        $logEntry['api1_token_refreshed'] = true;
        $logEntry['forward_attempts'][] = [
            'attempt' => 'token_refresh',
            'total_ms' => durationMs($stageMark, microtime(true)),
        ] + forwardAttemptSummary($result, $serverResp);
    }
}

$uploadDetail = [
    'time' => date('Y-m-d H:i:s'),
    'api_type' => $apiType,
    'target_url' => $target['url'],
    'method' => 'POST',
    'content_type' => 'application/json; charset=utf-8',
    'content_encoding' => $target['gzip'] ? 'gzip' : 'identity',
    'request_body' => json_decode($forwardBody, true),
    'http_code' => $result['http_code'] ?? 0,
    'response_json' => is_array($serverResp) ? $serverResp : null,
    'response_raw' => $result['response'],
    'error' => $result['error'],
    'forward_attempts' => $logEntry['forward_attempts'] ?? [],
];
$logEntry['upload_id'] = '';

if ($result['error']) {
    $logEntry['status'] = 'forward_fail';
    $logEntry['error']  = $result['error'];
    $logEntry['upload_id'] = (string)($logEntry['dump_id'] ?? '');
    if ($logEntry['upload_id'] === '') {
        $logEntry['upload_id'] = date('Ymd_His') . '_' . substr(md5($encryptedData . '|upload'), 0, 8);
    }
    $logEntry['timing_ms']['total'] = elapsedMs($requestStart);
    deferred(function () use ($LOG_FILE, $logEntry, $MAX_LOGS, $STATS_DIR, $input, $apiType, $uploadDetail) {
        appendLog($LOG_FILE, $logEntry, $MAX_LOGS);
        recordStats($STATS_DIR, $input, $apiType, 'forward_fail');
        saveUploadDump((string)($logEntry['upload_id'] ?? ''), $uploadDetail);
    });
    jsonResp(['ok' => false, 'msg' => '转发失败: ' . $result['error']]);
}

if ($apiType === 1) {
    $isForwardSuccess = api1ForwardSuccess($serverResp);
    if (!$isForwardSuccess && api1ParseTimeoutResponse($serverResp, (string)$result['response'])) {
        $logEntry['error'] = 'api1 parse timeout, auto retry attempts: ' . count($logEntry['forward_attempts']);
    }
} else {
    $isForwardSuccess = api2ForwardSuccess($serverResp);
}
$logEntry['status'] = $isForwardSuccess ? 'success' : 'task_server_error';
$logEntry['response'] = compactLogResponse($serverResp ?? $result['response'], $MAX_LOG_RESPONSE_BYTES);
$logEntry['timing_ms']['total'] = elapsedMs($requestStart);
if ($logEntry['status'] !== 'success') {
    $logEntry['upload_id'] = (string)($logEntry['dump_id'] ?? '');
    if ($logEntry['upload_id'] === '') {
        $logEntry['upload_id'] = date('Ymd_His') . '_' . substr(md5($encryptedData . '|upload'), 0, 8);
    }
} elseif ($SAVE_SUCCESS_UPLOAD_DUMPS) {
    $logEntry['upload_id'] = (string)($logEntry['dump_id'] ?? '');
    if ($logEntry['upload_id'] === '') {
        $logEntry['upload_id'] = date('Ymd_His') . '_' . substr(md5($encryptedData . '|upload'), 0, 8);
    }
}

$statsTaskId = '';
if (is_array($taskInfo ?? null)) $statsTaskId = $taskInfo['ID'] ?? '';
deferred(function () use ($LOG_FILE, $logEntry, $MAX_LOGS, $STATS_DIR, $input, $apiType, $statsTaskId, $uploadDetail) {
    global $SAVE_SUCCESS_UPLOAD_DUMPS;
    appendLog($LOG_FILE, $logEntry, $MAX_LOGS);
    recordStats($STATS_DIR, $input, $apiType, $logEntry['status'], $statsTaskId);
    if ($logEntry['status'] !== 'success' || $SAVE_SUCCESS_UPLOAD_DUMPS) {
        saveUploadDump((string)($logEntry['upload_id'] ?? ''), $uploadDetail);
    }
});

if (is_array($serverResp)) {
    $serverResp['_proxy'] = [
        'submit_accepted' => $isForwardSuccess,
        'counted' => $isForwardSuccess,
        'status' => $logEntry['status'],
        'api_type' => $apiType,
    ];
    jsonResp($serverResp);
} elseif ($serverResp) {
    jsonResp($serverResp);
} else {
    jsonResp(['ok' => false, 'msg' => '任务服务器响应异常', 'raw' => $result['response']]);
}

// ===== 前端页面渲染 =====
function renderH5Page(): void {
?>
<!DOCTYPE html>
<html lang="zh-CN" class="<?php echo $isH5Mode ? 'h5-mode' : ''; ?>">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">
<meta name="format-detection" content="telephone=no,email=no,address=no">
<meta name="theme-color" content="#111827">
<title>Ajie 控制台</title>
<style>
:root{--bg:#f6f7fb;--card:#fff;--text:#111827;--muted:#6b7280;--line:#e5e7eb;--primary:#2563eb;--green:#059669;--red:#dc2626;--amber:#d97706;--shadow:0 10px 28px rgba(15,23,42,.08);--safe-bottom:env(safe-area-inset-bottom,0px)}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--text);-webkit-font-smoothing:antialiased}button,input{font:inherit}button{border:0;cursor:pointer}code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.login{min-height:100vh;display:grid;place-items:center;padding:24px;background:linear-gradient(160deg,#111827,#1f2937 55%,#0f766e)}
.login-card{width:100%;max-width:380px;background:rgba(255,255,255,.96);border-radius:18px;padding:24px;box-shadow:0 24px 70px rgba(0,0,0,.28)}
.login-card h1{margin:0 0 8px;font-size:24px}.login-card p{margin:0 0 20px;color:var(--muted);font-size:14px;line-height:1.7}.field{display:flex;flex-direction:column;gap:8px;margin-bottom:14px}.field label{font-size:13px;color:#374151;font-weight:700}.field input{height:46px;border:1px solid var(--line);border-radius:12px;padding:0 13px;background:#f9fafb;outline:none}.field input:focus{border-color:var(--primary);background:#fff}.btn{height:42px;border-radius:12px;background:#f3f4f6;color:#111827;padding:0 14px;font-weight:800}.btn.primary{width:100%;height:48px;background:var(--primary);color:#fff}.btn.small{height:34px;border-radius:10px;font-size:13px}.btn.red{background:#fee2e2;color:#991b1b}.btn.green{background:#dcfce7;color:#166534}.msg{min-height:20px;font-size:13px;color:var(--red);margin-top:10px}
.app{display:none;min-height:100vh;padding-bottom:calc(72px + var(--safe-bottom))}.top{position:sticky;top:0;z-index:10;background:rgba(246,247,251,.92);backdrop-filter:blur(14px);border-bottom:1px solid rgba(229,231,235,.8);padding:12px 14px}.top-row{display:flex;align-items:center;justify-content:space-between;gap:10px}.brand{display:flex;align-items:center;gap:10px}.logo{width:36px;height:36px;border-radius:11px;background:#111827;color:#fff;display:grid;place-items:center;font-weight:900}.brand h2{font-size:17px;margin:0}.brand div:last-child{font-size:12px;color:var(--muted);margin-top:2px}.tabs{position:fixed;left:0;right:0;bottom:0;z-index:20;display:grid;grid-template-columns:repeat(5,1fr);gap:4px;background:rgba(255,255,255,.96);border-top:1px solid var(--line);padding:8px 8px calc(8px + var(--safe-bottom));box-shadow:0 -10px 30px rgba(15,23,42,.08)}.tab{height:48px;border-radius:13px;background:transparent;color:var(--muted);font-size:12px;font-weight:800}.tab.active{background:#eff6ff;color:var(--primary)}
.page{display:none;padding:14px}.page.active{display:block}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.stat{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:14px;box-shadow:var(--shadow)}.stat .label{font-size:12px;color:var(--muted);font-weight:700}.stat .value{font-size:26px;font-weight:900;margin-top:8px;line-height:1}.stat .value.green{color:var(--green)}.stat .value.red{color:var(--red)}.stat .value.blue{color:var(--primary)}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow);overflow:hidden;margin-bottom:12px}.card-head{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:13px 14px;border-bottom:1px solid var(--line)}.card-head h3{margin:0;font-size:15px}.card-body{padding:12px 14px}.empty{padding:26px 12px;text-align:center;color:var(--muted);font-size:14px}.list{display:flex;flex-direction:column}.item{padding:12px 14px;border-bottom:1px solid #f1f5f9}.item:last-child{border-bottom:0}.item-title{font-weight:800;font-size:14px;line-height:1.5;word-break:break-word}.item-sub{margin-top:5px;color:var(--muted);font-size:12px;line-height:1.55;word-break:break-word}.tag{display:inline-flex;align-items:center;height:24px;border-radius:999px;padding:0 9px;font-size:12px;font-weight:800;background:#f3f4f6;color:#374151}.tag.green{background:#dcfce7;color:#166534}.tag.red{background:#fee2e2;color:#991b1b}.tag.blue{background:#dbeafe;color:#1d4ed8}.tag.amber{background:#fef3c7;color:#92400e}.row{display:flex;align-items:center;justify-content:space-between;gap:10px}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.muted{color:var(--muted)}.tools{display:flex;gap:8px;flex-wrap:wrap}.search{height:38px;border:1px solid var(--line);border-radius:12px;padding:0 12px;background:#f9fafb;min-width:0;width:100%}
.kv{display:grid;grid-template-columns:96px 1fr;gap:8px;font-size:13px;line-height:1.5}.kv div:nth-child(odd){color:var(--muted)}.hide{display:none!important}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.mini{height:30px;border-radius:9px;padding:0 10px;background:#f3f4f6;color:#111827;font-size:12px;font-weight:800}.mini.primary{background:#dbeafe;color:#1d4ed8}.mini.green{background:#dcfce7;color:#166534}.mini.red{background:#fee2e2;color:#991b1b}.mini.amber{background:#fef3c7;color:#92400e}.hero{margin:14px;border-radius:22px;padding:18px;background:linear-gradient(135deg,#111827,#1e3a8a 52%,#0f766e);color:#fff;box-shadow:0 24px 60px rgba(15,23,42,.22)}.hero .eyebrow{font-size:12px;opacity:.76;font-weight:800}.hero .headline{font-size:24px;font-weight:900;margin-top:8px}.hero .desc{font-size:13px;opacity:.82;margin-top:7px;line-height:1.6}.toolbar{display:flex;gap:8px;padding:12px 14px;border-bottom:1px solid var(--line);background:#fbfdff}.toolbar .search{flex:1}.modal-mask{position:fixed;inset:0;z-index:80;background:rgba(15,23,42,.5);display:grid;place-items:center;padding:18px}.modal-box{width:min(360px,100%);background:#fff;border-radius:18px;padding:20px;box-shadow:0 24px 70px rgba(0,0,0,.22)}.modal-box h3{margin:0 0 14px;font-size:18px}.modal-footer{display:flex;gap:10px;justify-content:flex-end;margin-top:16px}
@media (min-width:700px){.app{max-width:720px;margin:0 auto}.tabs{left:50%;transform:translateX(-50%);max-width:720px;border-left:1px solid var(--line);border-right:1px solid var(--line)}}
</style>
</head>
<body class="<?php echo $isH5Mode ? 'h5-mode' : ''; ?>">
<section id="login" class="login">
  <div class="login-card">
    <h1>Ajie 控制台</h1>
    <p>移动端 H5 管理入口，可直接用于 WebView 打包。</p>
    <div class="field"><label>后台密码</label><input id="keyInput" type="password" autocomplete="current-password" placeholder="输入 decrypt_proxy.php 后台密码"></div>
    <button class="btn primary" onclick="login()">进入控制台</button>
    <div id="loginMsg" class="msg"></div>
  </div>
</section>

<section id="app" class="app">
  <header class="top">
    <div class="top-row">
      <div class="brand"><div class="logo">A</div><div><h2 id="pageTitle">概览</h2><div id="subTitle">--</div></div></div>
      <div class="tools"><button class="btn small" onclick="refreshCurrent()">刷新</button><button class="btn small" onclick="openPasswordModal()">改密</button><button class="btn small red" onclick="logout()">退出</button></div>
    </div>
  </header>

  <main>
    <section id="page-home" class="page active">
      <div class="hero"><div class="eyebrow">AJIE MOBILE CONSOLE</div><div class="headline">运行态总览</div><div class="desc">查看任务、设备、账号和转发日志，常用控制可直接在手机端完成。</div></div>
      <div class="grid" id="homeStats"></div>
      <div class="card"><div class="card-head"><h3>最近日志</h3><button class="btn small" onclick="showPage('logs')">查看</button></div><div id="homeLogs" class="list"><div class="empty">加载中...</div></div></div>
    </section>
    <section id="page-tasks" class="page">
      <div class="grid" id="taskStats"></div>
      <div class="card"><div class="card-head"><h3>Lease 分组</h3></div><div id="leaseGroups" class="list"><div class="empty">加载中...</div></div></div>
      <div class="card"><div class="card-head"><h3>最近 Lease</h3></div><div id="recentLeases" class="list"><div class="empty">加载中...</div></div></div>
    </section>
    <section id="page-accounts" class="page">
      <div class="card"><div class="card-head"><h3>插件账号</h3><span id="accountCount" class="tag blue">0</span></div><div id="accountList" class="list"><div class="empty">加载中...</div></div></div>
    </section>
    <section id="page-devices" class="page">
      <div class="card"><div class="card-head"><h3>在线设备</h3><span id="onlineCount" class="tag green">0</span></div><div id="deviceList" class="list"><div class="empty">加载中...</div></div></div>
    </section>
    <section id="page-android" class="page">
      <div class="card"><div class="card-head"><h3>&#x5B89;&#x5353;&#x63A7;&#x5236;</h3><span id="androidCountH5" class="tag green">0</span></div><div id="androidControlListH5" class="list"><div class="empty">&#x52A0;&#x8F7D;&#x4E2D;...</div></div></div>
    </section>
    <section id="page-logs" class="page">
      <div class="card"><div class="card-head"><h3>转发日志</h3><button class="btn small red" onclick="clearLogs()">清空</button></div><div class="toolbar"><input class="search" id="logSearch" placeholder="搜索账号 / 状态 / 来源 / 任务" oninput="renderLogCache()"><button class="btn small" onclick="loadLogs()">刷新</button></div><div id="logList" class="list"><div class="empty">加载中...</div></div></div>
    </section>
  </main>

  <nav class="tabs">
    <button class="tab active" data-page="home" onclick="showPage('home')">概览</button>
    <button class="tab" data-page="tasks" onclick="showPage('tasks')">任务</button>
    <button class="tab" data-page="accounts" onclick="showPage('accounts')">账号</button>
    <button class="tab" data-page="devices" onclick="showPage('devices')">设备</button>
    <button class="tab" data-page="android" onclick="showPage('android')">&#x5B89;&#x5353;</button>
    <button class="tab" data-page="logs" onclick="showPage('logs')">日志</button>
  </nav>
</section>

<div class="modal-mask hide" id="passwordModal" onclick="if(event.target===this)closePasswordModal()">
  <div class="modal-box">
    <h3>修改后台密码</h3>
    <div class="field"><label>当前密码</label><input id="currentPwd" type="password" autocomplete="current-password"></div>
    <div class="field"><label>新密码</label><input id="newPwd" type="password" autocomplete="new-password" placeholder="至少 6 位"></div>
    <div class="field"><label>确认新密码</label><input id="confirmPwd" type="password" autocomplete="new-password"></div>
    <div id="passwordResult" class="msg"></div>
    <div class="modal-footer">
      <button class="btn" onclick="closePasswordModal()">取消</button>
      <button class="btn primary" style="width:auto;height:42px" onclick="submitPasswordChange()">保存</button>
    </div>
  </div>
</div>

<script>
const BASE = location.pathname;
let KEY = localStorage.getItem('h5_admin_key') || '';
let currentPage = 'home';
let logCache = [];
const titles = {home:'\u6982\u89c8',tasks:'\u4efb\u52a1\u76d1\u63a7',accounts:'\u63d2\u4ef6\u8d26\u53f7',devices:'\u5728\u7ebf\u8bbe\u5907',android:'\u5b89\u5353\u63a7\u5236',logs:'\u8f6c\u53d1\u65e5\u5fd7'};
function esc(v){return String(v??'').replace(/[&<>"]/g,s=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[s]))}
function short(v,n=90){v=String(v||'');return v.length>n?v.slice(0,n-3)+'...':v}
function deviceLabelFromLog(log){
  const vals=[log?.platform,log?.device_type,log?.device_label,log?.client,log?.client_label,log?.source,log?.device_id,log?.fingerprint_name].map(v=>String(v||'').trim()).filter(Boolean);
  const text=vals.join(' ').toLowerCase();
  const source=String(log?.source||'').toLowerCase();
  if(text.includes('android')||text.includes('\u5b89\u5353'))return '\u5b89\u5353';
  if(text.includes('ios')||text.includes('iphone')||text.includes('ipad')||source.indexOf('ios_')===0)return 'iOS';
  if(text.includes('gejie-extension')||text.includes('extension')||text.includes('\u6d4f\u89c8\u5668\u63d2\u4ef6')||text.includes('\u7f51\u9875\u63d2\u4ef6')||source.indexOf('web_')===0||source.indexOf('decoded_extension')===0)return '\u7f51\u9875\u63d2\u4ef6';
  if(text.includes('gejie-controller')||text.includes('\u4e2d\u63a7')||source.indexOf('ctrl_')===0)return '\u4e2d\u63a7';
  if(text.includes('web'))return '\u7f51\u9875\u63d2\u4ef6';
  return '';
}
function api(act,opts={}){opts.headers=Object.assign({},opts.headers||{}, {'X-Auth-Key':KEY});return fetch(BASE+'?act='+act,opts).then(r=>r.json())}
function sizeText(bytes){const n=Number(bytes||0);if(n>1073741824)return(n/1073741824).toFixed(2)+' GB';if(n>1048576)return(n/1048576).toFixed(2)+' MB';if(n>1024)return(n/1024).toFixed(1)+' KB';return n+' B'}
function ageText(s){s=Number(s||0);if(s>=3600)return Math.floor(s/3600)+'小时'+Math.floor(s%3600/60)+'分';if(s>=60)return Math.floor(s/60)+'分'+s%60+'秒';return s+'秒'}
async function login(){KEY=document.getElementById('keyInput').value.trim();if(!KEY){msg('请输入密码');return}try{const d=await api('logs&limit=1');if(d.ok===false){msg(d.msg||'登录失败');return}localStorage.setItem('h5_admin_key',KEY);openApp()}catch(e){msg('网络错误')}}
function msg(t){document.getElementById('loginMsg').textContent=t}
function logout(){localStorage.removeItem('h5_admin_key');KEY='';document.getElementById('app').style.display='none';document.getElementById('login').style.display='grid'}
function openApp(){document.getElementById('login').style.display='none';document.getElementById('app').style.display='block';refreshCurrent()}
function openPasswordModal(){document.getElementById('currentPwd').value=KEY||'';document.getElementById('newPwd').value='';document.getElementById('confirmPwd').value='';document.getElementById('passwordResult').textContent='';document.getElementById('passwordModal').classList.remove('hide');setTimeout(()=>document.getElementById('newPwd').focus(),0)}
function closePasswordModal(){document.getElementById('passwordModal').classList.add('hide')}
async function submitPasswordChange(){
  const current=document.getElementById('currentPwd').value.trim();
  const next=document.getElementById('newPwd').value.trim();
  const confirm=document.getElementById('confirmPwd').value.trim();
  const result=document.getElementById('passwordResult');
  if(!current||!next||!confirm){result.textContent='请填写当前密码和新密码';return}
  const fd=new FormData();fd.append('act','change_password');fd.append('current_password',current);fd.append('new_password',next);fd.append('confirm_password',confirm);
  result.textContent='保存中...';
  try{
    const r=await fetch(BASE,{method:'POST',headers:{'X-Auth-Key':KEY},body:fd});
    const d=await r.json();
    result.textContent=d.msg||(d.ok?'密码已修改':'修改失败');
    if(d.ok){KEY=next;localStorage.setItem('h5_admin_key',KEY);setTimeout(closePasswordModal,800)}
  }catch(e){result.textContent='网络错误'}
}
function showPage(name){currentPage=name;document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));document.getElementById('page-'+name).classList.add('active');document.querySelectorAll('.tab').forEach(b=>b.classList.toggle('active',b.dataset.page===name));document.getElementById('pageTitle').textContent=titles[name]||name;refreshCurrent()}
function refreshCurrent(){document.getElementById('subTitle').textContent=new Date().toLocaleString();if(currentPage==='home')loadHome();else if(currentPage==='tasks')loadTasks();else if(currentPage==='accounts')loadAccounts();else if(currentPage==='devices')loadDevices();else if(currentPage==='android')loadAndroidControlH5();else if(currentPage==='logs')loadLogs()}
function stat(label,value,cls=''){return `<div class="stat"><div class="label">${esc(label)}</div><div class="value ${cls}">${esc(value)}</div></div>`}
async function loadHome(){const [logs,dev,sql,acc]=await Promise.allSettled([api('logs&limit=10'),api('devices'),api('sqlite_monitor'),api('decoded_ext_accounts')]);const l=logs.value?.data||[];const devices=dev.value?.data||[];const sqlData=sql.value?.data||{};const accounts=acc.value?.data||[];document.getElementById('homeStats').innerHTML=stat('在线设备',dev.value?.online_count||0,'green')+stat('插件账号',accounts.length,'blue')+stat('Queue',sqlData.tables?.task_queue?.rows||0)+stat('Lease',sqlData.tables?.task_leases?.rows||0,'red');renderLogs(l,'homeLogs',6)}
async function loadTasks(){const d=await api('sqlite_monitor');const data=d.data||{};document.getElementById('taskStats').innerHTML=stat('Queue',data.tables?.task_queue?.rows||0,'blue')+stat('Lease',data.tables?.task_leases?.rows||0,'red')+stat('数据库',sizeText((data.files||[]).reduce((s,f)=>s+Number(f.bytes||0),0)))+stat('健康',data.metrics?.quick_check||'-','green');const groups=data.lease_groups||[];document.getElementById('leaseGroups').innerHTML=groups.length?groups.map(g=>`<div class="item"><div class="row"><div class="item-title">${esc(g.account_id)}</div><span class="tag blue">${Number(g.lease_count||0)}</span></div><div class="item-sub">${esc(short(g.runtime_scope,120))}<br>最新：${esc(g.latest_at||'-')}</div></div>`).join(''):'<div class="empty">暂无 Lease 分组</div>';const leases=data.recent_leases||[];document.getElementById('recentLeases').innerHTML=leases.length?leases.map(x=>`<div class="item"><div class="item-title">${esc(x.task_id||'-')}</div><div class="item-sub">${esc(short(x.task_url,110))}<br>账号：${esc(x.task_account_username||'-')} | ${ageText(x.age_seconds)}</div></div>`).join(''):'<div class="empty">暂无 Lease</div>'}
async function loadAccounts(){const d=await api('decoded_ext_accounts');const rows=d.data||[];document.getElementById('accountCount').textContent=rows.length;document.getElementById('accountList').innerHTML=rows.length?rows.map(a=>{const names=String(a.api1_usernames||'').split(',').map(s=>s.trim()).filter(Boolean);const shown=names.slice(0,10).join(', ');const more=Math.max(0,Number(a.api1_count||names.length)-Math.min(10,names.length));return `<div class="item"><div class="row"><div class="item-title">${esc(a.accountId)}</div><span class="tag ${a.enabled?'green':'red'}">${a.enabled?'启用':'停用'}</span></div><div class="item-sub">任务账号：${esc(shown||'-')}${more>0?' 等 '+more+' 个':''}<br>模式：${a.task_mode==='concurrent'?'并发 '+(a.task_parallelism||a.api1_count||1):'轮询'} | 可用 ${a.api1_count||0} 个${a.remark?'<br>备注：'+esc(a.remark):''}</div><div class="actions"><button class="mini ${a.enabled?'amber':'green'}" onclick="toggleAccount('${esc(a.accountId)}',${a.enabled?0:1})">${a.enabled?'停用':'启用'}</button><button class="mini primary" onclick="resetAccountToken('${esc(a.accountId)}')">重置Token</button><button class="mini red" onclick="deleteAccount('${esc(a.accountId)}')">删除</button></div></div>`}).join(''):'<div class="empty">暂无账号</div>'}
async function loadDevices(){const d=await api('devices');const rows=d.data||[];document.getElementById('onlineCount').textContent=d.online_count||0;document.getElementById('deviceList').innerHTML=rows.length?rows.map(x=>{const dk=x.device_key||x.key||'';const disabled=!!x.disabled;return `<div class="item"><div class="row"><div class="item-title">${esc(x.device_label||x.device_id||'-')}</div><span class="tag ${disabled?'red':(x.online?'green':'amber')}">${disabled?'禁用':(x.online?'在线':'离线')}</span></div><div class="item-sub">用户：${esc(x.username||'-')}${x.account_remark?'（'+esc(x.account_remark)+'）':''}<br>${esc(x.platform||'')} ${esc(x.last_seen||'')}${x.disabled_reason?'<br>原因：'+esc(x.disabled_reason):''}<br><span class="mono">${esc(short(dk,96))}</span></div><div class="actions">${dk?`<button class="mini ${disabled?'green':'red'}" onclick="toggleDevice('${esc(dk)}',${disabled?0:1})">${disabled?'启用设备':'禁用设备'}</button>`:''}<button class="mini amber" onclick="toggleDeviceUser('${esc(x.username||'')}',1)">禁用用户</button><button class="mini green" onclick="toggleDeviceUser('${esc(x.username||'')}',0)">启用用户</button></div></div>`}).join(''):'<div class="empty">暂无在线设备</div>'}
async function loadLogs(){const d=await api('logs&limit=200');logCache=d.data||[];renderLogCache()}
function renderLogCache(){const q=String(document.getElementById('logSearch')?.value||'').trim().toLowerCase();let rows=logCache;if(q){rows=rows.filter(x=>JSON.stringify(x).toLowerCase().includes(q))}renderLogs(rows,'logList',200)}
function renderLogs(rows,target,limit){rows=(rows||[]).slice(0,limit);document.getElementById(target).innerHTML=rows.length?rows.map(x=>{const status=String(x.status||'-');const cls=status==='success'?'green':(status.includes('fail')||status.includes('error')?'red':(status.includes('pending')?'amber':'blue'));const detail=x.error||x.msg||x.response_msg||x.task_url||x.forward_url||x.source||'';const deviceLabel=deviceLabelFromLog(x)||short(x.device_id||x.client_label||'',50);return `<div class="item"><div class="row"><div class="item-title">${esc(status)}</div><span class="tag ${cls}">${esc(x.api_type||'-')}</span></div><div class="item-sub">${esc(x.time||'')} | ${esc(x.username||'')} ${x.account_remark?'（'+esc(x.account_remark)+'）':''}<br>来源：${esc(x.source||'-')} | 设备：${esc(deviceLabel||'-')}${x.task_id?'<br>任务：'+esc(x.task_id):''}<br>${esc(short(detail,150))}</div></div>`}).join(''):'<div class="empty">暂无日志</div>'}
async function toggleAccount(accountId,enabled){if(!accountId)return;if(!confirm((enabled?'启用':'停用')+'账号 '+accountId+'？'))return;const d=await api('decoded_ext_account_toggle&accountId='+encodeURIComponent(accountId)+'&enabled='+enabled);if(d.ok===false)alert(d.msg||'操作失败');await loadAccounts()}
async function resetAccountToken(accountId){if(!accountId)return;if(!confirm('重置 '+accountId+' 的插件 Token？旧插件配置会失效。'))return;const d=await api('decoded_ext_account_token&accountId='+encodeURIComponent(accountId));if(d.ok===false)alert(d.msg||'操作失败');else alert('Token 已重置，请重新复制配置');await loadAccounts()}
async function deleteAccount(accountId){if(!accountId)return;if(!confirm('删除账号 '+accountId+'？此操作不可撤销。'))return;const d=await api('decoded_ext_account_delete&accountId='+encodeURIComponent(accountId));if(d.ok===false)alert(d.msg||'删除失败');await loadAccounts()}
async function toggleDevice(deviceKey,disabled){if(!deviceKey)return;let reason='';if(disabled){reason=prompt('禁用原因', 'H5控制台禁用')||''}const d=await api('device_toggle&device_key='+encodeURIComponent(deviceKey)+'&disabled='+disabled+'&reason='+encodeURIComponent(reason));if(d.ok===false)alert(d.msg||'操作失败');await loadDevices()}
async function toggleDeviceUser(username,disabled){if(!username)return alert('缺少用户名');let reason='';if(disabled){reason=prompt('禁用该用户所有在线设备的原因', 'H5控制台禁用用户')||'';if(!confirm('禁用用户 '+username+' 的所有设备？'))return}else{if(!confirm('启用用户 '+username+' 的所有设备？'))return}const d=await api('device_toggle_user&username='+encodeURIComponent(username)+'&disabled='+disabled+'&reason='+encodeURIComponent(reason));if(d.ok===false)alert(d.msg||'操作失败');else alert(d.msg||'操作完成');await loadDevices()}
async function clearLogs(){if(!confirm('确定清空日志和缓存数据？'))return;const d=await api('clear');alert(d.msg||'已清空');loadLogs()}
function isAjieAndroidDeviceH5(x){const client=String(x&&x.client||'').toLowerCase();const label=String(x&&x.client_label||'').toLowerCase();return client==='ajie-android'||(label.includes('ajie')&&label.includes('android'))}
async function setAndroidCommandH5(dk,cmd){if(!dk)return;await api('android_device_command&device_key='+encodeURIComponent(dk)+'&command='+encodeURIComponent(cmd));await loadAndroidControlH5()}
async function loadAndroidControlH5(){const d=await api('devices');const rows=(d.data||[]).filter(isAjieAndroidDeviceH5);const cnt=document.getElementById('androidCountH5');const el=document.getElementById('androidControlListH5');if(cnt)cnt.textContent=rows.length;if(!el)return;if(!rows.length){el.innerHTML='<div class="empty">\u6682\u65e0\u5b89\u5353 App \u8bbe\u5907</div>';return}el.innerHTML=rows.map(x=>{const dk=x.device_key||x.key||'';const disabled=!!x.disabled;const sess=(x.has_android_session||x.android_has_cookie)?'\u5df2\u540c\u6b65':'\u672a\u540c\u6b65';const task=x.android_has_task_token?'\u4efb\u52a1\u5df2\u767b\u5f55':'\u4efb\u52a1\u672a\u767b\u5f55';return `<div class="item"><div class="row"><div class="item-title">${esc(x.username||'-')}</div><span class="tag ${disabled?'red':(x.online?'green':'amber')}">${disabled?'\u7981\u7528':(x.online?'\u5728\u7ebf':'\u79bb\u7ebf')}</span></div><div class="item-sub">\u8bbe\u5907\uff1a${esc(x.device_label||x.device_id||'-')}<br>\u4f1a\u8bdd\uff1a${sess} | ${task} | \u547d\u4ee4\uff1a${esc(x.android_command||'run')}<br>\u5fc3\u8df3\uff1a${esc(x.last_seen||'-')}</div><div class="actions"><button class="mini green" onclick="setAndroidCommandH5('${esc(dk)}','run')">\u542f\u52a8</button><button class="mini amber" onclick="setAndroidCommandH5('${esc(dk)}','pause')">\u6682\u505c</button><button class="mini primary" onclick="setAndroidCommandH5('${esc(dk)}','sync_session')">\u540c\u6b65\u4f1a\u8bdd</button><button class="mini red" onclick="setAndroidCommandH5('${esc(dk)}','clear_session')">\u6e05\u4f1a\u8bdd</button></div></div>`}).join('')}
if(KEY){api('logs&limit=1').then(d=>{if(d.ok===false)logout();else openApp()}).catch(()=>logout())}
</script>
</body>
</html>
<?php
}

function renderParallelControlPage(): void {
$token = trim((string)($_GET['t'] ?? ''));
$tokenJson = json_encode($token, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Referrer-Policy: no-referrer');
header('X-Robots-Tag: noindex, nofollow');
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">
<title>并发控制</title>
<style>
:root{--bg:#f6f8fb;--card:#fff;--text:#172033;--muted:#6b778c;--border:#dfe6f0;--primary:#2563eb;--primary2:#14b8a6;--danger:#ef4444;--ok:#10b981;--warn:#f59e0b;--shadow:0 18px 44px rgba(23,32,51,.12);--radius:18px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB",Arial,sans-serif}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:var(--bg);color:var(--text)}body{font-size:15px;-webkit-font-smoothing:antialiased}
.page{min-height:100vh;padding:24px 16px calc(28px + env(safe-area-inset-bottom));display:flex;align-items:center;justify-content:center;background:linear-gradient(180deg,#eef6ff 0%,#f6f8fb 42%,#eefaf7 100%)}
.shell{width:min(100%,520px)}
.hero{padding:4px 2px 18px}.eyebrow{display:inline-flex;align-items:center;gap:8px;padding:7px 11px;border-radius:999px;background:#e8f3ff;color:#1d4ed8;font-size:12px;font-weight:800}.eyebrow::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 4px rgba(16,185,129,.14)}
h1{font-size:30px;line-height:1.1;margin:16px 0 8px;letter-spacing:0;font-weight:850}.sub{color:var(--muted);line-height:1.7;margin:0}
.panel{background:rgba(255,255,255,.92);border:1px solid rgba(223,230,240,.9);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden;backdrop-filter:blur(12px)}
.top{padding:18px 18px 14px;display:grid;gap:12px;border-bottom:1px solid var(--border)}.account{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.account h2{font-size:18px;margin:0 0 5px;font-weight:800;word-break:break-word}.remark{margin:0;color:var(--muted);font-size:13px;line-height:1.5}.badge{flex:0 0 auto;border-radius:999px;padding:6px 10px;font-size:12px;font-weight:800;background:#ecfdf5;color:#047857;border:1px solid #a7f3d0}.badge.off{background:#fef2f2;color:#b91c1c;border-color:#fecaca}
.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}.metric{border:1px solid var(--border);border-radius:14px;padding:11px 10px;background:#f8fafc;min-width:0}.metric b{display:block;font-size:20px;line-height:1.15}.metric span{display:block;color:var(--muted);font-size:11px;font-weight:700;margin-top:4px;white-space:nowrap}
.body{padding:18px}.control{display:grid;gap:16px}.value-row{display:flex;align-items:flex-end;justify-content:space-between;gap:14px}.value{font-size:52px;font-weight:900;line-height:.9;color:#0f172a}.unit{font-size:14px;color:var(--muted);font-weight:700;margin-left:4px}.limit{color:var(--muted);font-size:13px;line-height:1.5;text-align:right}
input[type=range]{width:100%;accent-color:var(--primary);height:34px}input[type=number]{width:100%;height:48px;border:1px solid var(--border);border-radius:14px;padding:0 14px;font-size:18px;font-weight:800;color:var(--text);background:#f8fafc;outline:none}input[type=number]:focus{border-color:var(--primary);box-shadow:0 0 0 4px rgba(37,99,235,.12);background:#fff}
.names{display:flex;flex-wrap:wrap;gap:7px;margin-top:2px}.chip{max-width:100%;border:1px solid #dbeafe;background:#eff6ff;color:#1e40af;border-radius:999px;padding:6px 9px;font-size:12px;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.chip.more{background:#fffbeb;color:#92400e;border-color:#fde68a}
.actions{display:grid;grid-template-columns:1fr;gap:10px;margin-top:18px}.btn{height:50px;border:0;border-radius:14px;font-size:16px;font-weight:850;color:#fff;background:linear-gradient(135deg,var(--primary),var(--primary2));box-shadow:0 12px 24px rgba(37,99,235,.22);cursor:pointer}.btn:disabled{opacity:.55;cursor:not-allowed;box-shadow:none}.msg{min-height:22px;margin-top:12px;font-size:13px;color:var(--muted);line-height:1.6}.msg.ok{color:#047857}.msg.err{color:#b91c1c}.loading{padding:42px 18px;text-align:center;color:var(--muted);font-weight:700}.error{padding:24px 18px;color:#b91c1c;line-height:1.7;background:#fff7f7;border-top:1px solid #fecaca}
.shell{width:min(100%,980px)}.layout{display:grid;grid-template-columns:minmax(0,520px) minmax(300px,390px);gap:22px;align-items:start}.daily-panel{background:rgba(255,255,255,.92);border:1px solid rgba(223,230,240,.9);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden;backdrop-filter:blur(12px)}.daily-head{padding:18px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;gap:12px;align-items:flex-start}.daily-title{font-size:18px;font-weight:850;margin:0}.daily-sub{margin:6px 0 0;color:var(--muted);font-size:12px;line-height:1.5}.daily-live{flex:0 0 auto;display:inline-flex;align-items:center;gap:7px;border:1px solid #bfdbfe;background:#eff6ff;color:#1d4ed8;border-radius:999px;padding:6px 10px;font-size:12px;font-weight:800}.daily-live:before{content:"";width:7px;height:7px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 4px rgba(16,185,129,.14)}.daily-body{padding:16px 18px 18px}.daily-total{display:grid;grid-template-columns:1fr 1fr;gap:8px}.daily-card{border:1px solid var(--border);border-radius:14px;padding:12px;background:#f8fafc;min-width:0}.daily-card span{display:block;color:var(--muted);font-size:12px;font-weight:750}.daily-card b{display:block;margin-top:7px;font-size:24px;line-height:1.1}.daily-card.ok b{color:#047857}.daily-card.bad b{color:#e11d48}.daily-line{height:8px;border-radius:999px;background:#edf2f7;overflow:hidden;margin:14px 0 10px}.daily-line i{display:block;height:100%;width:var(--w,0%);background:linear-gradient(90deg,var(--primary),var(--primary2));border-radius:999px}.daily-meta{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px}.daily-pill{display:inline-flex;align-items:center;gap:5px;border:1px solid var(--border);background:#fff;border-radius:999px;padding:6px 9px;font-size:12px;color:var(--muted);font-weight:750}.daily-pill b{color:var(--text)}.daily-list{display:grid;gap:8px;max-height:310px;overflow:auto;padding-right:2px}.daily-row{border:1px solid var(--border);border-radius:14px;background:#fff;padding:10px 11px}.daily-row-top{display:flex;justify-content:space-between;gap:10px;margin-bottom:8px}.daily-user{font-size:13px;font-weight:850;word-break:break-all}.daily-tag{font-size:11px;font-weight:800;color:#047857;background:#ecfdf5;border:1px solid #a7f3d0;border-radius:999px;padding:3px 7px;max-width:42%;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.daily-row-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:6px}.daily-mini{background:#f8fafc;border-radius:10px;padding:7px 6px}.daily-mini span{display:block;font-size:10px;color:var(--muted);font-weight:750}.daily-mini b{display:block;margin-top:3px;font-size:13px}.daily-empty{padding:28px 12px;text-align:center;color:var(--muted);font-size:13px;border:1px dashed var(--border);border-radius:14px;background:#fff}.daily-warn{margin-top:10px;color:#92400e;background:#fffbeb;border:1px solid #fde68a;border-radius:12px;padding:9px 10px;font-size:12px;line-height:1.5}
.daily-mini b.ok{color:#047857}.daily-mini b.bad{color:#e11d48}
.page{
  align-items:flex-start;
  padding:54px 20px calc(40px + env(safe-area-inset-bottom));
  background:
    linear-gradient(180deg,rgba(37,99,235,.10) 0%,rgba(255,255,255,0) 260px),
    linear-gradient(135deg,rgba(20,184,166,.10) 0%,rgba(255,255,255,0) 520px),
    #f4f8fb;
}
.shell{width:min(100%,1120px)}
.hero{
  padding:0 2px 22px;
  max-width:760px;
}
.eyebrow{
  background:rgba(239,246,255,.92);
  border:1px solid #dbeafe;
  box-shadow:0 8px 18px rgba(37,99,235,.07);
}
h1{
  font-size:36px;
  margin:18px 0 10px;
  letter-spacing:0;
}
.sub{max-width:720px;font-size:14px}
.layout{
  grid-template-columns:minmax(0,560px) minmax(360px,1fr);
  gap:24px;
}
.panel,.daily-panel{
  border-radius:8px;
  border:1px solid rgba(203,213,225,.82);
  background:rgba(255,255,255,.94);
  box-shadow:0 26px 70px rgba(15,23,42,.11);
}
.top{
  padding:20px;
  gap:16px;
  background:linear-gradient(180deg,#fff,#f8fbff);
}
.account h2,.daily-title{font-size:20px;font-weight:900}
.badge,.daily-live{
  border-radius:8px;
  padding:7px 10px;
}
.metrics{gap:10px}
.metric{
  border-radius:8px;
  padding:13px 12px;
  background:#f8fafc;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.78);
}
.metric b{font-size:23px}
.body{padding:24px 20px 22px}
.value-row{
  align-items:center;
  padding:8px 2px 0;
}
.value{
  font-size:58px;
  color:#111827;
}
.limit{
  padding:10px 12px;
  border:1px solid var(--border);
  border-radius:8px;
  background:#f8fafc;
}
input[type=range]{height:28px}
input[type=number]{
  height:52px;
  border-radius:8px;
  background:#f8fafc;
}
.names{
  gap:8px;
  padding:2px 0 0;
}
.chip{
  border-radius:8px;
  padding:7px 10px;
  background:#eef6ff;
}
.btn{
  height:54px;
  border-radius:8px;
  box-shadow:0 18px 32px rgba(37,99,235,.20);
}
.daily-head{
  padding:20px 20px 16px;
  background:linear-gradient(180deg,#fff,#f8fbff);
}
.daily-sub{font-size:13px}
.daily-body{padding:18px 20px 20px}
.daily-total{
  grid-template-columns:repeat(4,minmax(0,1fr));
  gap:10px;
}
.daily-card{
  border-radius:8px;
  padding:13px 11px;
  background:#f8fafc;
  position:relative;
  overflow:hidden;
}
.daily-card:before{
  content:"";
  position:absolute;
  left:0;top:0;bottom:0;width:3px;
  background:#2563eb;
}
.daily-card.ok:before{background:#10b981}
.daily-card.bad:before{background:#e11d48}
.daily-card b{font-size:18px;line-height:1.05}
.daily-line{height:9px;margin:16px 0 12px;background:#e8eef6}
.daily-pill{
  border-radius:8px;
  background:#fff;
  padding:7px 10px;
}
.daily-list{
  gap:10px;
  max-height:344px;
  scrollbar-width:thin;
  scrollbar-color:#cbd5e1 transparent;
}
.daily-list::-webkit-scrollbar{width:7px}
.daily-list::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:999px}
.daily-list::-webkit-scrollbar-track{background:transparent}
.daily-row{
  border-radius:8px;
  padding:12px;
  box-shadow:0 8px 18px rgba(15,23,42,.04);
}
.daily-row-top{align-items:center}
.daily-user{font-size:14px}
.daily-tag{border-radius:8px;max-width:46%}
.daily-row-grid{gap:8px}
.daily-mini{
  border-radius:8px;
  border:1px solid #edf2f7;
  padding:9px 8px;
}
.daily-mini b{font-size:14px}
.daily-warn{border-radius:8px}
@media(max-width:900px){.page{align-items:flex-start}.layout{grid-template-columns:1fr}.shell{width:min(100%,560px)}}
@media(max-width:420px){.page{align-items:flex-start;padding:18px 12px calc(22px + env(safe-area-inset-bottom));background-attachment:scroll}h1{font-size:26px}.metrics{grid-template-columns:1fr 1fr}.metric:last-child{grid-column:1/-1}.value{font-size:46px}.top,.body,.daily-head,.daily-body{padding-left:14px;padding-right:14px}.limit{text-align:left}.value-row{display:grid;gap:8px}.account{display:grid}.badge{justify-self:start}.daily-total{grid-template-columns:1fr 1fr}.daily-row-grid{grid-template-columns:repeat(2,1fr)}}
.page{
  min-height:100vh;
  display:block;
  padding:40px 24px 56px;
  background:url('bj.jpeg') center center/cover no-repeat fixed;
}
.shell{
  width:min(100%,1280px);
  margin:0 auto;
}
.hero{
  padding:0 0 22px;
}
.eyebrow{
  height:28px;
  padding:0 11px;
  border-radius:8px;
  background:#eff6ff;
  border:1px solid #dbeafe;
  color:#1d4ed8;
  box-shadow:none;
}
h1{
  margin:18px 0 8px;
  font-size:34px;
  line-height:1.08;
  font-weight:900;
}
.sub{
  max-width:none;
  font-size:14px;
}
.layout{
  display:grid;
  grid-template-columns:minmax(0,1.15fr) minmax(0,1fr) minmax(0,1fr);
  gap:24px;
  align-items:start;
}
.layout > *{
  min-width:0;
}
.panel,.daily-panel{
  width:100%;
  border-radius:8px;
  border:1px solid #d8e1ee;
  background:#fff;
  box-shadow:0 18px 48px rgba(15,23,42,.09);
  overflow:hidden;
}
.top,.daily-head{
  min-height:110px;
  padding:20px;
  border-bottom:1px solid #d8e1ee;
  background:#fff;
}
.daily-head{
  display:flex;
  align-items:flex-start;
  justify-content:space-between;
}
.account{
  min-height:34px;
  align-items:flex-start;
}
.account h2,.daily-title{
  margin:0;
  font-size:20px;
  line-height:1.25;
  font-weight:900;
}
.remark,.daily-sub{
  margin-top:7px;
  font-size:12px;
  line-height:1.45;
}
.badge,.daily-live{
  height:32px;
  display:inline-flex;
  align-items:center;
  justify-content:center;
  border-radius:8px;
  padding:0 10px;
  font-size:12px;
}
.metrics,.daily-total{
  display:grid;
  gap:10px;
}
.metrics{grid-template-columns:repeat(3,minmax(0,1fr))}
.daily-total{grid-template-columns:repeat(4,minmax(0,1fr))}
.metric,.daily-card{
  height:78px;
  border:1px solid #dbe4f0;
  border-radius:8px;
  padding:13px 14px;
  background:#f8fafc;
  box-shadow:none;
}
.metric b,.daily-card b{
  display:block;
  margin:0;
  font-size:18px;
  line-height:1.05;
  font-weight:900;
  font-variant-numeric:tabular-nums;
}
.metric span,.daily-card span{
  display:block;
  margin-top:7px;
  color:#667085;
  font-size:11px;
  line-height:1.2;
  font-weight:750;
}
.daily-card:before{display:none}
.body,.daily-body{
  padding:22px 20px 24px;
}
.control{
  display:grid;
  gap:18px;
}
.value-row{
  display:grid;
  grid-template-columns:1fr 118px;
  gap:16px;
  align-items:center;
  padding:0;
}
.value{
  font-size:56px;
  line-height:1;
  font-weight:950;
  font-variant-numeric:tabular-nums;
}
.unit{
  margin-left:6px;
  font-size:14px;
}
.limit{
  min-height:62px;
  display:flex;
  align-items:center;
  justify-content:flex-end;
  text-align:right;
  padding:10px 12px;
  border-radius:8px;
  background:#f8fafc;
  border:1px solid #dbe4f0;
}
input[type=range]{
  height:28px;
  margin:0;
}
input[type=number]{
  height:52px;
  border-radius:8px;
  border-color:#dbe4f0;
  background:#f8fafc;
}
.names{
  display:flex;
  gap:8px;
  margin:0;
  min-height:70px;
  align-content:flex-start;
}
.chip{
  height:30px;
  display:inline-flex;
  align-items:center;
  border-radius:8px;
  padding:0 10px;
  background:#eff6ff;
  border-color:#dbeafe;
}
.actions{
  margin-top:0;
}
.btn{
  height:54px;
  border-radius:8px;
}
.msg{
  margin-top:10px;
}
.daily-line{
  height:8px;
  margin:16px 0 12px;
  border-radius:999px;
}
.daily-meta{
  display:grid;
  grid-template-columns:repeat(3,minmax(0,1fr));
  gap:8px;
  margin-bottom:14px;
}
.daily-pill{
  height:32px;
  min-width:0;
  justify-content:center;
  border-radius:8px;
  padding:0 9px;
  background:#fff;
  white-space:nowrap;
  overflow:hidden;
  text-overflow:ellipsis;
}
.daily-pill b{
  min-width:0;
  overflow:hidden;
  text-overflow:ellipsis;
}
.daily-list{
  display:grid;
  gap:10px;
  max-height:344px;
  padding-right:4px;
}
.daily-row{
  border-radius:8px;
  padding:12px;
  border-color:#dbe4f0;
  box-shadow:none;
}
.daily-row-top{
  height:28px;
  margin-bottom:10px;
  align-items:center;
}
.daily-user{
  min-width:0;
  font-size:14px;
  line-height:1.2;
}
.daily-tag{
  height:26px;
  display:inline-flex;
  align-items:center;
  border-radius:8px;
  max-width:150px;
  padding:0 9px;
}
.daily-tag.ok{background:#ecfdf5;border:1px solid #a7f3d0;color:#047857}
.daily-tag.bad{background:#fef2f2;border:1px solid #fecaca;color:#b91c1c}
.daily-tag.warn{background:#fffbeb;border:1px solid #fde68a;color:#92400e}
.daily-tag.info{background:#eff6ff;border:1px solid #bfdbfe;color:#1d4ed8}
.daily-row-grid{
  display:grid;
  grid-template-columns:repeat(4,minmax(0,1fr));
  gap:8px;
}
.daily-mini{
  height:56px;
  border:1px solid #edf2f7;
  border-radius:8px;
  padding:8px 9px;
}
.daily-mini span{
  font-size:10px;
  line-height:1.1;
}
.daily-mini b{
  margin-top:5px;
  font-size:14px;
  line-height:1.1;
  font-variant-numeric:tabular-nums;
  overflow-wrap:anywhere;
  word-break:break-word;
}
.daily-warn{
  margin-top:12px;
  border-radius:8px;
  overflow-wrap:anywhere;
  word-break:break-word;
}
.live-panel .daily-meta{
  grid-template-columns:repeat(2,minmax(0,1fr));
}
.live-panel .device-meta{
  grid-template-columns:1fr;
}
.live-panel .device-meta .daily-pill{
  justify-content:flex-start;
}
.live-panel .daily-total{
  gap:6px;
}
.live-panel .daily-card{
  height:70px;
  padding:10px 11px;
}
.live-panel .daily-card b{
  font-size:20px;
}
.live-panel .daily-pill{
  height:28px;
  font-size:11px;
}
.live-panel .daily-meta{
  margin-bottom:10px;
  gap:6px;
}
.live-panel .daily-row-grid{
  grid-template-columns:repeat(2,minmax(0,1fr));
  gap:6px;
}
.live-panel .daily-mini{
  height:auto;
  min-height:48px;
  padding:7px 8px;
  overflow:hidden;
}
.live-panel .daily-mini span{
  font-size:9px;
}
.live-panel .daily-mini b{
  margin-top:4px;
  font-size:12px;
}
.live-panel .daily-warn{
  margin-top:8px;
  padding:8px 9px;
}
.live-log-entry{
  border:1px solid #dbe4f0;
  border-radius:8px;
  background:#fff;
  padding:12px;
  font-size:12px;
}
.live-log-head{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:8px;
  margin-bottom:7px;
}
.live-log-title{
  min-width:0;
  color:#111827;
  font-size:14px;
  line-height:1.25;
  font-weight:900;
  word-break:break-word;
}
.live-log-sub{
  color:#667085;
  font-size:11px;
  line-height:1.5;
  margin-bottom:9px;
  overflow-wrap:anywhere;
  word-break:break-word;
}
.live-ip{
  margin-left:8px;
  color:#94a3b8;
}
.live-log-grid{
  display:grid;
  grid-template-columns:repeat(2,minmax(0,1fr));
  gap:6px;
}
.live-mini{
  min-height:46px;
  border:1px solid #edf2f7;
  border-radius:8px;
  background:#f8fafc;
  padding:7px 8px;
  overflow:hidden;
}
.live-mini span{
  display:block;
  color:#667085;
  font-size:9px;
  line-height:1.1;
  font-weight:750;
}
.live-mini b{
  display:block;
  margin-top:4px;
  color:#111827;
  font-size:12px;
  line-height:1.2;
  font-weight:850;
  overflow-wrap:anywhere;
  word-break:break-word;
}
.live-log-detail{
  margin-top:9px;
  color:#64748b;
  line-height:1.7;
  overflow-wrap:anywhere;
  word-break:break-word;
}
.live-log-detail code{
  display:inline-block;
  max-width:100%;
  margin:0 4px 4px 2px;
  padding:2px 6px;
  border-radius:5px;
  background:#f1f5f9;
  color:#334155;
  font-size:11px;
  vertical-align:middle;
  overflow-wrap:anywhere;
  word-break:break-word;
}
.live-note{
  color:#e11d48;
  font-size:11px;
  font-weight:800;
}
.live-resp{
  margin-top:8px;
  padding:8px 10px;
  border:1px solid #fde68a;
  border-radius:8px;
  background:#fffbeb;
  color:#92400e;
  font-size:11px;
  line-height:1.55;
  white-space:pre-wrap;
  overflow-wrap:anywhere;
  word-break:break-word;
}
.live-resp.danger{
  border-color:#fecaca;
  background:#fef2f2;
  color:#b91c1c;
}
@media(max-width:980px){
  .page{padding:24px 14px 36px}
  .layout{grid-template-columns:1fr}
  .shell{width:min(100%,620px)}
}
@media(max-width:520px){
  h1{font-size:30px}
  .top,.daily-head,.body,.daily-body{padding-left:14px;padding-right:14px}
  .top,.daily-head{min-height:auto}
  .metrics{grid-template-columns:repeat(3,minmax(0,1fr))}
  .daily-total{grid-template-columns:repeat(2,minmax(0,1fr))}
  .metric,.daily-card{height:74px;padding:12px}
  .value-row{grid-template-columns:1fr}
  .limit{justify-content:flex-start;text-align:left}
  .daily-meta{grid-template-columns:repeat(2,minmax(0,1fr))}
  .daily-row-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
}
.panel,.daily-panel{
  height:612px;
  min-height:0;
}
.live-panel{
  height:612px;
}
.daily-panel{
  display:grid;
  grid-template-rows:auto minmax(0,1fr);
  overflow:hidden;
}
.daily-body{
  min-height:0;
  overflow:hidden;
}
.daily-list{
  min-height:0;
  max-height:none;
  overflow:auto;
}
.panel{
  display:grid;
  grid-template-rows:auto minmax(0,1fr);
}
.body{
  min-height:0;
  display:flex;
  flex-direction:column;
  padding-bottom:34px;
}
.control{
  flex:1;
}
.actions{
  margin-top:26px;
  display:flex;
  justify-content:center;
}
.btn{
  width:min(100%,520px);
}
.daily-body{
  display:grid;
  grid-template-rows:auto auto minmax(0,1fr) auto;
  row-gap:12px;
}
.live-panel .daily-body{
  grid-template-rows:auto minmax(0,1fr) !important;
  row-gap:10px;
}
.daily-line{
  margin:0;
}
.daily-meta{
  margin:0;
}
.daily-list{
  min-height:0;
  height:100%;
  overscroll-behavior:contain;
  -webkit-overflow-scrolling:touch;
}
.live-panel .daily-list{
  height:100%;
  max-height:none;
  overflow:auto;
  padding-right:4px;
}
.daily-body{
  height:calc(612px - 110px);
  display:grid !important;
  grid-template-rows:auto auto auto minmax(0,1fr) auto !important;
  overflow:hidden !important;
}
.daily-list{
  height:auto !important;
  min-height:0 !important;
  max-height:none !important;
  overflow-y:auto !important;
  overflow-x:hidden;
}
@media(max-width:980px){
  .panel,.daily-panel{
    height:auto;
  }
  .live-panel{
    height:auto;
  }
  .daily-list{
    max-height:344px;
  }
  .daily-body{
    height:auto;
  }
}
</style>
</head>
<body>
<main class="page">
  <section class="shell">
    <div class="hero">
      <div class="eyebrow">用户自助</div>
      <h1>并发控制</h1>
      <p class="sub">这里的数量按单个插件实例生效，保存后插件会按新的并发数拉取任务。</p>
    </div>
    <div class="layout">
      <div class="panel" id="panel"><div class="loading">正在读取配置...</div></div>
      <aside class="daily-panel" id="dailyPanel">
        <div class="daily-head">
          <div>
            <h2 class="daily-title">当日任务数量</h2>
            <p class="daily-sub">按当前可用任务账号统计，自动实时更新。</p>
          </div>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;justify-content:flex-end">
            <button type="button" class="daily-live" style="border:0;cursor:pointer" onclick="loadDailyStats(true)">刷新</button>
            <span class="daily-live" id="dailyCountdown">15s</span>
          </div>
        </div>
        <div class="daily-body">
          <div class="loading">正在读取今日数据...</div>
        </div>
      </aside>
      <aside class="daily-panel live-panel" id="livePanel">
        <div class="daily-head">
          <div>
            <h2 class="daily-title">实时转发日志</h2>
            <p class="daily-sub">仅显示当前用户的提交 / 转发日志。</p>
          </div>
          <span class="daily-live" id="liveCountdown">12s</span>
        </div>
        <div class="daily-body">
          <div class="loading">正在读取实时数据...</div>
        </div>
      </aside>
    </div>
  </section>
</main>
<script>
const TOKEN = <?php echo $tokenJson ?: '""'; ?>;
const panel = document.getElementById('panel');
const dailyPanel = document.getElementById('dailyPanel');
const dailyCountdown = document.getElementById('dailyCountdown');
const livePanel = document.getElementById('livePanel');
const liveCountdown = document.getElementById('liveCountdown');
const DAILY_REFRESH_SECONDS = 15;
const LIVE_REFRESH_SECONDS = 12;
let current = null;
let dailyRemain = DAILY_REFRESH_SECONDS;
let dailyLoading = false;
let liveRemain = LIVE_REFRESH_SECONDS;
let liveLoading = false;
function text(v){return v===undefined||v===null||v===''?'-':String(v)}
function apiUrl(act){return '?act='+act+'&t='+encodeURIComponent(TOKEN)}
function clamp(v,min,max){v=parseInt(v,10)||min;return Math.max(min,Math.min(max,v))}
function esc(v){return text(v).replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
function num(v){return new Intl.NumberFormat('zh-CN').format(parseInt(v||0,10)||0)}
function pct(part,total){part=Number(part||0);total=Number(total||0);return total>0?Math.max(0,Math.min(100,part/total*100)):0}
function rate(part,total){const v=pct(part,total);return v?(Math.round(v*10)/10).toString().replace(/\.0$/,'')+'%':'0%'}
function today(){const d=new Date();return new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,10)}
function renderError(msg){panel.innerHTML='<div class="error">'+text(msg)+'</div>'}
function renderDailyError(msg){dailyPanel.querySelector('.daily-body').innerHTML='<div class="daily-empty">'+esc(msg||'当日任务数量读取失败')+'</div>'}
function renderDailyCountdown(){
  if(!dailyCountdown)return;
  dailyCountdown.textContent=dailyLoading?'更新中':(dailyRemain+'s');
}
function renderLiveError(msg){livePanel.querySelector('.daily-body').innerHTML='<div class="daily-empty">'+esc(msg||'实时转发数据读取失败')+'</div>'}
function renderLiveCountdown(){
  if(!liveCountdown)return;
  liveCountdown.textContent=liveLoading?'更新中':(liveRemain+'s');
}
function liveStatusClass(status){
  const v=String(status||'').toLowerCase();
  if(v==='success') return 'ok';
  if(v.includes('fail')||v.includes('error')) return 'bad';
  if(v.includes('pending')||v.includes('wait')||v.includes('relay')) return 'warn';
  return 'info';
}
function liveApiLabel(apiType){
  const n=parseInt(apiType||0,10)||0;
  if(n===1) return '聚星';
  if(n===2) return '调速';
  return n?('API '+n):'日志';
}
function liveClientLabel(log){
  const values=[
    log&&log.platform,
    log&&log.device_type,
    log&&log.device_label,
    log&&log.client,
    log&&log.client_label,
    log&&log.source,
    log&&log.device_id,
    log&&log.fingerprint_name
  ].map(v=>String(v||'').trim()).filter(Boolean);
  const text=values.join(' ').toLowerCase();
  if(text.includes('android')||text.includes('\u5b89\u5353')) return '\u5b89\u5353';
  if(text.includes('ios')||text.includes('iphone')||text.includes('ipad')) return 'iOS';
  if(text.includes('gejie-extension')||text.includes('extension')||text.includes('\u6d4f\u89c8\u5668\u63d2\u4ef6')||text.includes('\u7f51\u9875\u63d2\u4ef6')) return '\u7f51\u9875\u63d2\u4ef6';
  if(text.includes('gejie-controller')||text.includes('\u4e2d\u63a7')||text.includes('ctrl_')) return '\u4e2d\u63a7';
  if(text.includes('web')) return '\u7f51\u9875\u63d2\u4ef6';
  const source=String(log && log.source || '').toLowerCase();
  if(log && log.client_label) return String(log.client_label);
  if(source.indexOf('ctrl_')===0) return '中控';
  if(source.indexOf('web_')===0) return '网页插件';
  if(source.indexOf('decoded_extension')===0) return '插件';
  if(source.indexOf('ios_')===0) return 'iOS';
  return '';
}
function liveText(v){return v===undefined||v===null||v===''?'-':String(v)}
function liveRespPreview(v, max){
  const text = typeof v==='string' ? v : JSON.stringify(v, null, 2);
  return text.length>max ? text.slice(0, max) + '...' : text;
}
function renderLive(data){
  const body=livePanel.querySelector('.daily-body');
  const logs=Array.isArray(data.logs)?data.logs:[];
  const online=parseInt(data.online_device_count||0,10)||0;
  const accountLabel=data.remark||data.accountId||'-';
  const logHtml=logs.length?logs.map(log=>{
    const status=liveText(log.status||log.source||'-');
    const apiLabel=liveApiLabel(log.api_type);
    const clientLabel=liveClientLabel(log);
    const subtitle = `${liveText(log.time||'')} | ${liveText(log.username||'')}${log.account_remark?' ('+liveText(log.account_remark)+')':''}`;
    const detailBits=[];
    if(clientLabel) detailBits.push(`<b>\u8bbe\u5907:</b><code>${esc(clientLabel)}</code>`);
    if(log.username) detailBits.push(`<b>用户:</b><code>${esc(log.username)}</code>`);
    if(log.account_remark) detailBits.push(`<span class="live-note">${esc(log.account_remark)}</span>`);
    if(log.group_id) detailBits.push(`<b>组:</b><code>${esc(log.group_id)}</code>`);
    if(log.task_id) detailBits.push(`<b>任务:</b><code>${esc(log.task_id)}</code>`);
    if(log.submit_id) detailBits.push(`<b>提交:</b><code>${esc(log.submit_id)}</code>`);
    if(log.forward_url) detailBits.push(`<b>转发:</b><code>${esc(log.forward_url)}</code>`);
    if(log.encrypted_len) detailBits.push(`<b>加密:</b><code>${esc((Number(log.encrypted_len||0)/1024).toFixed(1)+'KB')}</code>`);
    if(log.decrypted_len) detailBits.push(`<b>解密:</b><code>${esc((Number(log.decrypted_len||0)/1024).toFixed(1)+'KB')}</code>`);
    if(log.extract_from) detailBits.push(`<b>提取:</b><code>${esc(log.extract_from)}</code>`);
    if(log.timing_ms){
      const t=log.timing_ms||{};
      detailBits.push(`<b>timing:</b><code>total ${(t.total||0)}ms / decrypt ${(t.aes_decrypt||0)} / parse ${(t.decrypted_json||0)} / extract ${(t.extract_response_body||0)} / dump ${(t.dump||0)} / forward ${(t.forward||0)}</code>`);
    }
    if(log.forward_attempts&&log.forward_attempts.length>1) detailBits.push(`<b>retry:</b><code>${log.forward_attempts.length}</code>`);
    const responseText = log.response ? `<pre class="live-resp">${esc(liveRespPreview(log.response, 520))}</pre>` : '';
    const responseMsg = log.response_msg ? `<div class="live-resp">${esc(log.response_msg)}</div>` : '';
    const errorText = log.error ? `<pre class="live-resp danger">${esc(log.error)}</pre>` : '';
    return `
      <div class="live-log-entry">
        <div class="live-log-head">
          <div class="live-log-title">${esc(status)}</div>
          <span class="daily-tag info">${esc(apiLabel)}</span>
          ${clientLabel?`<span class="daily-tag info">${esc(clientLabel)}</span>`:''}
        </div>
        <div class="live-log-sub">${esc(subtitle)}<span class="live-ip">IP ${esc(log.ip||'-')}</span></div>
        <div class="live-log-grid">
          <div class="live-mini"><span>账号</span><b>${esc(log.username||log.group_id||'-')}</b></div>
          <div class="live-mini"><span>任务</span><b>${esc(log.task_id||log.submit_id||'-')}</b></div>
        </div>
        ${detailBits.length?`<div class="live-log-detail">${detailBits.join(' ')}</div>`:''}
        ${responseMsg}${responseText}${errorText}
      </div>
    `;
  }).join(''):'<div class="daily-empty">暂无实时转发日志</div>';
  body.innerHTML=`
    <div class="daily-meta live-log-meta">
      <span class="daily-pill">账号 <b>${esc(accountLabel)}</b></span>
      <span class="daily-pill">更新时间 <b>${esc(data.updated_at||'-')}</b></span>
      <span class="daily-pill">转发日志 <b>${num(logs.length)}</b></span>
      <span class="daily-pill">在线设备 <b>${num(online)}</b></span>
    </div>
    <div class="daily-list">${logHtml}</div>
  `;
}
function renderDaily(data){
  const body=dailyPanel.querySelector('.daily-body');
  const summary=data.summary||{};
  const rows=Array.isArray(data.rows)?data.rows:[];
  const active=parseInt(data.active_count||0,10)||0;
  const taskCount=parseInt(data.task_count||0,10)||0;
  const successRate=rate(summary.success,summary.complete);
  const completeRate=rate(summary.complete,summary.take);
  const activeRate=rate(active,taskCount);
  const warning=data.warning?`<div class="daily-warn">${esc(data.warning)}</div>`:'';
  const rowHtml=rows.length?rows.map(row=>`
    <div class="daily-row">
      <div class="daily-row-top">
        <div class="daily-user">${esc(row.username)}</div>
        <div class="daily-tag">${esc(row.remark||'未备注')}</div>
      </div>
      <div class="daily-row-grid">
        <div class="daily-mini"><span>领取</span><b>${num(row.take)}</b></div>
        <div class="daily-mini"><span>完成</span><b>${num(row.complete)}</b></div>
        <div class="daily-mini"><span>通过</span><b class="ok">${num(row.success)}</b></div>
        <div class="daily-mini"><span>失败</span><b class="bad">${num(row.fail)}</b></div>
      </div>
    </div>
  `).join(''):'<div class="daily-empty">暂无可用任务账号</div>';
  body.innerHTML=`
    <div class="daily-total">
      <div class="daily-card"><span>领取</span><b>${num(summary.take)}</b></div>
      <div class="daily-card"><span>完成</span><b>${num(summary.complete)}</b></div>
      <div class="daily-card ok"><span>通过</span><b>${num(summary.success)}</b></div>
      <div class="daily-card bad"><span>失败</span><b>${num(summary.fail)}</b></div>
    </div>
    <div class="daily-line"><i style="--w:${Math.round(pct(summary.success,Math.max(1,summary.complete)))}%"></i></div>
    <div class="daily-meta">
      <span class="daily-pill">日期 <b>${esc(data.date||today())}</b></span>
      <span class="daily-pill">活跃 <b>${num(active)}/${num(taskCount)}</b></span>
      <span class="daily-pill">完成率 <b>${completeRate}</b></span>
      <span class="daily-pill">通过率 <b>${successRate}</b></span>
      <span class="daily-pill">活跃率 <b>${activeRate}</b></span>
      <span class="daily-pill">${data.fromCache?'缓存':'实时'} <b>${num(data.cacheAge||0)}s</b></span>
      <span class="daily-pill">匹配 <b>${num(data.matched_count||0)}/${num(data.allowed_count||taskCount)}</b></span>
      <span class="daily-pill">CX账号 <b>${num(data.cx_authorized_count||0)}</b></span>
      <span class="daily-pill">刷新 <b>${data.force_refresh?'强制':'自动'}</b></span>
    </div>
    <div class="daily-list">${rowHtml}</div>
    ${warning}
  `;
}
function render(data){
  current=data;
  const max=Math.max(1,parseInt(data.max_parallelism||1,10)||1);
  const val=clamp(data.task_parallelism||1,1,max);
  const names=Array.isArray(data.task_usernames)?data.task_usernames:[];
  panel.innerHTML=`
    <div class="top">
      <div class="account">
        <div><h2 id="accountId"></h2><p class="remark" id="remark"></p></div>
        <span class="badge ${data.enabled?'':'off'}">${data.enabled?'可使用':'已停用'}</span>
      </div>
      <div class="metrics">
        <div class="metric"><b>${val}</b><span>当前并发</span></div>
        <div class="metric"><b>${max}</b><span>最高可设</span></div>
        <div class="metric"><b>${data.enabled_task_count||0}</b><span>可用账号</span></div>
      </div>
    </div>
    <div class="body">
      <div class="control">
        <div class="value-row">
          <div><span class="value" id="bigValue">${val}</span><span class="unit">并发</span></div>
          <div class="limit">范围 1 - ${max}<br>当前模式：${data.task_mode==='concurrent'?'并发':'轮询'}</div>
        </div>
        <input id="range" type="range" min="1" max="${max}" value="${val}">
        <input id="number" type="number" min="1" max="${max}" step="1" value="${val}">
        <div class="names" id="names"></div>
      </div>
      <div class="actions"><button class="btn" id="saveBtn" ${data.enabled?'':'disabled'}>保存并发数量</button></div>
      <div class="msg" id="msg"></div>
    </div>`;
  document.getElementById('accountId').textContent=text(data.remark||data.accountId);
  document.getElementById('remark').textContent=data.remark?('账号ID：'+text(data.accountId)):'账号配置';
  const namesEl=document.getElementById('names');
  names.forEach(n=>{const s=document.createElement('span');s.className='chip';s.textContent=n;namesEl.appendChild(s)});
  if((data.hidden_task_username_count||0)>0){const s=document.createElement('span');s.className='chip more';s.textContent='等 '+data.hidden_task_username_count+' 个';namesEl.appendChild(s)}
  if(!names.length){const s=document.createElement('span');s.className='chip more';s.textContent='暂无可用任务账号';namesEl.appendChild(s)}
  const range=document.getElementById('range'), number=document.getElementById('number'), big=document.getElementById('bigValue');
  function setValue(v){v=clamp(v,1,max);range.value=v;number.value=v;big.textContent=v}
  range.addEventListener('input',()=>setValue(range.value));
  number.addEventListener('input',()=>setValue(number.value));
  document.getElementById('saveBtn').addEventListener('click',()=>save(number.value));
}
async function load(){
  if(!TOKEN){renderError('控制链接缺少 token');return}
  try{const r=await fetch(apiUrl('parallel_control_info'),{cache:'no-store'});const d=await r.json();if(!d.ok)throw new Error(d.msg||'读取失败');render(d.data||{})}
  catch(e){renderError(e.message||'读取失败')}
}
async function loadDailyStats(force){
  if(!TOKEN){renderDailyError('控制链接缺少 token');return}
  if(dailyLoading)return;
  dailyLoading=true;
  renderDailyCountdown();
  if(!TOKEN){renderDailyError('控制链接缺少 token');return}
  try{
    let url=apiUrl('parallel_control_daily_stats')+'&date='+encodeURIComponent(today())+'&_ts='+Date.now();
    if(force) url+='&force=1&refresh=1';
    const r=await fetch(url,{cache:'no-store'});
    const d=await r.json();
    if(!d.ok)throw new Error(d.msg||'读取失败');
    renderDaily(d.data||{});
    dailyRemain=DAILY_REFRESH_SECONDS;
    renderDailyCountdown();
  }catch(e){renderDailyError(e.message||'读取失败')}
  dailyLoading=false;
  dailyRemain=DAILY_REFRESH_SECONDS;
  renderDailyCountdown();
}
async function loadLiveStats(){
  if(!TOKEN){renderLiveError('控制链接缺少 token');return}
  if(liveLoading)return;
  liveLoading=true;
  renderLiveCountdown();
  try{
    const r=await fetch(apiUrl('parallel_control_live_stats')+'&_ts='+Date.now(),{cache:'no-store'});
    const d=await r.json();
    if(!d.ok)throw new Error(d.msg||'读取失败');
    renderLive(d.data||{});
    liveRemain=LIVE_REFRESH_SECONDS;
    renderLiveCountdown();
  }catch(e){renderLiveError(e.message||'读取失败')}
  liveLoading=false;
  liveRemain=LIVE_REFRESH_SECONDS;
  renderLiveCountdown();
}
function tickDailyCountdown(){
  dailyRemain=Math.max(0,dailyRemain-1);
  renderDailyCountdown();
  if(dailyRemain<=0)loadDailyStats(true);
}
function tickLiveCountdown(){
  liveRemain=Math.max(0,liveRemain-1);
  renderLiveCountdown();
  if(liveRemain<=0)loadLiveStats();
}
async function save(v){
  const msg=document.getElementById('msg'), btn=document.getElementById('saveBtn');
  msg.className='msg';msg.textContent='正在保存...';btn.disabled=true;
  try{
    const r=await fetch(apiUrl('parallel_control_save'),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({task_parallelism:v})});
    const d=await r.json();
    if(!d.ok)throw new Error(d.msg||'保存失败');
    render(d.data||current||{});
    loadDailyStats(true);
    loadLiveStats();
    const next=document.getElementById('msg');next.className='msg ok';next.textContent=d.msg||'已保存';
  }catch(e){msg.className='msg err';msg.textContent=e.message||'保存失败';btn.disabled=false}
}
load();
loadDailyStats(true);
loadLiveStats();
renderDailyCountdown();
renderLiveCountdown();
setInterval(tickDailyCountdown,1000);
setInterval(tickLiveCountdown,1000);
</script>
</body>
</html>
<?php
}

function renderPage(): void {
$isH5Mode = (string)($_GET['h5_mode'] ?? '') === '1' || (string)($_GET['act'] ?? '') === 'h5';
?>
<!DOCTYPE html>
<html lang="zh-CN" class="<?php echo $isH5Mode ? 'h5-mode' : ''; ?>">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1<?php echo $isH5Mode ? ',maximum-scale=1,user-scalable=no,viewport-fit=cover' : ''; ?>">
<title>Ajie 后台</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--primary:#6366f1;--primary-light:#818cf8;--primary-dark:#4f46e5;--success:#10b981;--danger:#ef4444;--warning:#f59e0b;--info:#8b5cf6;--sidebar:#0f172a;--sidebar-w:250px;--header-h:60px;--bg:#f1f5f9;--card:#ffffff;--border:#e2e8f0;--text:#1e293b;--muted:#94a3b8;--font:'Inter',-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB",sans-serif;--radius:12px;--shadow:0 1px 3px rgba(0,0,0,.04),0 1px 2px rgba(0,0,0,.06);--shadow-md:0 4px 6px -1px rgba(0,0,0,.07),0 2px 4px -2px rgba(0,0,0,.05);--shadow-lg:0 10px 15px -3px rgba(0,0,0,.08),0 4px 6px -4px rgba(0,0,0,.04)}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--font);background:var(--bg);color:var(--text);font-size:14px;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}
::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:3px}::-webkit-scrollbar-thumb:hover{background:#94a3b8}

/* Login */
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh;background:#09111f;position:relative;overflow:hidden}
.login-wrap::before{content:'';position:absolute;inset:0;background:linear-gradient(90deg,rgba(9,17,31,.94) 0%,rgba(9,17,31,.86) 34%,rgba(9,17,31,.56) 62%,rgba(9,17,31,.28) 100%),url('image-generate-f70447c5.png') right 4% center/clamp(420px,48vw,860px) auto no-repeat}
.login-wrap::after{content:none}
@keyframes loginIn{0%{opacity:0;transform:translateY(30px) scale(.96)}100%{opacity:1;transform:translateY(0) scale(1)}}
.login-box{background:rgba(18,18,18,.92);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border-radius:20px;padding:48px 40px;width:400px;box-shadow:0 25px 60px rgba(0,0,0,.5),0 0 0 1px rgba(180,150,80,.15),inset 0 1px 0 rgba(180,150,80,.08);position:relative;z-index:1;animation:loginIn .6s cubic-bezier(.16,1,.3,1)}
.login-box h1{font-size:24px;text-align:center;margin-bottom:6px;color:#e8e0d0;font-weight:700;letter-spacing:-0.5px}
.login-box p{text-align:center;color:#8a7e6e;margin-bottom:32px;font-size:14px;font-weight:400}
.login-box input{width:100%;height:48px;border:1px solid rgba(180,150,80,.2);border-radius:10px;padding:0 16px;font-size:15px;margin-bottom:20px;transition:all .25s;background:rgba(255,255,255,.06);font-family:var(--font);color:#e8e0d0}
.login-box input:focus{outline:none;border-color:rgba(180,150,80,.5);box-shadow:0 0 0 4px rgba(180,150,80,.1);background:rgba(255,255,255,.08)}
.login-box input::placeholder{color:#6a6050}
.login-box button{width:100%;height:48px;background:linear-gradient(135deg,#b4964f 0%,#8a7030 50%,#c4a660 100%);color:#fff;border:none;border-radius:10px;font-size:16px;font-weight:600;cursor:pointer;transition:all .25s;font-family:var(--font);box-shadow:0 4px 14px rgba(180,150,80,.3);text-shadow:0 1px 2px rgba(0,0,0,.2)}
.login-box button:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(180,150,80,.4)}
.login-box button:active{transform:translateY(0)}


/* Layout */
.layout{display:flex;min-height:100vh}
.sidebar{width:var(--sidebar-w);background:linear-gradient(180deg,#0f172a 0%,#1e293b 100%);position:fixed;top:0;left:0;bottom:0;z-index:100;overflow-y:auto;transition:width .3s cubic-bezier(.4,0,.2,1);border-right:1px solid rgba(255,255,255,.05)}
.sidebar::-webkit-scrollbar{width:0}
.sidebar-logo{height:60px;display:flex;align-items:center;padding:0 20px;color:#fff;font-size:15px;font-weight:700;letter-spacing:-0.3px;border-bottom:1px solid rgba(255,255,255,.06);background:rgba(255,255,255,.02);gap:12px}
.sidebar-logo-icon{width:34px;height:34px;background:linear-gradient(135deg,var(--primary),var(--info));border-radius:9px;display:flex;align-items:center;justify-content:center;flex-shrink:0;box-shadow:0 4px 12px rgba(99,102,241,.3)}
.sidebar-menu{padding:12px 10px 24px}
.menu-item{display:flex;align-items:center;height:42px;padding:0 14px;color:rgba(255,255,255,.55);cursor:pointer;font-size:14px;font-weight:500;transition:all .2s;gap:12px;border-radius:8px;margin-bottom:2px}
.menu-item:hover{color:rgba(255,255,255,.9);background:rgba(255,255,255,.06)}
.menu-item.active{color:#fff;background:linear-gradient(135deg,rgba(99,102,241,.3),rgba(139,92,246,.2));box-shadow:0 2px 8px rgba(99,102,241,.15)}
.menu-icon{width:20px;text-align:center;font-style:normal;font-size:15px;opacity:.8}
.side-pet{display:none}
.pet-hit{position:absolute;left:50%;bottom:18px;width:210px;height:300px;transform:translateX(-50%);pointer-events:auto;cursor:pointer}
.pet-time{position:absolute;left:50%;bottom:298px;min-width:142px;padding:5px 10px;border-radius:999px;background:rgba(15,23,42,.72);border:1px solid rgba(147,197,253,.22);box-shadow:0 8px 24px rgba(15,23,42,.22);color:#dbeafe;font-size:11px;font-weight:700;text-align:center;letter-spacing:.2px;transform:translateX(calc(-50% + var(--pet-x))) translateY(var(--pet-y));opacity:.88;white-space:nowrap;transition:transform .14s ease-out,opacity .2s ease}
.side-pet:hover .pet-time{opacity:1}
.side-pet.is-launching .pet-time{animation:petTimeLaunch 3.6s cubic-bezier(.2,.8,.18,1) forwards}
.pet-stage{position:absolute;left:50%;bottom:24px;width:192px;height:268px;transform:translateX(calc(-50% + var(--pet-x))) translateY(var(--pet-y)) rotate(var(--pet-tilt));animation:petFloat 2.8s ease-in-out infinite;transition:transform .14s ease-out,filter .2s ease;will-change:transform}
.side-pet:hover .pet-stage{filter:drop-shadow(0 16px 24px rgba(37,99,235,.22))}
.side-pet.is-launching .pet-stage{animation:petLaunch 3.6s cubic-bezier(.24,.78,.16,1) forwards}
.side-pet.is-launching .pet-shadow{animation:petLaunchShadow 3.6s ease forwards}
.pet-shadow{position:absolute;left:50%;bottom:24px;width:120px;height:18px;border-radius:50%;background:rgba(0,0,0,.34);filter:blur(4px);transform:translateX(calc(-50% + var(--pet-x)));animation:petShadow 2.8s ease-in-out infinite;transition:transform .14s ease-out}
.pet-anim{position:absolute;inset:0;background-image:url('pet_frames/pet_sprite.png');background-repeat:no-repeat;background-size:600% 100%;background-position:0 0;image-rendering:auto;animation:petFrames 4.2s steps(1) infinite;filter:drop-shadow(0 6px 12px rgba(15,23,42,.35))}
.side-pet:hover .pet-anim{animation-duration:1.4s}
.pet-launch-flame{position:absolute;left:50%;bottom:-4px;width:30px;height:0;border-radius:999px;background:linear-gradient(180deg,#fef3c7 0%,#f97316 45%,rgba(239,68,68,0) 100%);filter:blur(.5px);opacity:0;transform:translateX(-50%);transform-origin:top center}
.side-pet.is-launching .pet-launch-flame{height:96px;opacity:.95;animation:rocketFlame .16s ease-in-out infinite alternate}
.pet-pulse{position:absolute;width:18px;height:18px;border:2px solid rgba(147,197,253,.9);border-radius:50%;pointer-events:none;transform:translate(-50%,-50%);animation:petPulse .62s ease-out forwards}
.rocket-trail{position:absolute;left:50%;bottom:86px;width:4px;height:0;border-radius:999px;background:linear-gradient(180deg,rgba(96,165,250,0),rgba(96,165,250,.85),rgba(248,113,113,.12));box-shadow:0 0 22px rgba(59,130,246,.42);transform:translateX(-50%);pointer-events:none;opacity:0}
.side-pet.is-launching .rocket-trail{animation:rocketTrail 2.05s ease-out forwards}
.pet-spark{position:absolute;width:4px;height:4px;border-radius:50%;background:#bfdbfe;box-shadow:0 0 10px #60a5fa;opacity:.75;animation:petSpark 3.5s ease-in-out infinite;z-index:2}
.pet-spark.s1{left:24px;top:64px}.pet-spark.s2{right:30px;top:30px;animation-delay:1s}.pet-spark.s3{left:140px;top:160px;animation-delay:2s}
@keyframes petAura{to{transform:rotate(360deg)}}
@keyframes petFloat{0%,100%{transform:translateX(-50%) translateY(0)}50%{transform:translateX(-50%) translateY(-10px)}}
@keyframes petShadow{0%,100%{transform:translateX(-50%) scale(1);opacity:.45}50%{transform:translateX(-50%) scale(.82);opacity:.26}}
@keyframes petFrames{0%{background-position:0% 0}16.66%{background-position:20% 0}33.33%{background-position:40% 0}50%{background-position:60% 0}66.66%{background-position:80% 0}83.33%{background-position:100% 0}100%{background-position:100% 0}}
@keyframes petSpark{0%,100%{transform:translateY(0) scale(.7);opacity:.25}45%{transform:translateY(-18px) scale(1.15);opacity:.95}}
@keyframes petPulse{0%{width:18px;height:18px;opacity:.95}100%{width:132px;height:132px;opacity:0}}
@keyframes petLaunch{0%{opacity:1;transform:translateX(calc(-50% + var(--pet-x))) translateY(var(--pet-y)) rotate(var(--pet-tilt)) scale(1)}10%{transform:translateX(calc(-50% + var(--pet-x))) translateY(16px) rotate(0deg) scale(.96)}66%{opacity:1;transform:translateX(calc(-50% + var(--pet-x))) translateY(calc(-1 * var(--pet-rise, 720px))) rotate(2deg) scale(.9)}69%{opacity:0;transform:translateX(calc(-50% + var(--pet-x))) translateY(calc(-1 * var(--pet-rise, 760px))) scale(.84)}76%{opacity:0;transform:translateX(calc(-50% + var(--pet-x))) translateY(260px) scale(.9)}86%{opacity:1;transform:translateX(calc(-50% + var(--pet-x))) translateY(42px) rotate(-2deg) scale(1.02)}94%{transform:translateX(calc(-50% + var(--pet-x))) translateY(-8px) rotate(1deg) scale(1)}100%{opacity:1;transform:translateX(calc(-50% + var(--pet-x))) translateY(var(--pet-y)) rotate(var(--pet-tilt)) scale(1)}}
@keyframes petTimeLaunch{0%{opacity:.9;transform:translateX(calc(-50% + var(--pet-x))) translateY(var(--pet-y))}10%{opacity:.95;transform:translateX(calc(-50% + var(--pet-x))) translateY(16px)}66%{opacity:.95;transform:translateX(calc(-50% + var(--pet-x))) translateY(calc(-1 * var(--pet-rise, 720px)))}69%{opacity:0;transform:translateX(calc(-50% + var(--pet-x))) translateY(calc(-1 * var(--pet-rise, 760px)))}76%{opacity:0;transform:translateX(calc(-50% + var(--pet-x))) translateY(260px)}86%{opacity:.95;transform:translateX(calc(-50% + var(--pet-x))) translateY(42px)}100%{opacity:.88;transform:translateX(calc(-50% + var(--pet-x))) translateY(var(--pet-y))}}
@keyframes petLaunchShadow{0%,100%{opacity:.45;transform:translateX(calc(-50% + var(--pet-x))) scale(1)}18%{opacity:.2;transform:translateX(calc(-50% + var(--pet-x))) scale(.6)}58%,76%{opacity:0;transform:translateX(calc(-50% + var(--pet-x))) scale(.22)}88%{opacity:.35;transform:translateX(calc(-50% + var(--pet-x))) scale(1.18)}}
@keyframes rocketFlame{0%{transform:translateX(-50%) scaleY(.72);filter:blur(.5px)}100%{transform:translateX(-50%) scaleY(1.12);filter:blur(1px)}}
@keyframes rocketTrail{0%{height:0;opacity:0}10%{height:70px;opacity:.72}60%{height:calc(var(--pet-rise, 720px) - 120px);opacity:.92}82%{height:calc(var(--pet-rise, 720px) - 120px);opacity:.18}100%{height:0;opacity:0}}
.main{margin-left:var(--sidebar-w);flex:1;min-width:0;position:relative}
.header{height:var(--header-h);background:rgba(255,255,255,.85);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;padding:0 28px;position:sticky;top:0;z-index:50}
.header-left{font-size:18px;font-weight:700;letter-spacing:-0.3px;color:#0f172a}
.header-right{display:flex;align-items:center;gap:20px;font-size:13px;color:var(--muted)}
.header-expiry{display:inline-flex;align-items:center;gap:6px;color:#64748b;background:#f8fafc;border:1px solid #e2e8f0;border-radius:999px;padding:5px 10px;font-size:12px;font-weight:600}
.header-expiry b{color:#ef4444;font-weight:700}
.header-right a{color:var(--danger);text-decoration:none;cursor:pointer;font-weight:600;padding:6px 14px;border-radius:6px;transition:all .2s;font-size:13px}
.header-right a:hover{background:rgba(239,68,68,.06)}
.content{padding:24px 28px;position:relative}
.content::before{content:none}
.content::after{content:'';position:fixed;left:calc(var(--sidebar-w) + 120px);right:-8px;top:92px;bottom:0;pointer-events:none;z-index:0;background:url('image-generate-f70447c5.png') right bottom/clamp(560px,48vw,860px) auto no-repeat;opacity:.9;filter:saturate(1.02) contrast(1.01) brightness(1.01)}
.content>*{position:relative;z-index:1}

/* Cards */
.stat-row{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.stat-card{background:#fff;border-radius:var(--radius);padding:22px 24px;border:1px solid #e2e8f0;box-shadow:0 16px 40px rgba(15,23,42,.08);transition:all .25s;position:relative;overflow:hidden}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--primary),var(--info));opacity:0;transition:opacity .25s}
.stat-card:hover{box-shadow:var(--shadow-md);transform:translateY(-2px)}
.stat-card:hover::before{opacity:1}
.stat-card .label{font-size:12px;color:var(--muted);margin-bottom:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px}
.stat-card .value{font-size:30px;font-weight:800;letter-spacing:-1px}
.stat-card .value.green{color:var(--success)}.stat-card .value.red{color:var(--danger)}.stat-card .value.blue{color:var(--primary)}.stat-card .value.purple{color:var(--info)}
.card{background:#fff;border-radius:var(--radius);border:1px solid #e2e8f0;margin-bottom:20px;box-shadow:0 18px 44px rgba(15,23,42,.08);transition:box-shadow .25s}
.card:hover{box-shadow:var(--shadow-md)}
.card-head{padding:18px 24px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.card-head h3{font-size:15px;font-weight:700;letter-spacing:-0.2px;color:#0f172a}
.card-body{padding:20px 24px}
.card-toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}

/* Table */
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:12px 14px;border-bottom:1px solid #f1f5f9;font-size:13px;white-space:nowrap}
th{background:rgba(248,250,252,.96);font-weight:600;color:#64748b;white-space:nowrap;text-transform:uppercase;font-size:11px;letter-spacing:0.5px}
tr{transition:background .15s}
tr:hover td{background:#f8fafc}
.account-pager{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 14px;border-top:1px solid #f1f5f9;background:#fff;flex-wrap:wrap}
.account-pager-info{font-size:12px;color:var(--muted);font-weight:600}
.account-pager-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.account-pager-actions .btn[disabled]{opacity:.45;cursor:not-allowed;transform:none;box-shadow:none}
.account-page-size{height:30px;border:1px solid #e2e8f0;border-radius:7px;padding:0 8px;background:#f8fafc;color:#334155;font-size:12px;font-family:var(--font)}

/* Buttons */
.btn{height:34px;border:none;border-radius:8px;cursor:pointer;font-size:13px;font-weight:600;padding:0 16px;display:inline-flex;align-items:center;gap:5px;transition:all .2s;color:#fff;font-family:var(--font);letter-spacing:-0.1px;white-space:nowrap}
.btn:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(0,0,0,.1)}
.btn:active{transform:translateY(0)}
.btn-sm{height:28px;font-size:12px;padding:0 12px;border-radius:6px;white-space:nowrap}
.btn-primary{background:linear-gradient(135deg,var(--primary),var(--primary-dark));box-shadow:0 2px 8px rgba(99,102,241,.25)}.btn-success{background:linear-gradient(135deg,var(--success),#059669);box-shadow:0 2px 8px rgba(16,185,129,.25)}.btn-danger{background:linear-gradient(135deg,var(--danger),#dc2626);box-shadow:0 2px 8px rgba(239,68,68,.25)}.btn-warning{background:linear-gradient(135deg,var(--warning),#d97706);color:#fff;box-shadow:0 2px 8px rgba(245,158,11,.25)}.btn-info{background:linear-gradient(135deg,var(--info),#7c3aed);box-shadow:0 2px 8px rgba(139,92,246,.25)}.btn-default{background:#fff;color:var(--text);border:1px solid #dbe2ea;box-shadow:0 8px 18px rgba(15,23,42,.07)}
.btn-default:hover{background:#f8fafc;border-color:#cbd5e1}

/* Tags */
.tag{display:inline-block;padding:3px 10px;border-radius:6px;font-size:12px;font-weight:600;line-height:18px;letter-spacing:-0.1px}
.tag-success{background:#ecfdf5;color:#059669;border:1px solid #a7f3d0}.tag-danger{background:#fef2f2;color:#dc2626;border:1px solid #fecaca}.tag-warning{background:#fffbeb;color:#d97706;border:1px solid #fde68a}.tag-info{background:#f5f3ff;color:#7c3aed;border:1px solid #ddd6fe}.tag-blue{background:#eef2ff;color:#4f46e5;border:1px solid #c7d2fe}

/* Form */
.form-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:18px}
.form-item{display:flex;flex-direction:column;gap:6px}
.form-item label{font-size:13px;color:#64748b;font-weight:600;letter-spacing:-0.1px}
.form-item input,.form-item textarea,.form-item select{height:40px;border:2px solid #e2e8f0;border-radius:8px;padding:0 12px;font-size:14px;font-family:var(--font);transition:all .2s;background:#f8fafc}
.form-item input:focus,.form-item textarea:focus,.form-item select:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(99,102,241,.1);background:#fff}
.form-item textarea{height:auto;min-height:80px;padding:10px 12px;resize:vertical}
.form-check{display:flex;align-items:center;gap:8px;padding-top:20px}
.form-check input[type="checkbox"]{width:18px;height:18px;accent-color:var(--primary)}

/* Log items */
.log-entry{padding:14px 20px;border-bottom:1px solid #f1f5f9;font-size:13px;transition:background .15s}
.log-entry:last-child{border-bottom:none}
.log-entry:hover{background:#f8fafc}
.log-meta{display:flex;gap:10px;align-items:center;margin-bottom:6px;flex-wrap:wrap}
.log-detail{color:#64748b;line-height:1.9}
.log-detail code{background:#f1f5f9;padding:2px 8px;border-radius:5px;font-size:12px;color:#334155;font-weight:500}
.log-actions{margin-top:8px;display:flex;gap:8px}
.log-actions a{font-size:12px;color:var(--primary);text-decoration:none;font-weight:600;padding:2px 6px;border-radius:4px;transition:background .15s}
.log-actions a:hover{background:rgba(99,102,241,.06)}
pre.resp{background:#fff;padding:12px 14px;border-radius:8px;font-size:12px;overflow-x:auto;max-height:160px;margin-top:8px;color:#334155;border:1px solid #e2e8f0;line-height:1.6}

/* Device */
.device-card{padding:14px 16px;border:1px solid #e2e8f0;border-radius:10px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;background:#fff;box-shadow:0 10px 24px rgba(15,23,42,.05)}
.device-info{flex:1;min-width:200px}
.device-info b{font-size:15px}
.device-meta{font-size:12px;color:var(--muted);margin-top:4px;display:flex;gap:12px;flex-wrap:wrap}

/* Stats user row */
.stats-user{padding:18px 20px;border:1px solid #e2e8f0;border-radius:10px;margin-bottom:12px;background:#fff;transition:all .2s;box-shadow:0 16px 40px rgba(15,23,42,.08)}
.stats-user:hover{box-shadow:var(--shadow-md);border-color:#cbd5e1}
.stats-user-head{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}
.stats-nums{display:flex;gap:24px;font-size:14px}
.stats-records{margin-top:8px;font-size:12px;color:var(--muted)}

.empty{text-align:center;padding:48px;color:var(--muted);font-size:14px}
.hidden{display:none !important}
@media(max-width:768px){.sidebar{width:0;overflow:hidden}.main{margin-left:0}.content::before{content:none}.content::after{left:48px;right:-18px;top:132px;bottom:0;background:url('image-generate-f70447c5.png') right bottom/clamp(260px,60vw,380px) auto no-repeat;opacity:.72}.stat-row{grid-template-columns:repeat(2,1fr)}.form-grid{grid-template-columns:1fr}.login-box{width:90vw;padding:32px 24px}.header{padding:0 16px}.content{padding:16px}}

.modal-mask{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(15,23,42,.5);backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px);z-index:200;display:flex;align-items:center;justify-content:center;animation:fadeIn .2s ease}
@keyframes fadeIn{0%{opacity:0}100%{opacity:1}}
.modal-box{background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:28px;width:480px;max-width:90vw;max-height:80vh;overflow-y:auto;box-shadow:0 25px 60px rgba(0,0,0,.2);animation:modalIn .3s cubic-bezier(.16,1,.3,1)}
@keyframes modalIn{0%{opacity:0;transform:scale(.95) translateY(10px)}100%{opacity:1;transform:scale(1) translateY(0)}}
.modal-box h3{margin-bottom:20px;font-size:17px;font-weight:700;color:#0f172a}
.modal-footer{margin-top:20px;display:flex;justify-content:flex-end;gap:10px}

/* H5 shell: same full web app, mobile layout only */
html.h5-mode,html:has(body.h5-mode),body.h5-mode{width:100%;max-width:100%;overflow-x:hidden}
body.h5-mode{background:var(--bg);overscroll-behavior:none}
body.h5-mode *{max-width:100%}
body.h5-mode .layout{display:block;min-height:100vh;width:100%;max-width:100%;overflow-x:hidden}
body.h5-mode .sidebar{position:fixed;left:0;right:0;bottom:0;top:auto;width:auto;height:calc(78px + env(safe-area-inset-bottom,0px));z-index:180;border-right:0;border-top:1px solid rgba(255,255,255,.08);overflow-x:auto;overflow-y:hidden;background:linear-gradient(180deg,#0f172a 0%,#1e293b 100%);box-shadow:0 -18px 45px rgba(15,23,42,.2)}
body.h5-mode .sidebar::-webkit-scrollbar{height:0}
body.h5-mode .sidebar-logo{display:none}
body.h5-mode .sidebar-menu{display:flex;gap:6px;min-width:max-content;padding:8px 10px calc(8px + env(safe-area-inset-bottom,0px))}
body.h5-mode .menu-item{height:54px;min-width:86px;display:flex;flex-direction:column;justify-content:center;align-items:center;gap:4px;margin:0;padding:6px 8px;border-radius:14px;font-size:11px;line-height:1.2;white-space:nowrap;color:rgba(255,255,255,.62)}
body.h5-mode .menu-item.active{color:#fff;background:linear-gradient(135deg,rgba(99,102,241,.38),rgba(139,92,246,.26))}
body.h5-mode .menu-icon{width:auto;font-size:16px;line-height:1}
body.h5-mode .main{margin-left:0;min-height:100vh;padding-bottom:calc(84px + env(safe-area-inset-bottom,0px));width:100%;max-width:100%;min-width:0;overflow-x:hidden}
body.h5-mode .header{min-height:58px;height:auto;padding:10px 12px;gap:10px;align-items:flex-start}
body.h5-mode .header-left{font-size:17px;line-height:1.4;padding-top:4px}
body.h5-mode .header-right{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:6px;font-size:12px}
body.h5-mode .header-expiry{padding:4px 8px;font-size:11px}
body.h5-mode .content{padding:12px 12px calc(96px + env(safe-area-inset-bottom,0px));width:100%;max-width:100%;overflow-x:hidden}
body.h5-mode .content::after{left:0;right:-36px;top:118px;bottom:80px;background:url('image-generate-f70447c5.png') right bottom/clamp(250px,66vw,430px) auto no-repeat;opacity:.52}
body.h5-mode .stat-row{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-bottom:12px}
body.h5-mode .stat-card{padding:14px;border-radius:12px}
body.h5-mode .stat-card .value{font-size:24px;letter-spacing:0;word-break:break-word}
body.h5-mode .page,body.h5-mode .card,body.h5-mode .form-grid,body.h5-mode .form-item{width:100%;max-width:100%;min-width:0}
body.h5-mode .card{border-radius:12px;margin-bottom:12px;overflow:hidden}
body.h5-mode .card-head{padding:12px;align-items:flex-start;gap:8px}
body.h5-mode .card-head h3{font-size:15px;line-height:1.4}
body.h5-mode .card-toolbar{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}
body.h5-mode .card-body{padding:12px;overflow-x:auto;-webkit-overflow-scrolling:touch}
body.h5-mode table{width:max-content;min-width:640px;max-width:none}
body.h5-mode th,body.h5-mode td{padding:10px 8px;font-size:12px;vertical-align:top}
body.h5-mode .form-grid{grid-template-columns:1fr;gap:12px}
body.h5-mode .form-item input,body.h5-mode .form-item textarea,body.h5-mode select{font-size:16px;width:100%;max-width:100%;min-width:0}
body.h5-mode input,body.h5-mode textarea,body.h5-mode select{max-width:100%;min-width:0}
body.h5-mode .btn{min-height:34px}
body.h5-mode .btn-sm{height:32px;padding:0 10px;font-size:12px}
body.h5-mode .modal-mask{align-items:flex-end;padding:10px}
body.h5-mode .modal{width:100%;max-width:calc(100vw - 20px);max-height:calc(100vh - 24px);overflow:auto;border-radius:16px 16px 12px 12px}
body.h5-mode .modal-footer{position:sticky;bottom:0;background:#fff;padding-top:12px;flex-wrap:wrap}
body.h5-mode .login-box{width:calc(100vw - 28px);padding:34px 24px}
body.h5-mode pre.resp{font-size:12px;max-height:55vh}
</style>
</head>
<body class="<?php echo $isH5Mode ? 'h5-mode' : ''; ?>">

<!-- Login Page -->
<div class="login-wrap" id="loginPage">
<div class="login-box">
    <div style="text-align:center;margin-bottom:20px">
        <img src="1777990327149137925.png" alt="logo" style="width:80px;height:80px;border-radius:16px;object-fit:cover;box-shadow:0 8px 24px rgba(0,0,0,.15)">
    </div>
    <h1>Ajie 后台</h1>
    <p>日志监控 / 设备管理 / 数据统计</p>
    <input type="password" id="loginPwd" placeholder="请输入管理密码" onkeydown="if(event.key==='Enter')doLogin()">
    <button onclick="doLogin()">登 录</button>
</div>
</div>

<!-- Admin Layout -->
<div class="layout hidden" id="adminLayout">
<div class="sidebar">
    <div class="sidebar-logo">
        <div class="sidebar-logo-icon">
            <img src="1777990327149137925.png" alt="logo" style="width:100%;height:100%;object-fit:cover;border-radius:9px">
        </div>
        Ajie 控制台
    </div>
    <div class="sidebar-menu">
        <div class="menu-item" onclick="openPasswordModal()"><i class="menu-icon">&#128274;</i>修改密码</div>
        <div class="menu-item" onclick="switchPage('extconfig',this)"><i class="menu-icon">&#128273;</i>浏览器插件配置</div>
        <div class="menu-item active" onclick="switchPage('dashboard',this)"><i class="menu-icon">&#9632;</i>仪表盘</div>
        <div class="menu-item" data-page-menu="logs" onclick="switchPage('logs',this)"><i class="menu-icon">&#9776;</i>转发日志</div>
        <div class="menu-item" onclick="switchPage('devices',this)"><i class="menu-icon">&#9679;</i>在线设备</div>
        <div class="menu-item" onclick="switchPage('android',this)"><i class="menu-icon">&#128241;</i>&#x5B89;&#x5353;&#x63A7;&#x5236;</div>
        <div class="menu-item" onclick="switchPage('stats',this)"><i class="menu-icon">&#9733;</i>环境统计</div>
        <div class="menu-item" onclick="switchPage('accounts',this)"><i class="menu-icon">&#9737;</i>账号授权</div>
        <div class="menu-item" onclick="switchPage('update',this)"><i class="menu-icon">&#8679;</i>更新发布</div>
        <div class="menu-item" onclick="switchPage('verctrl',this)"><i class="menu-icon">&#9881;</i>版本控制</div>
        <div class="menu-item" onclick="switchPage('data',this)"><i class="menu-icon">&#128196;</i>解密数据</div>
        <div class="menu-item" onclick="switchPage('jsonmon',this)"><i class="menu-icon">&#128450;</i>JSON监控</div>
        <div class="menu-item" onclick="switchPage('sqlite',this)"><i class="menu-icon">&#9638;</i>SQLite监控</div>
        <div class="menu-item" onclick="switchPage('cache',this)"><i class="menu-icon">&#9851;</i>缓存清理</div>
    </div>
</div>
<div class="main">
    <div class="header">
        <div class="header-left" id="pageTitle">仪表盘</div>
        <div class="header-right">
            <span class="header-expiry" id="serverExpiry">服务器到期 <b>--</b></span>
            <span id="headerTime"></span>
            <button class="btn btn-default btn-sm" onclick="openPasswordModal()">修改密码</button>
            <a onclick="doLogout()">退出登录</a>
        </div>
    </div>
    <div class="content">

    <!-- Dashboard -->
    <div class="page" id="page-dashboard">
        <div class="stat-row" id="dashStats"></div>
        <div class="card"><div class="card-head"><h3>最近转发</h3><div class="card-toolbar"><button class="btn btn-primary btn-sm" onclick="switchPage('logs',document.querySelector('[data-page-menu=&quot;logs&quot;]'))">查看全部</button></div></div><div class="card-body"><div id="dashLogs" style="max-height:400px;overflow-y:auto"><div class="empty">加载中...</div></div></div></div>
    </div>

    <!-- Logs -->
    <div class="page hidden" id="page-logs">
        <div class="card"><div class="card-head"><h3>转发日志</h3><div class="card-toolbar"><button class="btn btn-primary btn-sm" onclick="loadLogs()">刷新</button><button class="btn btn-success btn-sm" onclick="toggleAutoLog()" id="autoLogBtn">自动刷新</button><button class="btn btn-danger btn-sm" onclick="clearLogs()">清空</button></div></div><div class="card-body" style="padding:0"><div id="logList"><div class="empty">点击刷新加载日志</div></div></div></div>
    </div>

    <!-- Devices -->
    <div class="page hidden" id="page-devices">
        <div class="card"><div class="card-head"><h3>在线设备 <span id="onlineCount" style="color:var(--success);font-size:14px"></span></h3><div class="card-toolbar"><span style="font-size:12px;color:var(--muted)">每10秒自动刷新，禁用设备会保留显示便于解除</span></div></div><div class="card-body"><div id="deviceList"><div class="empty">加载中...</div></div></div></div>
    </div>


    <!-- Android Control -->
    <div class="page hidden" id="page-android">
        <div class="card"><div class="card-head"><h3>&#x5B89;&#x5353; App &#x63A7;&#x5236; <span id="androidCount" style="color:var(--success);font-size:14px"></span></h3><div class="card-toolbar"><button class="btn btn-primary btn-sm" onclick="loadAndroidControl()">&#x5237;&#x65B0;</button><button class="btn btn-success btn-sm" onclick="androidCommandAll('run')">&#x5168;&#x90E8;&#x542F;&#x52A8;</button><button class="btn btn-warning btn-sm" onclick="androidCommandAll('pause')">&#x5168;&#x90E8;&#x6682;&#x505C;</button></div></div><div class="card-body"><div id="androidControlList"><div class="empty">&#x52A0;&#x8F7D;&#x4E2D;...</div></div></div></div>
    </div>

    <!-- Stats -->
    <div class="page hidden" id="page-stats">
        <div class="card"><div class="card-head"><h3>指纹环境管理</h3><div class="card-toolbar"><select id="statsDate" onchange="loadStats()" style="height:34px;border:2px solid #e2e8f0;border-radius:8px;padding:0 12px;font-size:13px;font-family:var(--font);background:#f8fafc"></select><button class="btn btn-danger btn-sm" onclick="clearStats()">清除统计</button></div></div><div class="card-body"><div id="statsBody"><div class="empty">加载中...</div></div></div></div>
    </div>

    <!-- Browser Plugin Config -->
    <div class="page hidden" id="page-extconfig">
        <div class="card">
            <div class="card-head">
                <h3>浏览器插件配置 <span id="extAccountCount" style="font-size:13px;color:var(--muted)"></span></h3>
                <div class="card-toolbar">
                    <button class="btn btn-primary btn-sm" onclick="showExtAccountModal()">新增插件账号</button>
                    <button class="btn btn-info btn-sm" onclick="showExtBatchModal()">批量生成</button>
                </div>
            </div>
            <div class="card-body" style="padding:0">
                <div style="font-size:12px;color:var(--muted);padding:10px 12px 0">这里填写真实任务接口账号密码，系统生成下发给用户的 accountId/token。</div>
                <div id="extAccountTable"><div class="empty">加载中...</div></div>
            </div>
        </div>
    </div>

    <!-- Accounts -->
    <div class="page hidden" id="page-accounts">
        <div class="form-grid">
        <div class="card">
            <div class="card-head">
                <h3>聚星账号白名单 <span id="api1Count" style="font-size:13px;color:var(--muted)"></span></h3>
                <div class="card-toolbar">
                    <button class="btn btn-primary btn-sm" onclick="showAddAccount(1)">单独添加</button>
                    <button class="btn btn-info btn-sm" onclick="showBatchAdd(1)">批量添加</button>
                    <button class="btn btn-danger btn-sm" id="batchDelete1" onclick="deleteSelectedAccounts(1)" disabled>批量删除</button>
                </div>
            </div>
            <div class="card-body" style="padding:0"><div style="font-size:12px;color:var(--muted);padding:10px 12px 0">未设置账号会拒绝登录</div><div id="api1Table"><div class="empty">加载中...</div></div></div>
        </div>
        </div>
    </div>

    <!-- Update -->
    <div class="page hidden" id="page-update">
        <div id="updateBody"><div class="empty">加载中...</div></div>
    </div>

    <!-- Version Control -->
    <div class="page hidden" id="page-verctrl">
        <div class="card">
            <div class="card-head"><h3>版本控制</h3></div>
            <div class="card-body">
                <div style="background:linear-gradient(135deg,#fefce8,#fffbeb);border:1px solid #fde68a;padding:12px 16px;border-radius:10px;margin-bottom:16px;font-size:13px;color:#92400e">低于最低版本号的App将被强制停用；也可单独停用指定版本。App检测到停用后弹窗提示并要求更新。</div>
                <div class="form-grid" style="margin-bottom:20px">
                    <div class="form-item"><label>最低允许版本号 (versionCode)</label><input id="vcMinCode" type="number" min="0" value="0" placeholder="0表示不限制"></div>
                    <div class="form-item"><label>低版本停用提示语</label><input id="vcMinMsg" value="" placeholder="您的版本已停用，请更新到最新版本"></div>
                    <div class="form-item"><label>接口2编号最小值</label><input id="api2LoginMin" type="number" min="0" value="0"></div>
                    <div class="form-item"><label>接口2编号最大值</label><input id="api2LoginMax" type="number" min="0" value="10000"></div>
                </div>
                <div style="display:flex;gap:10px;align-items:center;margin-bottom:16px">
                    <button class="btn btn-primary" onclick="saveVerCtrl()">保存设置</button>
                    <span id="vcResult" style="font-size:13px;color:var(--muted)"></span>
                </div>
                <div class="card" style="margin-top:10px">
                    <div class="card-head"><h3>单独停用版本</h3><div class="card-toolbar"><button class="btn btn-danger btn-sm" onclick="showAddBlockedVer()">添加停用版本</button></div></div>
                    <div class="card-body" style="padding:0"><div id="blockedVerList"><div class="empty">暂无停用版本</div></div></div>
                </div>
            </div>
        </div>
    </div>

    <!-- Data -->
    <div class="page hidden" id="page-data">
        <div class="card"><div class="card-head"><h3>解密数据列表</h3><div class="card-toolbar"><button class="btn btn-info btn-sm" onclick="openLatestDump()">打开最新</button></div></div><div class="card-body"><div id="dumpList"><div class="empty">加载中...</div></div></div></div>
    </div>

    <!-- JSON Monitor -->
    <div class="page hidden" id="page-jsonmon">
        <div class="card">
            <div class="card-head">
                <h3>JSON文件监控</h3>
                <div class="card-toolbar">
                    <button class="btn btn-primary btn-sm" onclick="loadJsonMonitor()">刷新</button>
                </div>
            </div>
            <div class="card-body">
                <div style="background:linear-gradient(135deg,#eff6ff,#f5f3ff);border:1px solid #c7d2fe;padding:12px 16px;border-radius:10px;margin-bottom:16px;font-size:13px;color:#334155">
                    只读取 decrypt_proxy.php 同目录下的 .json / .jsonl 文件；password、token、auth、hash 等字段会自动打码。
                </div>
                <div id="jsonMonitorBody"><div class="empty">点击刷新加载文件</div></div>
            </div>
        </div>
    </div>

    <!-- SQLite Monitor -->
    <div class="page hidden" id="page-sqlite">
        <div class="card">
            <div class="card-head">
                <h3>SQLite运行监控</h3>
                <div class="card-toolbar">
                    <button class="btn btn-primary btn-sm" onclick="loadSQLiteMonitor()">刷新</button>
                    <button class="btn btn-success btn-sm" onclick="toggleSQLiteAuto()" id="sqliteAutoBtn">自动刷新</button>
                </div>
            </div>
            <div class="card-body">
                <div style="background:linear-gradient(135deg,#ecfdf5,#eff6ff);border:1px solid #bfdbfe;padding:12px 16px;border-radius:10px;margin-bottom:16px;font-size:13px;color:#334155">
                    监控 runtime.sqlite 的任务队列、任务租约、WAL文件和数据库健康状态；敏感 token 不会显示。
                </div>
                <div id="sqliteMonitorBody"><div class="empty">点击刷新加载数据库状态</div></div>
            </div>
        </div>
    </div>

    <!-- Cache -->
    <div class="page hidden" id="page-cache">
        <div class="card">
            <div class="card-head">
                <h3>缓存清理工具</h3>
                <div class="card-toolbar">
                    <button class="btn btn-primary btn-sm" onclick="loadCacheOverview()">刷新</button>
                    <button class="btn btn-danger btn-sm" onclick="cleanupCache('unused')">清理废弃缓存</button>
                    <button class="btn btn-info btn-sm" onclick="cleanupCache('deep')">深度清理</button>
                </div>
            </div>
            <div class="card-body">
                <div style="background:linear-gradient(135deg,#fefce8,#fffbeb);border:1px solid #fde68a;padding:12px 16px;border-radius:10px;margin-bottom:16px;font-size:13px;color:#92400e">
                    上传详情缓存已启用，可在日志中查看上传响应；深度清理会额外清空日志并整理旧缓存。
                </div>
                <div id="cacheResult" style="font-size:13px;color:var(--muted);margin-bottom:12px"></div>
                <div id="cacheBody"><div class="empty">加载中...</div></div>
            </div>
        </div>
    </div>

    </div>
</div>
</div>

<!-- Password Modal -->
<div class="modal-mask hidden" id="passwordModal" onclick="if(event.target===this)closePasswordModal()">
<div class="modal-box">
    <h3>修改后台密码</h3>
    <div class="form-grid">
        <div class="form-item"><label>当前密码</label><input id="currentPwd" type="password" autocomplete="current-password"></div>
        <div class="form-item"><label>新密码</label><input id="newPwd" type="password" autocomplete="new-password" placeholder="至少 6 位"></div>
        <div class="form-item"><label>确认新密码</label><input id="confirmPwd" type="password" autocomplete="new-password"></div>
    </div>
    <div id="passwordResult" style="font-size:13px;color:var(--muted);margin-top:14px;min-height:18px"></div>
    <div class="modal-footer">
        <button class="btn btn-default" onclick="closePasswordModal()">取消</button>
        <button class="btn btn-primary" onclick="submitPasswordChange()">保存</button>
    </div>
</div>
</div>

<!-- Account Modal -->
<div class="modal-mask hidden" id="accountModal" onclick="if(event.target===this)closeAccountModal()">
<div class="modal-box">
    <h3 id="acctModalTitle">添加账号</h3>
    <div id="acctModalBody"></div>
    <div class="modal-footer">
        <button class="btn btn-default" onclick="closeAccountModal()">取消</button>
        <button class="btn btn-primary" onclick="acctModalConfirm()">确定</button>
    </div>
</div>
</div>

<script>
const BASE = location.pathname;
const AUTH_KEY = '';
const SERVER_RENDER_TIME_MS = <?php echo (int)round(microtime(true) * 1000); ?>;
const CLIENT_RENDER_TIME_MS = Date.now();
let KEY = localStorage.getItem('admin_key') || '';
let autoLogTimer = null, deviceTimer = null, sqliteTimer = null;

function doLogin() {
    const pwd = document.getElementById('loginPwd').value.trim();
    if (!pwd) return alert('请输入密码');
    KEY = pwd;
    localStorage.setItem('admin_key', pwd);
    authFetch(BASE+'?act=logs&limit=1').then(r=>r.json()).then(d=>{
        if (d.ok === false && d.msg === '密码错误') { alert('密码错误'); KEY=''; localStorage.removeItem('admin_key'); return; }
        showAdmin();
    }).catch(()=>alert('网络错误'));
}
function doLogout() { KEY=''; localStorage.removeItem('admin_key'); location.reload(); }
function openPasswordModal() {
    document.getElementById('currentPwd').value = KEY || '';
    document.getElementById('newPwd').value = '';
    document.getElementById('confirmPwd').value = '';
    document.getElementById('passwordResult').textContent = '';
    document.getElementById('passwordModal').classList.remove('hidden');
    setTimeout(()=>document.getElementById('newPwd').focus(), 0);
}
function closePasswordModal() { document.getElementById('passwordModal').classList.add('hidden'); }
async function submitPasswordChange() {
    const current = document.getElementById('currentPwd').value.trim();
    const next = document.getElementById('newPwd').value.trim();
    const confirm = document.getElementById('confirmPwd').value.trim();
    const result = document.getElementById('passwordResult');
    if (!current || !next || !confirm) { result.textContent = '请填写当前密码和新密码'; return; }
    const fd = new FormData();
    fd.append('act', 'change_password');
    fd.append('current_password', current);
    fd.append('new_password', next);
    fd.append('confirm_password', confirm);
    result.textContent = '保存中...';
    try {
        const r = await authFetch(BASE, { method: 'POST', body: fd });
        const d = await r.json();
        result.textContent = d.msg || (d.ok ? '密码已修改' : '修改失败');
        if (d.ok) {
            KEY = next;
            localStorage.setItem('admin_key', KEY);
            setTimeout(closePasswordModal, 800);
        }
    } catch (e) {
        result.textContent = '网络错误';
    }
}
function initSidePet() {
    return;
}
function currentServerDate(){
    return new Date(SERVER_RENDER_TIME_MS + (Date.now() - CLIENT_RENDER_TIME_MS));
}
function nextServerExpiryDate(now){
    return new Date(2026, 7, 18, 0, 0, 0, 0);
}
function formatExpiryCountdown(ms){
    const totalSeconds=Math.max(0,Math.floor(ms/1000));
    const days=Math.floor(totalSeconds/86400);
    const hours=Math.floor((totalSeconds%86400)/3600);
    const minutes=Math.floor((totalSeconds%3600)/60);
    const seconds=totalSeconds%60;
    return `${days}天 ${String(hours).padStart(2,'0')}:${String(minutes).padStart(2,'0')}:${String(seconds).padStart(2,'0')}`;
}
function updateHeaderClock(){
    const now=currentServerDate();
    const timeEl=document.getElementById('headerTime');
    if(timeEl) timeEl.textContent=now.toLocaleTimeString();
    const expiryEl=document.getElementById('serverExpiry');
    if(expiryEl){
        const expiry=nextServerExpiryDate(now);
        const dateText=`${expiry.getFullYear()}-${String(expiry.getMonth()+1).padStart(2,'0')}-${String(expiry.getDate()).padStart(2,'0')}`;
        expiryEl.innerHTML=`服务器到期 ${dateText} <b>${formatExpiryCountdown(expiry-now)}</b>`;
    }
}
function showAdmin() {
    document.getElementById('loginPage').classList.add('hidden');
    document.getElementById('adminLayout').classList.remove('hidden');
    initSidePet();
    loadDashboard();
    updateHeaderClock();
    setInterval(updateHeaderClock, 1000);
}

if (KEY) { authFetch(BASE+'?act=logs&limit=1').then(r=>r.json()).then(d=>{ if(d.ok!==false||d.msg!=='密码错误') showAdmin(); else { KEY=''; localStorage.removeItem('admin_key'); }}).catch(()=>{}); }

const pageTitles = {dashboard:'\u4eea\u8868\u76d8',logs:'\u8f6c\u53d1\u65e5\u5fd7',devices:'\u5728\u7ebf\u8bbe\u5907',android:'\u5b89\u5353\u63a7\u5236',stats:'\u6307\u7eb9\u73af\u5883\u7ba1\u7406',extconfig:'\u6d4f\u89c8\u5668\u63d2\u4ef6\u914d\u7f6e',accounts:'\u8d26\u53f7\u6388\u6743',update:'\u66f4\u65b0\u53d1\u5e03',verctrl:'\u7248\u672c\u63a7\u5236',data:'\u89e3\u5bc6\u6570\u636e',cache:'\u7f13\u5b58\u6e05\u7406'};
let currentPage = 'dashboard';
pageTitles.jsonmon = 'JSON文件监控';
pageTitles.sqlite = 'SQLite运行监控';
function switchPage(name, el) {
    if (deviceTimer && name !== 'devices') { clearInterval(deviceTimer); deviceTimer = null; }
    if (sqliteTimer && name !== 'sqlite') { clearInterval(sqliteTimer); sqliteTimer = null; const b=document.getElementById('sqliteAutoBtn'); if(b){b.textContent='自动刷新';b.className='btn btn-success btn-sm';} }
    currentPage = name;
    document.querySelectorAll('.page').forEach(p=>p.classList.add('hidden'));
    document.getElementById('page-'+name).classList.remove('hidden');
    document.querySelectorAll('.menu-item').forEach(m=>m.classList.remove('active'));
    if (el) el.classList.add('active');
    document.getElementById('pageTitle').textContent = pageTitles[name]||name;
    if (name==='dashboard') loadDashboard();
    else if (name==='logs') loadLogs();
    else if (name==='devices') { loadDevices(); if(!deviceTimer) deviceTimer=setInterval(loadDevices,10000); }
    else if (name==='android') { loadAndroidControl(); if(!deviceTimer) deviceTimer=setInterval(loadAndroidControl,10000); }
    else if (name==='stats') loadStats();
    else if (name==='extconfig') loadApi1Accounts();
    else if (name==='accounts') loadApi1Accounts();
    else if (name==='update') loadUpdateConfig();
    else if (name==='verctrl') loadVerCtrl();
    else if (name==='data') loadDumpList();
    else if (name==='jsonmon') loadJsonMonitor();
    else if (name==='sqlite') loadSQLiteMonitor();
    else if (name==='cache') loadCacheOverview();
}

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function escAttr(s){return esc(s).replace(/"/g,'&quot;');}
function logDeviceLabel(log){
    const values=[
        log&&log.platform,
        log&&log.device_type,
        log&&log.device_label,
        log&&log.client,
        log&&log.client_label,
        log&&log.source,
        log&&log.device_id,
        log&&log.fingerprint_name
    ].map(v=>String(v||'').trim()).filter(Boolean);
    const text=values.join(' ').toLowerCase();
    const source=String(log&&log.source||'').toLowerCase();
    if(text.includes('android')||text.includes('\u5b89\u5353'))return '\u5b89\u5353';
    if(text.includes('ios')||text.includes('iphone')||text.includes('ipad')||source.indexOf('ios_')===0)return 'iOS';
    if(text.includes('gejie-extension')||text.includes('extension')||text.includes('\u6d4f\u89c8\u5668\u63d2\u4ef6')||text.includes('\u7f51\u9875\u63d2\u4ef6')||source.indexOf('web_')===0||source.indexOf('decoded_extension')===0)return '\u7f51\u9875\u63d2\u4ef6';
    if(text.includes('gejie-controller')||text.includes('\u4e2d\u63a7')||source.indexOf('ctrl_')===0)return '\u4e2d\u63a7';
    if(text.includes('web'))return '\u7f51\u9875\u63d2\u4ef6';
    return '';
}
function authFetch(url,opts){opts=opts||{};if(!opts.headers)opts.headers={};opts.headers['X-Auth-Key']=KEY;return fetch(url,opts);}
async function viewJson(act,id,extra){
    try{
        let url=BASE+'?act='+act+'&id='+id;
        if(extra){
            Object.keys(extra).forEach(k=>{
                if(extra[k]!==undefined&&extra[k]!==null) url+='&'+encodeURIComponent(k)+'='+encodeURIComponent(extra[k]);
            });
        }
        const r=await authFetch(url);
        const text=await r.text();
        const blob=new Blob([text],{type:'application/json;charset=utf-8'});
        window.open(URL.createObjectURL(blob),'_blank');
    }catch(e){alert('加载失败: '+e.message);}
}

// ===== Dashboard =====
async function loadDashboard() {
    try {
        const [logsR, devR, statsR] = await Promise.all([
            authFetch(BASE+'?act=logs&limit=50').then(r=>r.json()),
            authFetch(BASE+'?act=devices').then(r=>r.json()),
            authFetch(BASE+'?act=stats').then(r=>r.json())
        ]);
        const logs = logsR.data||[];
        const online = devR.online_count||0;
        const users = statsR.data||[];
        const todayTotal = users.reduce((s,u)=>s+u.total,0);
        const todayOk = users.reduce((s,u)=>s+u.success,0);
        const ok = logs.filter(l=>l.status==='success').length;
        document.getElementById('dashStats').innerHTML = `
            <div class="stat-card"><div class="label">在线设备</div><div class="value blue">${online}</div></div>
            <div class="stat-card"><div class="label">今日请求</div><div class="value">${todayTotal}</div></div>
            <div class="stat-card"><div class="label">今日成功</div><div class="value green">${todayOk}</div></div>
            <div class="stat-card"><div class="label">活跃指纹</div><div class="value purple">${users.length}</div></div>`;
        renderLogEntries(logs.slice(0,10), 'dashLogs');
    } catch(e) { console.error(e); }
}

// ===== Logs =====
async function loadLogs() {
    const r = await authFetch(BASE+'?act=logs&limit=100');
    const d = await r.json();
    if (!d.ok) return;
    renderLogEntries(d.data||[], 'logList');
}
function renderLogEntries(logs, target) {
    const el = document.getElementById(target);
    if (!logs.length) { el.innerHTML='<div class="empty">暂无日志</div>'; return; }
    el.innerHTML = logs.map(l => {
        const st = l.status||'';
        const apiTag = `<span class="tag tag-${l.api_type===1?'blue':'info'}">${l.api_type===1?'聚星':'调速'}</span>`;
        const source = String(l.source||'');
        const deviceLabel = logDeviceLabel(l);
        const clientLabel = l.client_label || (source.indexOf('ctrl_')===0 ? '中控' : (source.indexOf('web_')===0 ? '网页插件' : ''));
        const deviceTag = deviceLabel ? `<span class="tag tag-info">\u8bbe\u5907:${esc(deviceLabel)}</span>` : '';
        const webTag = clientLabel && clientLabel!==deviceLabel ? `<span class="tag tag-info">${esc(clientLabel)}</span>` : '';
        let stTag = '';
        if(st==='success') stTag='<span class="tag tag-success">成功</span>';
        else if(st==='decrypt_fail'||st==='json_fail') stTag=`<span class="tag tag-danger">${st}</span>`;
        else if(st) stTag=`<span class="tag tag-warning">${st}</span>`;
        let body='';
        if(l.username) body+=`<b>用户:</b><code>${esc(l.username)}</code>${l.account_remark?'<span style="color:var(--danger);font-weight:600;font-size:12px;margin-left:4px">'+esc(l.account_remark)+'</span>':''} `;
        if(deviceLabel) body+=`<b>\u8bbe\u5907:</b><code>${esc(deviceLabel)}</code> `;
        if(l.group_id) body+=`<b>组:</b><code>${esc(l.group_id)}</code> `;
        if(l.task_info) body+=`<b>任务:</b><code>${esc(l.task_info.ID||JSON.stringify(l.task_info))}</code> `;
        if(l.encrypted_len) body+=`<b>加密:</b><code>${(l.encrypted_len/1024).toFixed(1)}KB</code> `;
        if(l.decrypted_len) body+=`<b>解密:</b><code>${(l.decrypted_len/1024).toFixed(1)}KB</code> `;
        if(l.extract_from) body+=`<b>提取:</b><code>${esc(l.extract_from)}</code> `;
        if(l.timing_ms){
            const t=l.timing_ms||{};
            body+='<b>timing:</b><code>'
                +'total '+(t.total||0)+'ms'
                +' / decrypt '+(t.aes_decrypt||0)
                +' / parse '+(t.decrypted_json||0)
                +' / extract '+(t.extract_response_body||0)
                +' / dump'+(t.dump||0)
                +' / forward '+(t.forward||0)
                +'</code> ';
        }
        if(l.forward_attempts&&l.forward_attempts.length>1) body+='<b>retry:</b><code>'+l.forward_attempts.length+'</code> ';
        let resp='';
        if(l.response){ const rs=typeof l.response==='string'?l.response:JSON.stringify(l.response,null,2); resp=`<pre class="resp">${esc(rs.substring(0,500))}</pre>`; }
        if(l.error) resp+=`<pre class="resp" style="color:var(--danger)">${esc(l.error)}</pre>`;
        const actions=[];
        if(l.dump_id) actions.push(`<a href="javascript:void(0)" onclick="viewJson('dump','${encodeURIComponent(l.dump_id)}')">解密数据</a>`);
        if(l.upload_id){
            actions.push(`<a href="javascript:void(0)" onclick="viewJson('upload','${encodeURIComponent(l.upload_id)}',{field:'response'})">上传响应</a>`);
            actions.push(`<a href="javascript:void(0)" onclick="viewJson('upload','${encodeURIComponent(l.upload_id)}',{full:1})">上传详情</a>`);
        }
        const actionHtml=actions.length?`<div class="log-actions">${actions.join('')}</div>`:'';
        return `<div class="log-entry"><div class="log-meta">${apiTag} ${deviceTag} ${webTag} ${stTag} <span style="color:var(--muted);font-size:12px">${l.time||''} &nbsp; IP:${l.ip||'-'}</span></div><div class="log-detail">${body}</div>${actionHtml} ${resp}</div>`;
    }).join('');
}
function toggleAutoLog() {
    const btn=document.getElementById('autoLogBtn');
    if(autoLogTimer){clearInterval(autoLogTimer);autoLogTimer=null;btn.textContent='自动刷新';btn.className='btn btn-success btn-sm';}
    else{loadLogs();autoLogTimer=setInterval(loadLogs,5000);btn.textContent='停止刷新';btn.className='btn btn-default btn-sm';}
}
async function clearLogs(){
    if(!confirm('确定清空所有日志和数据?'))return;
    await authFetch(BASE+'?act=clear');
    alert('已清空');loadLogs();
}

// ===== Devices =====
async function loadDevices() {
    const r = await authFetch(BASE+'?act=devices');
    const d = await r.json();
    if(!d.ok) return;
    document.getElementById('onlineCount').textContent='('+d.online_count+'台在线)';
    const el=document.getElementById('deviceList');
    const devs=d.data||[];
    if(!devs.length){el.innerHTML='<div class="empty">当前没有在线或已禁用设备</div>';return;}

    // 按账号分组
    const byUser={};
    for(const dv of devs){
        const u=dv.username||'unknown';
        if(!byUser[u]) byUser[u]={username:u,account_remark:dv.account_remark||'',devices:[],api_type:dv.api_type||0};
        byUser[u].devices.push(dv);
        if(dv.account_remark) byUser[u].account_remark=dv.account_remark;
    }
    const users=Object.values(byUser).sort((a,b)=>b.devices.length-a.devices.length);

    el.innerHTML=users.map(u=>{
        const remark=u.account_remark?`<span style="color:var(--danger);font-weight:600;font-size:12px;margin-left:8px">${esc(u.account_remark)}</span>`:'';
        const allDisabled=u.devices.every(d=>d.disabled);
        const someDisabled=u.devices.some(d=>d.disabled);
        const userTag=allDisabled?'<span class="tag tag-danger">全部禁用</span>':someDisabled?'<span class="tag tag-warning">部分禁用</span>':'<span class="tag tag-success">在线</span>';
        const batchBtn=allDisabled
            ?`<button class="btn btn-success btn-sm" onclick="toggleUserDevices('${escAttr(u.username)}',0)">全部启用</button>`
            :`<button class="btn btn-danger btn-sm" onclick="toggleUserDevices('${escAttr(u.username)}',1)">全部禁用</button>`;

        const devRows=u.devices.map(dv=>{
            const dis=!!dv.disabled;
            const isOnline=!!dv.online;
            const st=dis
                ?`<span class="tag tag-danger" style="font-size:11px">禁用${isOnline?'在线':'离线'}</span>`
                :`<span class="tag tag-success" style="font-size:11px">${isOnline?'在线':'离线'}</span>`;
            const deviceLabel=dv.device_label||(String(dv.platform||dv.device_type||'').toLowerCase()==='ios'?'iOS设备':'-');
            const singleBtn=dis
                ?`<button class="btn btn-success btn-sm" onclick="toggleDevice('${esc(dv.key)}',0)">\u542f\u7528</button>`
                :`<button class="btn btn-danger btn-sm" onclick="toggleDevice('${esc(dv.key)}',1)">\u7981\u7528</button>`;
            return `<tr>
                <td>${st}</td>
                <td>${esc(deviceLabel)} ${esc(dv.fingerprint_name||((dv.fingerprint_id||dv.fingerprint_key||'').substring(0,14))||'-')}</td>
                <td style="font-size:12px">${esc((dv.device_id||'-').substring(0,14))}</td>
                <td style="font-size:12px">${esc(dv.ip||'-')}</td>
                <td style="font-size:12px;color:var(--muted)">${esc((dv.last_seen||'').substring(11)||'-')}</td>
                <td style="display:flex;gap:6px;flex-wrap:wrap">${singleBtn}</td>
            </tr>`;
        }).join('');

        return `<div class="stats-user">
            <div class="stats-user-head">
                <div>
                    <b style="font-size:15px">${esc(u.username)}</b> ${userTag}${remark}
                    <div class="stats-records">${u.api_type===1?'聚星':'调速'} 设备数:${u.devices.length} 组:${esc(u.devices[0]?.group_id||'-')}</div>
                </div>
                <div style="display:flex;gap:6px">${batchBtn}</div>
            </div>
            <table style="margin-top:10px"><thead><tr><th style="width:60px">状态</th><th>指纹</th><th>设备ID</th><th>IP</th><th style="width:70px">心跳</th><th style="width:150px">操作</th></tr></thead><tbody>${devRows}</tbody></table>
        </div>`;
    }).join('');
}
async function toggleDevice(dk,dis){
    let reason='';
    if(dis){reason=prompt('禁用原因（App会显示）','账号已被下线，禁止使用');if(!reason)return;}
    await authFetch(BASE+'?act=device_toggle&device_key='+encodeURIComponent(dk)+'&disabled='+dis+'&reason='+encodeURIComponent(reason));
    loadDevices();
}
async function toggleUserDevices(username,dis){
    let reason='';
    if(dis){reason=prompt('禁用 '+username+' 所有设备的原因','账号已被下线，禁止使用');if(!reason)return;}
    await authFetch(BASE+'?act=device_toggle_user&username='+encodeURIComponent(username)+'&disabled='+dis+'&reason='+encodeURIComponent(reason));
    loadDevices();
}


async function setAndroidCommand(dk,cmd){
    if(!dk)return;
    await authFetch(BASE+'?act=android_device_command&device_key='+encodeURIComponent(dk)+'&command='+encodeURIComponent(cmd));
    if(currentPage==='android') loadAndroidControl(); else loadDevices();
}
function isAjieAndroidDevice(x){
    const client=String(x&&x.client||'').toLowerCase();
    const label=String(x&&x.client_label||'').toLowerCase();
    return client==='ajie-android' || (label.includes('ajie') && label.includes('android'));
}

// ===== Stats =====

async function loadAndroidControl(){
    const r=await authFetch(BASE+'?act=devices');
    const d=await r.json();
    if(!d.ok)return;
    const rows=(d.data||[]).filter(isAjieAndroidDevice);
    const el=document.getElementById('androidControlList');
    const cnt=document.getElementById('androidCount');
    if(cnt)cnt.textContent='('+rows.length+' \u53f0)';
    if(!rows.length){el.innerHTML='<div class="empty">\u6682\u65e0\u5b89\u5353 App \u8bbe\u5907</div>';return;}
    el.innerHTML=`<table><thead><tr><th>\u72b6\u6001</th><th>\u4efb\u52a1\u8d26\u6237</th><th>\u8bbe\u5907</th><th>\u4f1a\u8bdd</th><th>\u4efb\u52a1\u767b\u5f55</th><th>\u547d\u4ee4</th><th>\u5fc3\u8df3</th><th style="width:360px">\u63a7\u5236</th></tr></thead><tbody>${rows.map(dv=>{
        const online=!!dv.online, dis=!!dv.disabled;
        const st=dis?'<span class="tag tag-danger">\u7981\u7528</span>':(online?'<span class="tag tag-success">\u5728\u7ebf</span>':'<span class="tag tag-warning">\u79bb\u7ebf</span>');
        const sess=dv.has_android_session||dv.android_has_cookie?'<span class="tag tag-success">\u5df2\u540c\u6b65</span>':'<span class="tag tag-warning">\u672a\u540c\u6b65</span>';
        const task=dv.android_has_task_token?'<span class="tag tag-success">\u5df2\u767b\u5f55</span>':'<span class="tag tag-warning">\u672a\u767b\u5f55</span>';
        const cmd=esc(dv.android_command||'run');
        const key=esc(dv.key||'');
        return `<tr><td>${st}</td><td>${esc(dv.username||'-')}</td><td>${esc(dv.device_label||dv.device_id||'-')}<div style="font-size:11px;color:var(--muted)">${esc((dv.device_id||'').substring(0,18))}</div></td><td>${sess}</td><td>${task}</td><td>${cmd}</td><td>${esc((dv.last_seen||'').substring(11)||'-')}</td><td style="display:flex;gap:6px;flex-wrap:wrap"><button class="btn btn-success btn-sm" onclick="setAndroidCommand('${key}','run')">\u542f\u52a8</button><button class="btn btn-warning btn-sm" onclick="setAndroidCommand('${key}','pause')">\u6682\u505c</button><button class="btn btn-default btn-sm" onclick="setAndroidCommand('${key}','sync_session')">\u540c\u6b65\u4f1a\u8bdd</button><button class="btn btn-danger btn-sm" onclick="setAndroidCommand('${key}','clear_session')">\u6e05\u4f1a\u8bdd</button><button class="btn btn-danger btn-sm" onclick="toggleDevice('${key}',1)">\u7981\u7528</button></td></tr>`;
    }).join('')}</tbody></table>`;
}
async function androidCommandAll(cmd){
    const r=await authFetch(BASE+'?act=devices'); const d=await r.json();
    const rows=(d.data||[]).filter(isAjieAndroidDevice);
    for(const dv of rows){ if(dv.key) await authFetch(BASE+'?act=android_device_command&device_key='+encodeURIComponent(dv.key)+'&command='+encodeURIComponent(cmd)); }
    loadAndroidControl();
}

async function loadStats(){
    const sel=document.getElementById('statsDate');
    const date=sel.value||'';
    const r=await authFetch(BASE+'?act=stats'+(date?'&date='+encodeURIComponent(date):''));
    const d=await r.json();
    if(!d.ok)return;
    if(d.dates&&d.dates.length){const cv=sel.value||d.date;sel.innerHTML=d.dates.map(dt=>`<option value="${dt}" ${dt===cv?'selected':''}>${dt}</option>`).join('');}
    const el=document.getElementById('statsBody');
    const fps=d.data||[];
    if(!fps.length){el.innerHTML='<div class="empty">当天暂无指纹记录</div>';return;}

    // 按账号分组
    const byUser={};
    for(const fp of fps){
        const u=fp.username||'unknown';
        if(!byUser[u]) byUser[u]={username:u,account_remark:fp.account_remark||'',fingerprints:[],total:0,generate:0,write:0};
        byUser[u].fingerprints.push(fp);
        byUser[u].total+=fp.total||0;
        byUser[u].generate+=fp.generate||0;
        byUser[u].write+=fp.write||0;
        if(fp.account_remark) byUser[u].account_remark=fp.account_remark;
    }
    const users=Object.values(byUser).sort((a,b)=>b.total-a.total);
    const totalGen=fps.reduce((s,u)=>s+(u.generate||0),0);
    const totalWrite=fps.reduce((s,u)=>s+(u.write||0),0);

    let html=`<div class="stat-row" style="margin-bottom:16px">
        <div class="stat-card"><div class="label">日期</div><div class="value" style="font-size:18px">${esc(d.date)}</div></div>
        <div class="stat-card"><div class="label">活跃账号</div><div class="value blue">${users.length}</div></div>
        <div class="stat-card"><div class="label">生成指纹</div><div class="value purple">${totalGen}</div></div>
        <div class="stat-card"><div class="label">写入指纹(v32)</div><div class="value green">${totalWrite}</div></div>
    </div>`;

    html+=users.map(u=>{
        const remark=u.account_remark?` <span style="color:var(--danger);font-weight:600">${esc(u.account_remark)}</span>`:'';

        // 指纹明细表格
        let fpTable='';
        if(u.fingerprints.length>0){
            fpTable=`<table style="margin-top:10px"><thead><tr><th>指纹名称</th><th>指纹ID</th><th>设备ID</th><th style="text-align:center">生成</th><th style="text-align:center">写入</th><th style="text-align:center">总计</th><th>最后活跃</th></tr></thead><tbody>`;
            for(const fp of u.fingerprints.sort((a,b)=>b.total-a.total)){
                const fpName=fp.fingerprint_name||'-';
                const fpId=(fp.fingerprint_id||fp.fingerprint_key||'-').substring(0,20);
                const devId=(fp.device_id||'-').substring(0,14);
                fpTable+=`<tr>
                    <td><b>${esc(fpName)}</b></td>
                    <td><code style="font-size:11px">${esc(fpId)}</code></td>
                    <td style="font-size:12px">${esc(devId)}</td>
                    <td style="text-align:center;color:var(--info)">${fp.generate||0}</td>
                    <td style="text-align:center;color:var(--success)">${fp.write||0}</td>
                    <td style="text-align:center"><b>${fp.total||0}</b></td>
                    <td style="font-size:12px;color:var(--muted)">${esc(fp.last_seen||'-')}</td>
                </tr>`;
            }
            fpTable+='</tbody></table>';
        }

        // 最近操作记录
        const allRec=u.fingerprints.flatMap(fp=>(fp.records||[]).map(r=>({...r,fp_name:fp.fingerprint_name||fp.fingerprint_id||''})));
        allRec.sort((a,b)=>b.time.localeCompare(a.time));
        const last8=allRec.slice(0,8).map(r=>
            `<span class="tag ${r.event==='write'?'tag-success':'tag-blue'}" style="margin-right:4px">${r.time} ${r.event==='write'?'写入':'生成'}${r.fp_name?' '+esc(r.fp_name.substring(0,10)):''}</span>`
        ).join('');

        return `<div class="stats-user">
            <div class="stats-user-head">
                <div><b style="font-size:15px">${esc(u.username)}</b>${remark}
                    <div class="stats-records">指纹数:${u.fingerprints.length} 组:${esc(u.fingerprints[0]?.group_id||'-')}</div>
                </div>
                <div class="stats-nums">
                    <span>总计 <b>${u.total}</b></span>
                    <span style="color:var(--info)">生成 <b>${u.generate}</b></span>
                    <span style="color:var(--success)">写入 <b>${u.write}</b></span>
                </div>
            </div>
            ${fpTable}
            ${last8?`<div class="stats-records" style="margin-top:8px">${last8}</div>`:''}
        </div>`;
    }).join('');
    el.innerHTML=html;
}

async function clearStats(){
    const sel=document.getElementById('statsDate');
    const date=sel.value||'';
    if(!confirm('确定清除 '+(date||'今天')+' 的指纹环境统计?'))return;
    const r=await authFetch(BASE+'?act=clear_stats'+(date?'&date='+encodeURIComponent(date):''));
    const d=await r.json();
    if(!d.ok) return alert(d.msg||'清除失败');
    loadStats();
}

// ===== API Accounts =====
let api1Data=[];
let extAccountData=[], extServerBaseUrl='';
let acctModalMode='', acctEditApiType=0, acctEditUsername='';
const accountPager={1:{page:1,size:10},2:{page:1,size:10},3:{page:1,size:10}};
const accountSelection={1:new Set(),2:new Set(),3:new Set()};

function accountDataByType(apiType){
    return api1Data;
}

function accountTargetByType(apiType){
    return 'api1Table';
}

function updateBatchDeleteButton(apiType){
    const btn=document.getElementById('batchDelete'+apiType);
    if(!btn)return;
    const count=accountSelection[apiType]?.size||0;
    btn.disabled=count<=0;
    btn.textContent=count>0?'批量删除('+count+')':'批量删除';
}

function syncAccountSelection(apiType){
    const data=accountDataByType(apiType);
    const valid=new Set(data.map(a=>a.username||a));
    for(const name of [...accountSelection[apiType]]) if(!valid.has(name)) accountSelection[apiType].delete(name);
    updateBatchDeleteButton(apiType);
}

function setAccountPage(apiType,page){
    const data=accountDataByType(apiType);
    const pager=accountPager[apiType];
    const totalPages=Math.max(1,Math.ceil(data.length/pager.size));
    pager.page=Math.min(Math.max(1,page),totalPages);
    renderAccountTable(data,accountTargetByType(apiType),apiType);
}

function setAccountPageSize(apiType,size){
    const pager=accountPager[apiType];
    pager.size=Math.max(5,parseInt(size,10)||10);
    pager.page=1;
    renderAccountTable(accountDataByType(apiType),accountTargetByType(apiType),apiType);
}

async function loadApi1Accounts(){
    const [r1,r5]=await Promise.all([
        authFetch(BASE+'?act=api1_accounts').then(r=>r.json()),
        authFetch(BASE+'?act=decoded_ext_accounts').then(r=>r.json())
    ]);
    if(r1.ok){ api1Data=r1.data||[]; syncAccountSelection(1); renderAccountTable(api1Data,'api1Table',1); }
    if(r5.ok){ extAccountData=r5.data||[]; extServerBaseUrl=r5.serverBaseUrl||BASE; renderExtAccountTable(); }
    const api1Count=document.getElementById('api1Count');
    if(api1Count) api1Count.textContent='('+api1Data.length+'个)';
}
function formatTaskAccountNames(names, count, disabledNames='', disabledCount=0, totalCount=0){
    const list=String(names||'').split(',').map(s=>s.trim()).filter(Boolean);
    const total=Number(count||list.length||0);
    const shown=list.slice(0,10);
    const hidden=Math.max(0,total-shown.length);
    const text=shown.join(', ')+(hidden>0?` \u7b49 ${hidden} \u4e2a`:'');
    const disabledList=String(disabledNames||'').split(',').map(s=>s.trim()).filter(Boolean);
    const disabledTotal=Number(disabledCount||disabledList.length||0);
    const disabledShown=disabledList.slice(0,8).join(', ');
    const allTotal=Number(totalCount||total+disabledTotal||0);
    const disabledHtml=disabledTotal>0?`<div style="font-size:12px;color:var(--danger);margin-top:4px">\u4e0d\u53c2\u4e0e\u4efb\u52a1 ${disabledTotal} \u4e2a\uff1a${esc(disabledShown)}${disabledTotal>8?' \u7b49 '+(disabledTotal-8)+' \u4e2a':''}</div>`:'';
    return `<code title="${escAttr(list.join(', '))}" style="display:block;max-width:720px;white-space:normal;word-break:break-word;line-height:1.7">${esc(text||'-')}</code><div style="font-size:12px;color:var(--muted);margin-top:4px">\u53ef\u62c9\u4efb\u52a1 ${total} / \u603b\u6570 ${allTotal}${hidden>0?'\uff0c\u5df2\u7701\u7565 '+hidden+' \u4e2a':''}</div>${disabledHtml}`;
}
function renderExtAccountTable(){
    const el=document.getElementById('extAccountTable');
    if(!el)return;
    document.getElementById('extAccountCount').textContent='('+extAccountData.length+'\u4e2a)';
    if(!extAccountData.length){el.innerHTML='<div class="empty">\u6682\u65e0\u63d2\u4ef6\u8d26\u53f7</div>';return;}
    el.innerHTML=`<table><thead><tr><th>#</th><th>\u4e0b\u53d1ID</th><th>\u63d2\u4ef6Token</th><th>\u4efb\u52a1\u8d26\u53f7</th><th style="width:82px;text-align:center">\u6a21\u5f0f</th><th>\u72b6\u6001</th><th>\u5907\u6ce8</th><th style="width:440px">\u64cd\u4f5c</th></tr></thead><tbody>${
        extAccountData.map((a,i)=>`<tr>
            <td>${i+1}</td>
            <td><code>${esc(a.accountId)}</code></td>
            <td><code>${esc((a.token||'').slice(0,10)+'...'+(a.token||'').slice(-6))}</code></td>
            <td>${formatTaskAccountNames(a.api1_usernames,a.api1_count,a.api1_disabled_usernames,a.api1_disabled_count,a.api1_total_count)}</td>
            <td style="text-align:center">${a.task_mode==='concurrent'?'<span class="tag tag-success">\u5e76\u53d1 '+(a.task_parallelism||a.api1_count||1)+'</span>':'<span class="tag tag-blue">\u8f6e\u8be2</span>'}</td>
            <td>${a.enabled?'<span class="tag tag-success">\u542f\u7528</span>':'<span class="tag tag-danger">\u505c\u7528</span>'}</td>
            <td>${esc(a.remark||'-')}</td>
            <td>
                <button class="btn btn-primary btn-sm" onclick="copyExtConfig('${escAttr(a.accountId)}')">\u590d\u5236\u914d\u7f6e</button>
                <button class="btn btn-success btn-sm" onclick="copyParallelControlLink('${escAttr(a.accountId)}')">\u590d\u5236\u63a7\u5236\u94fe\u63a5</button>
                <button class="btn btn-info btn-sm" onclick="showExtAccountModal('${escAttr(a.accountId)}')">\u4fee\u6539</button>
                <button class="btn btn-warning btn-sm" onclick="toggleExtAccount('${escAttr(a.accountId)}',${a.enabled?0:1})">${a.enabled?'\u505c\u7528':'\u542f\u7528'}</button>
                <button class="btn btn-default btn-sm" onclick="resetExtToken('${escAttr(a.accountId)}')">\u91cd\u7f6eToken</button>
                <button class="btn btn-default btn-sm" onclick="resetParallelControlLink('${escAttr(a.accountId)}')">\u91cd\u7f6e\u63a7\u5236\u94fe\u63a5</button>
                <button class="btn btn-danger btn-sm" onclick="deleteExtAccount('${escAttr(a.accountId)}')">\u5220\u9664</button>
            </td>
        </tr>`).join('')
    }</tbody></table>`;
}
function extAccountById(accountId){
    return extAccountData.find(a=>a.accountId===accountId)||null;
}

function extSelectedDisabledTaskUsers(){
    return [...document.querySelectorAll('#extDisabledTaskAccounts input[type="checkbox"]:checked')]
        .map(el => (el.value || '').trim())
        .filter(Boolean);
}

function renderExtDisabledTaskAccounts(selected){
    const host=document.getElementById('extDisabledTaskAccounts');
    if(!host)return;
    const rows=parseExtTaskAccountLines(document.getElementById('extApi1Accounts')?.value||'');
    const picked=new Set((selected||[]).map(x=>String(x||'').trim()).filter(Boolean));
    const seen=new Set();
    const list=[];
    for(const row of rows){
        const username=String(row.username||'').trim();
        if(!username || seen.has(username)) continue;
        seen.add(username);
        list.push({username, remark:String(row.remark||'').trim()});
    }
    if(!list.length){
        host.innerHTML='<div style="font-size:12px;color:var(--muted);line-height:1.6">\u8bf7\u5148\u5728\u4e0a\u9762\u7684\u4efb\u52a1\u8d26\u53f7\u6c60\u91cc\u586b\u5199\u8d26\u53f7\uff0c\u518d\u52fe\u9009\u4e0d\u53c2\u4e0e\u4efb\u52a1\u7684\u8d26\u53f7\u3002</div>';
        return;
    }
    host.innerHTML=list.map((item,idx)=>`<label style="display:flex;align-items:center;gap:10px;padding:8px 10px;border:1px solid #e2e8f0;border-radius:8px;background:#f8fafc;cursor:pointer">
        <input type="checkbox" value="${escAttr(item.username)}" ${picked.has(item.username)?'checked':''}>
        <span style="font-family:monospace;font-size:13px;word-break:break-all">${esc(item.username)}</span>
        ${item.remark?`<span style="font-size:12px;color:var(--muted)">(${esc(item.remark)})</span>`:''}
    </label>`).join('');
}
function extConfigText(a){
    return JSON.stringify({
        serverBaseUrl: extServerBaseUrl||BASE,
        accountId: a.accountId,
        token: a.token,
        idleDelayMs: 5000,
        errorDelayMs: 4000,
        captureTimeoutMs: 180000,
        deadlineBufferMs: 5000
    },null,2);
}

async function copyText(text){
    try{ await navigator.clipboard.writeText(text); alert('已复制'); }
    catch(e){ prompt('复制下面内容',text); }
}

function copyExtConfig(accountId){
    const a=extAccountById(accountId);
    if(!a)return alert('未找到账号');
    copyText(extConfigText(a));
}

function parallelControlLinkText(a){
    if(a?.parallel_control_url)return a.parallel_control_url;
    if(a?.parallel_control_token)return '?act=parallel_control&t='+encodeURIComponent(a.parallel_control_token);
    return '';
}

function copyParallelControlLink(accountId){
    const a=extAccountById(accountId);
    if(!a)return alert('未找到账号');
    const link=parallelControlLinkText(a);
    if(!link)return alert('该账号还没有控制链接，请刷新账号列表后再试');
    copyText(link);
}

function showExtAccountModal(accountId){
    const a=accountId?extAccountById(accountId):null;
    const accountLines=(a?.api1_accounts||[]).map(x=>`${x.username||''}||${x.remark||''}`).join('\n');
    const disabledTaskUsers=(a?.api1_accounts||[]).filter(x=>!x.enabled).map(x=>x.username||'').filter(Boolean);
    const taskParallelism=Math.max(1,parseInt(a?.task_parallelism||a?.api1_count||1,10)||1);
    acctModalMode=accountId?'extEdit':'extAdd';
    acctEditUsername=accountId||'';
    document.getElementById('acctModalTitle').textContent=accountId?'\u4fee\u6539\u63d2\u4ef6\u8d26\u53f7':'\u65b0\u589e\u63d2\u4ef6\u8d26\u53f7';
    document.getElementById('acctModalBody').innerHTML=`
        <div class="form-item" style="margin-bottom:12px"><label>\u4e0b\u53d1ID</label><input id="extAccountId" value="${escAttr(a?.accountId||'')}" placeholder="\u7559\u7a7a\u81ea\u52a8\u751f\u6210" ${a?'disabled':''} style="height:40px;border:2px solid #e2e8f0;border-radius:8px;padding:0 12px;font-size:14px;width:100%;background:#f8fafc"></div>
        <div class="form-item" style="margin-bottom:12px"><label>\u62c9\u4efb\u52a1\u6a21\u5f0f</label><select id="extTaskMode" style="height:40px;border:2px solid #e2e8f0;border-radius:8px;padding:0 12px;font-size:14px;width:100%;background:#f8fafc;font-family:var(--font)"><option value="poll" ${(a?.task_mode||'poll')==='poll'?'selected':''}>\u8f6e\u8be2</option><option value="concurrent" ${(a?.task_mode||'poll')==='concurrent'?'selected':''}>\u5e76\u53d1</option></select></div>
        <div class="form-item" style="margin-bottom:12px"><label>\u5e76\u53d1\u6570\u91cf</label><input id="extTaskParallelism" type="number" min="1" step="1" value="${taskParallelism}" placeholder="\u4f8b\u5982 5" style="height:40px;border:2px solid #e2e8f0;border-radius:8px;padding:0 12px;font-size:14px;width:100%;background:#f8fafc"><div style="font-size:12px;color:var(--muted);margin-top:6px">\u5e76\u53d1\u6a21\u5f0f\u4e0b\u751f\u6548\uff1b\u6bd4\u5982\u8be5\u7528\u6237\u6709 10 \u4e2a\u4efb\u52a1\u8d26\u53f7\uff0c\u586b 5 \u5c31\u53ea\u540c\u65f6\u62c9\u53d6/\u6253\u5f00 5 \u6761\u3002</div></div>
        <div class="form-item" style="margin-bottom:12px"><label>\u8be5\u7528\u6237\u4e0b\u7684\u4efb\u52a1\u8d26\u53f7\u6c60\uff0c\u6bcf\u884c\uff1a\u4efb\u52a1\u8d26\u53f7 \u4efb\u52a1\u5bc6\u7801 \u8d26\u53f7\u5907\u6ce8\uff1b\u652f\u6301 Tab\u3001\u7a7a\u683c\u3001|\u3001\u9017\u53f7\u3001\u5206\u53f7</label><textarea id="extApi1Accounts" rows="8" placeholder="task_user1&#9;task_pass1&#10;task_user2|task_pass2|\u8d26\u53f72" style="height:180px;width:100%;border:2px solid #e2e8f0;border-radius:8px;padding:10px 12px;font-size:14px;resize:vertical;font-family:monospace;background:#f8fafc">${esc(accountLines)}</textarea><div style="font-size:12px;color:var(--muted);margin-top:6px">\u4fee\u6539\u65f6\u5bc6\u7801\u7559\u7a7a\u8868\u793a\u4fdd\u7559\u539f\u5bc6\u7801\uff0c\u4f8b\u5982\uff1atask_user1||\u8d26\u53f71</div></div>
        <div class="form-item" style="margin-bottom:12px"><label>\u4e0d\u53c2\u4e0e\u4efb\u52a1\u7684\u8d26\u6237\uff08\u52fe\u9009\u540e\u4e0d\u4f1a\u62c9\u4efb\u52a1\uff09</label><div id="extDisabledTaskAccounts" style="display:grid;gap:8px;margin-top:8px"></div><div style="font-size:12px;color:var(--muted);margin-top:6px">\u4e0d\u60f3\u8ba9\u67d0\u4e2a\u4efb\u52a1\u8d26\u53f7\u7ee7\u7eed\u62c9\u53d6\u4efb\u52a1\uff0c\u5c31\u52fe\u9009\u5b83\u3002</div></div>
        <div class="form-item"><label>\u5907\u6ce8</label><input id="extRemark" value="${escAttr(a?.remark||'')}" placeholder="\u7528\u6237\u5907\u6ce8" style="height:40px;border:2px solid #e2e8f0;border-radius:8px;padding:0 12px;font-size:14px;width:100%;background:#f8fafc"></div>`;
    const extApi1AccountsEl=document.getElementById('extApi1Accounts');
    if(extApi1AccountsEl){
        extApi1AccountsEl.addEventListener('input', ()=>renderExtDisabledTaskAccounts(extSelectedDisabledTaskUsers()));
    }
    renderExtDisabledTaskAccounts(disabledTaskUsers);
    document.getElementById('accountModal').classList.remove('hidden');
}
function showExtBatchModal(){
    acctModalMode='extBatch';
    document.getElementById('acctModalTitle').textContent='\u6279\u91cf\u751f\u6210\u63d2\u4ef6\u8d26\u53f7';
    document.getElementById('acctModalBody').innerHTML=`
        <div class="form-item"><label>\u6bcf\u884c\u4e00\u4e2a\uff1a\u4efb\u52a1\u8d26\u53f7 \u4efb\u52a1\u5bc6\u7801 \u5907\u6ce8\uff1b\u652f\u6301 Tab\u3001\u7a7a\u683c\u3001|\u3001\u9017\u53f7\u3001\u5206\u53f7</label>
        <textarea id="extBatchInput" rows="10" placeholder="user1&#9;pass1&#10;user2|pass2|\u5907\u6ce82" style="height:220px;width:100%;border:2px solid #e2e8f0;border-radius:8px;padding:10px 12px;font-size:14px;resize:vertical;font-family:monospace;background:#f8fafc"></textarea></div>`;
    document.getElementById('accountModal').classList.remove('hidden');
}

function parseExtTaskAccountLines(text){
    return String(text||'').split(/\r?\n/).map(line=>{
        const trimmed=line.trim();
        if(!trimmed)return null;
        let parts, joiner=' ';
        const normalized=trimmed.replace(/\uFF5C/g,'|');
        if(normalized.includes('|')){ parts=normalized.split('|'); joiner='|'; }
        else if(/\t/.test(trimmed)){ parts=trimmed.split(/\t+/); joiner=' '; }
        else if(/[\uFF0C,]/.test(trimmed)){ parts=trimmed.split(/[\uFF0C,]/); joiner=','; }
        else if(/[\uFF1B;]/.test(trimmed)){ parts=trimmed.split(/[\uFF1B;]/); joiner=';'; }
        else parts=trimmed.split(/\s+/);
        return {
            username:(parts[0]||'').trim(),
            password:(parts[1]||'').trim(),
            remark:(parts.slice(2).join(joiner)||'').trim(),
            enabled:true
        };
    }).filter(x=>x&&x.username);
}

async function saveExtAccountFromModal(){
    const disabled=new Set(extSelectedDisabledTaskUsers());
    const accounts=parseExtTaskAccountLines(document.getElementById('extApi1Accounts')?.value||'').map(row=>({
        ...row,
        enabled:!disabled.has(row.username)
    }));
    const payload={
        accountId:(document.getElementById('extAccountId')?.value||acctEditUsername||'').trim(),
        api1_accounts:accounts,
        task_mode:(document.getElementById('extTaskMode')?.value||'poll').trim(),
        task_parallelism:Math.max(1,parseInt(document.getElementById('extTaskParallelism')?.value||'1',10)||1),
        remark:(document.getElementById('extRemark')?.value||'').trim(),
        enabled:true
    };
    const r=await authFetch(BASE+'?act=decoded_ext_account_save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const d=await r.json();
    if(!d.ok)return alert(d.msg||'\u4fdd\u5b58\u5931\u8d25');
    closeAccountModal();
    await loadApi1Accounts();
    if(d.account) copyText(extConfigText(d.account));
}
async function saveExtBatchFromModal(){
    const batch=(document.getElementById('extBatchInput')?.value||'').trim();
    if(!batch)return alert('\u8bf7\u8f93\u5165\u4efb\u52a1\u8d26\u53f7\u548c\u5bc6\u7801');
    const r=await authFetch(BASE+'?act=decoded_ext_account_batch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({batch})});
    const d=await r.json();
    if(!d.ok)return alert(d.msg||'\u64cd\u4f5c\u5931\u8d25');
    closeAccountModal();
    await loadApi1Accounts();
    const text=(d.created||[]).map(a=>extConfigText(a)).join('\n\n');
    if(text) copyText(text);
}

async function toggleExtAccount(accountId,enabled){
    await authFetch(BASE+'?act=decoded_ext_account_toggle&accountId='+encodeURIComponent(accountId)+'&enabled='+enabled);
    loadApi1Accounts();
}

async function resetExtToken(accountId){
    if(!confirm('重置后旧插件 token 会失效，确定继续？'))return;
    await authFetch(BASE+'?act=decoded_ext_account_token&accountId='+encodeURIComponent(accountId));
    loadApi1Accounts();
}

async function resetParallelControlLink(accountId){
    if(!confirm('重置后旧的用户控制链接会失效，确定继续？'))return;
    await authFetch(BASE+'?act=decoded_ext_account_parallel_token&accountId='+encodeURIComponent(accountId));
    await loadApi1Accounts();
    alert('控制链接已重置，请重新复制发给用户');
}

async function deleteExtAccount(accountId){
    if(!confirm('确定删除插件账号 '+accountId+' ?'))return;
    await authFetch(BASE+'?act=decoded_ext_account_delete&accountId='+encodeURIComponent(accountId));
    loadApi1Accounts();
}

function parseAccountBatchLine(line){
    const trimmed=String(line||'').trim();
    if(!trimmed)return null;
    let parts, joiner=' ';
    const normalized=trimmed.replace(/\uFF5C/g,'|');
    if(normalized.includes('|')){ parts=normalized.split('|'); joiner='|'; }
    else if(/\t/.test(trimmed)){ parts=trimmed.split(/\t+/); }
    else if(/[\uFF0C,]/.test(trimmed)){ parts=trimmed.split(/[\uFF0C,]/); joiner=','; }
    else if(/[\uFF1B;]/.test(trimmed)){ parts=trimmed.split(/[\uFF1B;]/); joiner=';'; }
    else parts=trimmed.split(/\s+/);
    const name=(parts[0]||'').trim();
    const remark=(parts.slice(1).join(joiner)||'').trim();
    return name?{username:name,remark}:null;
}

function toggleAccountSelection(apiType,username,checked){
    if(checked) accountSelection[apiType].add(username);
    else accountSelection[apiType].delete(username);
    updateBatchDeleteButton(apiType);
}

function toggleAccountPageSelection(apiType,checked){
    const pager=accountPager[apiType]||{page:1,size:10};
    const data=accountDataByType(apiType);
    const start=(pager.page-1)*pager.size;
    data.slice(start,start+pager.size).forEach(a=>{
        const name=a.username||a;
        if(checked) accountSelection[apiType].add(name);
        else accountSelection[apiType].delete(name);
    });
    renderAccountTable(data,accountTargetByType(apiType),apiType);
}

function renderAccountTable(accounts, targetId, apiType){
    const el=document.getElementById(targetId);
    const label=apiType===3?'编号':'账号';
    if(!accounts.length){accountSelection[apiType]?.clear();updateBatchDeleteButton(apiType);el.innerHTML='<div class="empty">暂无'+label+'</div>';return;}
    el.innerHTML=`<table><thead><tr><th style="width:50px">#</th><th>${label}</th><th>备注</th><th style="width:78px;text-align:center">修改</th><th style="width:78px;text-align:center">操作</th></tr></thead><tbody>${
        accounts.map((a,i)=>{
            const name=a.username||a;
            const remark=a.remark||'';
            return `<tr><td>${i+1}</td><td><code>${esc(name)}</code></td><td>${esc(remark||'-')}</td><td style="text-align:center">
                <button class="btn btn-info btn-sm" style="min-width:46px;padding:4px 10px" onclick="showEditAccountRemark(${apiType},'${escAttr(name)}')">修改</button>
            </td><td style="text-align:center">
                <button class="btn btn-danger btn-sm" style="min-width:46px" onclick="deleteAccount(${apiType},'${escAttr(name)}')">删除</button>
            </td></tr>`;
        }).join('')
    }</tbody></table>`;
}

function renderAccountTable(accounts, targetId, apiType){
    const el=document.getElementById(targetId);
    const label=apiType===3?'编号':'账号';
    if(!accounts.length){accountSelection[apiType]?.clear();updateBatchDeleteButton(apiType);el.innerHTML='<div class="empty">暂无'+label+'</div>';return;}
    const pager=accountPager[apiType]||{page:1,size:10};
    const total=accounts.length;
    const totalPages=Math.max(1,Math.ceil(total/pager.size));
    pager.page=Math.min(Math.max(1,pager.page),totalPages);
    const start=(pager.page-1)*pager.size;
    const pageRows=accounts.slice(start,start+pager.size);
    const from=start+1;
    const to=Math.min(start+pager.size,total);
    const selected=accountSelection[apiType]||new Set();
    const pageAllChecked=pageRows.length>0&&pageRows.every(a=>selected.has(a.username||a));
    el.innerHTML=`<table><thead><tr><th style="width:42px;text-align:center"><input type="checkbox" ${pageAllChecked?'checked':''} onchange="toggleAccountPageSelection(${apiType},this.checked)"></th><th style="width:50px">#</th><th>${label}</th><th>备注</th><th style="width:78px;text-align:center">修改</th><th style="width:78px;text-align:center">操作</th></tr></thead><tbody>${
        pageRows.map((a,i)=>{
            const name=a.username||a;
            const remark=a.remark||'';
            const checked=selected.has(name)?'checked':'';
            return `<tr><td style="text-align:center"><input type="checkbox" ${checked} onchange="toggleAccountSelection(${apiType},'${escAttr(name)}',this.checked)"></td><td>${start+i+1}</td><td><code>${esc(name)}</code></td><td>${esc(remark||'-')}</td><td style="text-align:center">
                <button class="btn btn-info btn-sm" style="min-width:46px;padding:4px 10px" onclick="showEditAccountRemark(${apiType},'${escAttr(name)}')">修改</button>
            </td><td style="text-align:center">
                <button class="btn btn-danger btn-sm" style="min-width:46px" onclick="deleteAccount(${apiType},'${escAttr(name)}')">删除</button>
            </td></tr>`;
        }).join('')
    }</tbody></table>
    <div class="account-pager">
        <div class="account-pager-info">Showing ${from}-${to} / ${total}, page ${pager.page} / ${totalPages}</div>
        <div class="account-pager-actions">
            <span class="account-pager-info">Per page</span>
            <select class="account-page-size" onchange="setAccountPageSize(${apiType},this.value)">
                ${[10,20,50,100].map(n=>`<option value="${n}" ${pager.size===n?'selected':''}>${n}</option>`).join('')}
            </select>
            <button class="btn btn-default btn-sm" ${pager.page<=1?'disabled':''} onclick="setAccountPage(${apiType},1)">First</button>
            <button class="btn btn-default btn-sm" ${pager.page<=1?'disabled':''} onclick="setAccountPage(${apiType},${pager.page-1})">Prev</button>
            <button class="btn btn-default btn-sm" ${pager.page>=totalPages?'disabled':''} onclick="setAccountPage(${apiType},${pager.page+1})">Next</button>
            <button class="btn btn-default btn-sm" ${pager.page>=totalPages?'disabled':''} onclick="setAccountPage(${apiType},${totalPages})">Last</button>
        </div>
    </div>`;
    updateBatchDeleteButton(apiType);
}

function showAddAccount(apiType){
    acctModalMode='add'+apiType;
    const title=apiType===3?'添加接口2编号备注':'添加接口'+apiType+'账号';
    const label=apiType===3?'编号':'账号';
    document.getElementById('acctModalTitle').textContent=title;
    document.getElementById('acctModalBody').innerHTML=`
        <div class="form-item" style="margin-bottom:12px"><label>${label}</label><input id="acctInputName" placeholder="输入${label}" style="height:40px;border:2px solid #e2e8f0;border-radius:8px;padding:0 12px;font-size:14px;width:100%;background:#f8fafc;font-family:var(--font);transition:all .2s"></div>
        <div class="form-item"><label>备注</label><input id="acctInputRemark" placeholder="备注（可选）" style="height:40px;border:2px solid #e2e8f0;border-radius:8px;padding:0 12px;font-size:14px;width:100%;background:#f8fafc;font-family:var(--font);transition:all .2s"></div>`;
    document.getElementById('accountModal').classList.remove('hidden');
    setTimeout(()=>{const inp=document.getElementById('acctInputName');if(inp)inp.focus();},100);
}

function showBatchAdd(apiType){
    acctModalMode='batch'+apiType;
    const title=apiType===3?'批量添加接口2编号备注':'批量添加接口'+apiType+'账号';
    const label=apiType===3?'编号':'账号';
    const sample=apiType===3?'7000\t张三\n7029|李四\n7030,王五':'user1\t备注1\nuser2|备注2\nuser3,备注3\nuser4;备注4';
    document.getElementById('acctModalTitle').textContent=title;
    document.getElementById('acctModalBody').innerHTML=`
        <div class="form-item"><label>每行一个${label}，自动识别 Tab、空格、|、逗号、分号：${label} 备注</label>
        <textarea id="acctBatchInput" rows="10" placeholder="${sample}" style="height:220px;width:100%;border:2px solid #e2e8f0;border-radius:8px;padding:10px 12px;font-size:14px;resize:vertical;font-family:monospace;background:#f8fafc;transition:all .2s"></textarea></div>`;
    document.getElementById('accountModal').classList.remove('hidden');
    setTimeout(()=>{const inp=document.getElementById('acctBatchInput');if(inp)inp.focus();},100);
}

function showEditAccountRemark(apiType, username){
    acctModalMode='edit';
    acctEditApiType=apiType;
    acctEditUsername=username;
    const label=apiType===3?'编号':'账号';
    const data=api1Data;
    const item=data.find(a=>(a.username||a)===username) || {};
    document.getElementById('acctModalTitle').textContent='修改备注';
    document.getElementById('acctModalBody').innerHTML=`
        <div class="form-item" style="margin-bottom:12px"><label>${label}</label><input value="${escAttr(username)}" disabled style="height:40px;border:2px solid #e2e8f0;border-radius:8px;padding:0 12px;font-size:14px;width:100%;background:#f1f5f9;color:#64748b;font-family:var(--font)"></div>
        <div class="form-item"><label>备注</label><input id="acctEditRemark" value="${escAttr(item.remark||'')}" placeholder="留空则清除备注" style="height:40px;border:2px solid #e2e8f0;border-radius:8px;padding:0 12px;font-size:14px;width:100%;background:#f8fafc;font-family:var(--font);transition:all .2s"></div>`;
    document.getElementById('accountModal').classList.remove('hidden');
    setTimeout(()=>{const inp=document.getElementById('acctEditRemark');if(inp){inp.focus();inp.select();}},100);
}

function closeAccountModal(){
    document.getElementById('accountModal').classList.add('hidden');
    acctModalMode='';
    acctEditApiType=0;
    acctEditUsername='';
}

async function acctModalConfirm(){
    if(acctModalMode==='extAdd'||acctModalMode==='extEdit'){
        await saveExtAccountFromModal();
        return;
    }
    if(acctModalMode==='extBatch'){
        await saveExtBatchFromModal();
        return;
    }
    if(acctModalMode.startsWith('add')){
        const apiType=parseInt(acctModalMode.replace('add',''));
        const label=apiType===3?'编号':'账号';
        const name=(document.getElementById('acctInputName').value||'').trim();
        const remark=(document.getElementById('acctInputRemark').value||'').trim();
        if(!name) return alert('请输入'+label);
        const data=api1Data;
        if(data.some(a=>(a.username||a)===name)) return alert(label+'已存在');
        data.push({username:name,remark:remark});
        await saveAccountList(apiType,data);
    }else if(acctModalMode.startsWith('batch')){
        const apiType=parseInt(acctModalMode.replace('batch',''));
        const label=apiType===3?'编号':'账号';
        const text=(document.getElementById('acctBatchInput').value||'').trim();
        if(!text) return alert('请输入'+label);
        const data=[...api1Data];
        const existingNames=new Set(data.map(a=>a.username||a));
        let added=0;
        for(const line of text.split(/\r?\n/)){
            const parsed=parseAccountBatchLine(line);
            if(parsed&&!existingNames.has(parsed.username)){
                data.push(parsed);
                existingNames.add(parsed.username);
                added++;
            }
        }
        api1Data=data;
        await saveAccountList(apiType,data);
        alert('已添加 '+added+' 个'+label);
    }else if(acctModalMode==='edit'){
        const apiType=acctEditApiType;
        const username=acctEditUsername;
        const remark=(document.getElementById('acctEditRemark').value||'').trim();
        let data=[...api1Data];
        let found=false;
        data=data.map(a=>{
            const name=a.username||a;
            if(name!==username) return a;
            found=true;
            return {username:name,remark:remark};
        });
        if(!found) return alert('未找到要修改的账号');
        api1Data=data;
        await saveAccountList(apiType,data);
    }
    closeAccountModal();
    loadApi1Accounts();
}

async function deleteAccount(apiType,username){
    const label=apiType===3?'编号':'账号';
    if(!confirm('确定删除'+label+' '+username+' ?')) return;
    let data=api1Data;
    data=data.filter(a=>(a.username||a)!==username);
    accountSelection[apiType].delete(username);
    api1Data=data;
    await saveAccountList(apiType,data);
    loadApi1Accounts();
}

async function deleteSelectedAccounts(apiType){
    const label=apiType===3?'编号':'账号';
    const selected=[...(accountSelection[apiType]||new Set())];
    if(!selected.length)return;
    if(!confirm('确定批量删除 '+selected.length+' 个'+label+'？'))return;
    let data=api1Data;
    const selectedSet=new Set(selected);
    data=data.filter(a=>!selectedSet.has(a.username||a));
    accountSelection[apiType].clear();
    api1Data=data;
    await saveAccountList(apiType,data);
    updateBatchDeleteButton(apiType);
    loadApi1Accounts();
}

async function saveAccountList(apiType,data){
    const text=data.map(a=>(a.username||a)+(a.remark?'|'+a.remark:'')).join('\n');
    const act='save_api1_accounts';
    await authFetch(BASE+'?act='+act+'&accounts='+encodeURIComponent(text));
}

// ===== Version Control =====
let vcBlockedVersions={};

async function loadVerCtrl(){
    const r=await authFetch(BASE+'?act=version_controls');
    const d=await r.json();
    if(!d.ok)return;
    const c=d.data||{};
    document.getElementById('vcMinCode').value=c.min_version_code||0;
    document.getElementById('vcMinMsg').value=c.min_version_msg||'';
    document.getElementById('api2LoginMin').value=(c.api2_login_min!==undefined?c.api2_login_min:0);
    document.getElementById('api2LoginMax').value=c.api2_login_max||10000;
    vcBlockedVersions=c.blocked_versions||{};
    document.getElementById('vcResult').textContent=c.updated_at?'上次保存: '+c.updated_at:'';
    renderBlockedVersions();
}

function renderBlockedVersions(){
    const el=document.getElementById('blockedVerList');
    const keys=Object.keys(vcBlockedVersions).sort((a,b)=>Number(a)-Number(b));
    if(!keys.length){el.innerHTML='<div class="empty">暂无单独停用的版本</div>';return;}
    el.innerHTML=`<table><thead><tr><th style="width:50px">#</th><th>版本号 (versionCode)</th><th>停用提示语</th><th style="width:70px">操作</th></tr></thead><tbody>${
        keys.map((k,i)=>{
            const v=vcBlockedVersions[k];
            const msg=typeof v==='object'?(v.message||''):(typeof v==='string'?v:'');
            return `<tr><td>${i+1}</td><td><b>${esc(k)}</b></td><td>${esc(msg||'此版本已停用，请更新')}</td><td><button class="btn btn-success btn-sm" onclick="removeBlockedVer('${escAttr(k)}')">移除</button></td></tr>`;
        }).join('')
    }</tbody></table>`;
}

function showAddBlockedVer(){
    const code=prompt('输入要停用的版本号 (versionCode)','');
    if(!code||isNaN(Number(code)))return;
    const msg=prompt('停用提示语（App会显示给用户）','此版本已停用，请更新到最新版本');
    if(msg===null)return;
    vcBlockedVersions[String(Number(code))]={message:msg};
    renderBlockedVersions();
}

function removeBlockedVer(code){
    if(!confirm('确定移除版本 '+code+' 的停用限制？'))return;
    delete vcBlockedVersions[code];
    renderBlockedVersions();
}

async function saveVerCtrl(){
    const minCode=document.getElementById('vcMinCode').value||'0';
    const minMsg=document.getElementById('vcMinMsg').value||'';
    const api2Min=document.getElementById('api2LoginMin').value||'0';
    const api2Max=document.getElementById('api2LoginMax').value||'10000';
    document.getElementById('vcResult').textContent='保存中...';
    const params=new URLSearchParams({
        act:'save_version_controls',
        min_version_code:minCode,min_version_msg:minMsg,
        api2_login_min:api2Min,api2_login_max:api2Max,
        blocked_versions:JSON.stringify(vcBlockedVersions)
    });
    const r=await authFetch(BASE+'?'+params.toString());
    const d=await r.json();
    document.getElementById('vcResult').textContent=d.msg||(d.ok?'已保存':'保存失败');
    if(d.ok&&d.data) updateApi2RangeTip(d.data);
}

// ===== Update =====
async function loadUpdateConfig(){
    const [appResp,pluginResp]=await Promise.all([
        authFetch(BASE+'?act=update_config').then(r=>r.json()),
        authFetch(BASE+'?act=plugin_update_config').then(r=>r.json())
    ]);
    if(!appResp.ok)return;
    const c=appResp.data||{};
    const p=pluginResp.ok?(pluginResp.data||{}):{};
    document.getElementById('updateBody').innerHTML=`
        <div class="card" style="margin-bottom:16px">
        <div class="card-head"><h3>App 更新发布</h3></div>
        <div class="card-body">
        <div style="background:linear-gradient(135deg,#fefce8,#fffbeb);border:1px solid #fde68a;padding:12px 16px;border-radius:10px;margin-bottom:16px;font-size:13px;color:#92400e">App请求时带versionCode，后台版本号大于App才会弹窗更新。</div>
        <form id="updateForm" onsubmit="submitUpdate(event)">
        <div class="form-grid">
            <div class="form-item"><label>versionCode</label><input name="version_code" type="number" min="1" value="${escAttr(String(c.version_code||1))}"></div>
            <div class="form-item"><label>versionName</label><input name="version_name" value="${escAttr(c.version_name||'1.0.0')}"></div>
            <div class="form-item"><label>APK文件</label><input name="apk" type="file" accept=".apk"></div>
            <div class="form-item"><label>下载地址</label><input name="apk_url" value="${escAttr(c.apk_url||'')}" placeholder="上传APK后自动生成"></div>
            <div class="form-item"><label>弹窗标题</label><input name="title" value="${escAttr(c.title||'发现新版本')}"></div>
            <div class="form-check"><input name="force" type="checkbox" ${c.force?'checked':''}><label>强制更新</label></div>
            <div class="form-item" style="grid-column:1/-1"><label>更新说明</label><textarea name="message" placeholder="给用户看的更新内容">${esc(c.message||'')}</textarea></div>
        </div>
        <div style="margin-top:16px;display:flex;gap:10px;align-items:center">
            <button class="btn btn-primary" type="submit">保存并发布</button>
            ${c.apk_url?`<a href="${escAttr(c.apk_url)}" target="_blank" class="btn btn-default">测试下载</a>`:''}
            <span id="updateResult" style="font-size:13px;color:var(--muted)">${c.updated_at?'上次: '+esc(c.updated_at):''}</span>
        </div></form>
        </div></div>
        <div class="card">
        <div class="card-head"><h3>浏览器插件半自动更新</h3></div>
        <div class="card-body">
        <div style="background:#f8fafc;border:1px solid #e2e8f0;padding:12px 16px;border-radius:10px;margin-bottom:16px;font-size:13px;color:#475569">上传新版插件 ZIP/CRX 后，插件会在心跳时检测版本，并在插件面板显示下载更新提示。用户下载后手动替换/重新加载插件。</div>
        <form id="pluginUpdateForm" onsubmit="submitPluginUpdate(event)">
        <div class="form-grid">
            <div class="form-item"><label>插件版本号</label><input name="version_name" value="${escAttr(p.version_name||'1.0.0')}" placeholder="例如 1.0.1"></div>
            <div class="form-item"><label>版本数值</label><input name="version_code" type="number" min="1" value="${escAttr(String(p.version_code||''))}" placeholder="留空按版本号自动生成"></div>
            <div class="form-item"><label>插件包</label><input name="package" type="file" accept=".zip,.crx"></div>
            <div class="form-item"><label>下载地址</label><input name="package_url" value="${escAttr(p.package_url||'')}" placeholder="上传插件包后自动生成，也可手动填写"></div>
            <div class="form-item"><label>提示标题</label><input name="title" value="${escAttr(p.title||'发现插件新版本')}"></div>
            <div class="form-check"><input name="enabled" type="checkbox" ${p.enabled!==false?'checked':''}><label>启用更新检测</label></div>
            <div class="form-check"><input name="force" type="checkbox" ${p.force?'checked':''}><label>标记重要更新</label></div>
            <div class="form-item" style="grid-column:1/-1"><label>更新说明</label><textarea name="message" placeholder="给插件用户看的更新内容">${esc(p.message||'')}</textarea></div>
        </div>
        <div style="margin-top:16px;display:flex;gap:10px;align-items:center">
            <button class="btn btn-primary" type="submit">保存插件更新</button>
            ${p.package_url?`<a href="${escAttr(p.package_url)}" target="_blank" class="btn btn-default">测试下载</a>`:''}
            <span id="pluginUpdateResult" style="font-size:13px;color:var(--muted)">${p.updated_at?'上次: '+esc(p.updated_at):''}</span>
        </div></form>
        </div></div>`;
}
async function submitUpdate(e){
    e.preventDefault();
    const fd=new FormData(document.getElementById('updateForm'));
    fd.append('act','upload_update');
    document.getElementById('updateResult').textContent='保存中...';
    const r=await authFetch(BASE,{method:'POST',body:fd});
    const d=await r.json();
    document.getElementById('updateResult').textContent=d.msg||(d.ok?'已保存':'失败');
    if(d.ok) loadUpdateConfig();
}

async function submitPluginUpdate(e){
    e.preventDefault();
    const fd=new FormData(document.getElementById('pluginUpdateForm'));
    fd.append('act','upload_plugin_update');
    if(!fd.has('enabled')) fd.append('enabled','0');
    document.getElementById('pluginUpdateResult').textContent='保存中...';
    const r=await authFetch(BASE,{method:'POST',body:fd});
    const d=await r.json();
    document.getElementById('pluginUpdateResult').textContent=d.msg||(d.ok?'已保存':'失败');
    if(d.ok) loadUpdateConfig();
}

// ===== Data =====
async function loadDumpList(){
    const r=await authFetch(BASE+'?act=dumps');
    const d=await r.json();
    if(!d.ok)return;
    const el=document.getElementById('dumpList');
    const files=d.data||[];
    if(!files.length){el.innerHTML='<div class="empty">暂无解密数据</div>';return;}
    el.innerHTML=`<table><thead><tr><th>#</th><th>时间</th><th>ID</th><th>大小</th><th>操作</th></tr></thead><tbody>${files.map((f,i)=>`<tr><td>${i+1}</td><td>${esc(f.time)}</td><td style="font-size:12px;font-family:monospace">${esc(f.id)}</td><td>${(f.size/1024).toFixed(1)}KB</td><td><a href="javascript:void(0)" onclick="viewJson('dump','${encodeURIComponent(f.id)}')" style="color:var(--primary)">查看</a></td></tr>`).join('')}</tbody></table>`;
}
async function openLatestDump(){
    const r=await authFetch(BASE+'?act=dumps');
    const d=await r.json();
    const files=d.data||[];
    if(!files.length) return alert('暂无数据');
    viewJson('dump',encodeURIComponent(files[0].id));
}

// ===== Cache Cleanup =====
function jsonRiskClass(level){
    if(level==='high')return 'tag-danger';
    if(level==='sensitive')return 'tag-warning';
    if(level==='normal')return 'tag-success';
    return 'tag-info';
}

function jsonPreviewText(preview){
    if(preview===null||preview===undefined)return '';
    try{return JSON.stringify(preview,null,2);}
    catch(e){return String(preview);}
}

async function loadJsonMonitor(){
    const el=document.getElementById('jsonMonitorBody');
    if(!el)return;
    el.innerHTML='<div class="empty">Loading...</div>';
    const r=await authFetch(BASE+'?act=json_monitor');
    const d=await r.json();
    if(!d.ok){el.innerHTML='<div class="empty">'+esc(d.msg||'Load failed')+'</div>';return;}
    const rows=d.data||[];
    const totalBytes=rows.reduce((sum,x)=>sum+Number(x.bytes||0),0);
    const sensitive=rows.filter(x=>['sensitive','high'].includes(x.risk_level)).length;
    if(!rows.length){el.innerHTML='<div class="empty">No JSON files found.</div>';return;}
    el.innerHTML=`
        <div class="stat-row" style="margin-bottom:16px">
            <div class="stat-card"><div class="label">JSON Files</div><div class="value blue">${rows.length}</div></div>
            <div class="stat-card"><div class="label">Total Size</div><div class="value purple">${cacheSizeText(totalBytes)}</div></div>
            <div class="stat-card"><div class="label">Sensitive</div><div class="value red">${sensitive}</div></div>
            <div class="stat-card"><div class="label">Latest Update</div><div class="value" style="font-size:17px">${esc(rows[0]?.mtime_text||'-')}</div></div>
        </div>
        <table>
            <thead><tr><th>#</th><th>File</th><th>Purpose</th><th>Category</th><th>Risk</th><th>Records</th><th>Size</th><th>Updated</th><th>Status</th></tr></thead>
            <tbody>${rows.map((row,i)=>{
                const parseTag=row.parse_ok===false?'<span class="tag tag-danger">Parse error</span>':(row.parse_ok===true?'<span class="tag tag-success">OK</span>':'<span class="tag tag-info">Skipped</span>');
                const keys=(row.top_keys||[]).length?`<div style="font-size:12px;color:var(--muted);margin-top:4px">keys: ${esc((row.top_keys||[]).join(', '))}</div>`:'';
                const preview=jsonPreviewText(row.preview);
                return `<tr>
                    <td>${i+1}</td>
                    <td><code>${esc(row.name)}</code><div style="font-size:12px;color:var(--muted);margin-top:4px">${esc(row.path||'')}</div></td>
                    <td><b>${esc(row.label||'-')}</b>${keys}${row.parse_error?`<div style="font-size:12px;color:var(--danger);margin-top:4px">${esc(row.parse_error)}</div>`:''}</td>
                    <td><span class="tag tag-blue">${esc(row.category||'-')}</span></td>
                    <td><span class="tag ${jsonRiskClass(row.risk_level)}">${esc(row.risk||'-')}</span></td>
                    <td>${Number(row.records||0)}</td>
                    <td>${esc(row.size_text||cacheSizeText(row.bytes||0))}</td>
                    <td>${esc(row.mtime_text||'-')}${row.updated_at?`<div style="font-size:12px;color:var(--muted);margin-top:4px">updated_at: ${esc(row.updated_at)}</div>`:''}</td>
                    <td>${parseTag}<button class="btn btn-default btn-sm" style="margin-left:8px" onclick="toggleJsonPreview('jsonPreview${i}')">Preview</button></td>
                </tr>
                <tr id="jsonPreview${i}" class="hidden"><td colspan="9"><pre class="resp" style="max-height:320px">${esc(preview||'No preview')}</pre></td></tr>`;
            }).join('')}</tbody>
        </table>`;
}

function toggleJsonPreview(id){
    document.getElementById(id)?.classList.toggle('hidden');
}
function cacheSizeText(bytes){
    const n=Number(bytes||0);
    if(n>=1024*1024*1024) return (n/1024/1024/1024).toFixed(2)+' GB';
    if(n>=1024*1024) return (n/1024/1024).toFixed(2)+' MB';
    if(n>=1024) return (n/1024).toFixed(1)+' KB';
    return n+' B';
}

function shortText(s,len){
    s=String(s||'');
    len=Number(len||80);
    return s.length>len?s.slice(0,len-3)+'...':s;
}

function sqliteAgeText(seconds){
    const s=Number(seconds||0);
    if(s>=3600)return Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m';
    if(s>=60)return Math.floor(s/60)+'m '+(s%60)+'s';
    return s+'s';
}

function renderSQLiteMonitor(data){
    const el=document.getElementById('sqliteMonitorBody');
    if(!el)return;
    if(!data||data.ok===false){
        el.innerHTML='<div class="empty">'+esc(data?.msg||'SQLite unavailable')+'</div>';
        return;
    }
    const files=data.files||[];
    const tables=data.tables||{};
    const metrics=data.metrics||{};
    const queueRows=data.recent_queue||[];
    const leaseRows=data.recent_leases||[];
    const groups=data.lease_groups||[];
    const fileBytes=files.reduce((s,f)=>s+Number(f.bytes||0),0);
    const quick=String(metrics.quick_check||'');
    el.innerHTML=`
        <div class="stat-row" style="margin-bottom:16px">
            <div class="stat-card"><div class="label">Queue Rows</div><div class="value blue">${Number(tables.task_queue?.rows||0)}</div></div>
            <div class="stat-card"><div class="label">Lease Rows</div><div class="value purple">${Number(tables.task_leases?.rows||0)}</div></div>
            <div class="stat-card"><div class="label">DB Files</div><div class="value">${cacheSizeText(fileBytes)}</div></div>
            <div class="stat-card"><div class="label">Quick Check</div><div class="value ${quick==='ok'?'green':'red'}">${esc(quick||'-')}</div></div>
        </div>
        <div class="card" style="margin-bottom:16px">
            <div class="card-head"><h3>数据库文件</h3><div class="card-toolbar"><span style="font-size:12px;color:var(--muted)">Generated: ${esc(data.generated_at||'-')}</span></div></div>
            <div class="card-body" style="padding:0">
                <table><thead><tr><th>File</th><th>Exists</th><th>Size</th><th>Updated</th><th>Path</th></tr></thead>
                <tbody>${files.map(f=>`<tr>
                    <td><code>${esc(f.name)}</code></td>
                    <td><span class="tag ${f.exists?'tag-success':'tag-warning'}">${f.exists?'yes':'no'}</span></td>
                    <td>${esc(f.size_text||cacheSizeText(f.bytes||0))}</td>
                    <td>${esc(f.updated_at||'-')}</td>
                    <td style="font-size:12px;color:var(--muted)">${esc(f.path||'')}</td>
                </tr>`).join('')}</tbody></table>
            </div>
        </div>
        <div class="card" style="margin-bottom:16px">
            <div class="card-head"><h3>运行指标</h3></div>
            <div class="card-body" style="padding:0">
                <table><thead><tr><th>Metric</th><th>Value</th></tr></thead>
                <tbody>${Object.keys(metrics).map(k=>`<tr><td><code>${esc(k)}</code></td><td>${esc(metrics[k])}</td></tr>`).join('')}</tbody></table>
            </div>
        </div>
        <div class="card" style="margin-bottom:16px">
            <div class="card-head"><h3>最近 Lease</h3></div>
            <div class="card-body" style="padding:0">${leaseRows.length?`
                <table><thead><tr><th>ID</th><th>Account</th><th>Task</th><th>Task Account</th><th>Token Hash</th><th>Age</th><th>Created</th></tr></thead>
                <tbody>${leaseRows.map(r=>`<tr>
                    <td>${Number(r.id||0)}</td>
                    <td><code>${esc(r.account_id||'')}</code><div style="font-size:12px;color:var(--muted)">${esc(shortText(r.runtime_scope,70))}</div></td>
                    <td><code>${esc(r.task_id||'')}</code><div style="font-size:12px;color:var(--muted)">${esc(shortText(r.task_url,90))}</div></td>
                    <td>${esc(r.task_account_username||'')}<div style="font-size:12px;color:var(--muted)">${esc(r.task_account_key||'')}</div></td>
                    <td><code>${esc(r.api1_token_hash||'')}</code><div style="font-size:12px;color:var(--muted)">${esc(r.api1_token_expires_at_text||'')}</div></td>
                    <td>${sqliteAgeText(r.age_seconds)}</td>
                    <td>${esc(r.created_at||'')}</td>
                </tr>`).join('')}</tbody></table>`:'<div class="empty">暂无 lease</div>'}</div>
        </div>
        <div class="card" style="margin-bottom:16px">
            <div class="card-head"><h3>最近 Queue</h3></div>
            <div class="card-body" style="padding:0">${queueRows.length?`
                <table><thead><tr><th>ID</th><th>Account</th><th>Task Key</th><th>Age</th><th>Queued</th></tr></thead>
                <tbody>${queueRows.map(r=>`<tr>
                    <td>${Number(r.id||0)}</td>
                    <td><code>${esc(r.account_id||'')}</code><div style="font-size:12px;color:var(--muted)">${esc(shortText(r.runtime_scope,70))}</div></td>
                    <td><code>${esc(shortText(r.task_key,120))}</code></td>
                    <td>${sqliteAgeText(r.age_seconds)}</td>
                    <td>${esc(r.queued_at||'')}</td>
                </tr>`).join('')}</tbody></table>`:'<div class="empty">暂无队列任务</div>'}</div>
        </div>
        <div class="card">
            <div class="card-head"><h3>Lease 分组</h3></div>
            <div class="card-body" style="padding:0">${groups.length?`
                <table><thead><tr><th>Account</th><th>Runtime Scope</th><th>Leases</th><th>Latest</th></tr></thead>
                <tbody>${groups.map(r=>`<tr>
                    <td><code>${esc(r.account_id||'')}</code></td>
                    <td style="font-size:12px;color:var(--muted)">${esc(shortText(r.runtime_scope,120))}</td>
                    <td>${Number(r.lease_count||0)}</td>
                    <td>${esc(r.latest_at||'')}</td>
                </tr>`).join('')}</tbody></table>`:'<div class="empty">暂无分组</div>'}</div>
        </div>`;
}

async function loadSQLiteMonitor(){
    const el=document.getElementById('sqliteMonitorBody');
    if(!el)return;
    el.innerHTML='<div class="empty">Loading...</div>';
    const r=await authFetch(BASE+'?act=sqlite_monitor');
    const d=await r.json();
    if(!d.ok){el.innerHTML='<div class="empty">'+esc(d.msg||'Load failed')+'</div>';return;}
    renderSQLiteMonitor(d.data||{});
}

function toggleSQLiteAuto(){
    const btn=document.getElementById('sqliteAutoBtn');
    if(sqliteTimer){
        clearInterval(sqliteTimer); sqliteTimer=null;
        if(btn){btn.textContent='自动刷新';btn.className='btn btn-success btn-sm';}
    }else{
        loadSQLiteMonitor();
        sqliteTimer=setInterval(loadSQLiteMonitor,5000);
        if(btn){btn.textContent='停止刷新';btn.className='btn btn-default btn-sm';}
    }
}

function renderCacheOverview(items){
    const el=document.getElementById('cacheBody');
    const rows=items||[];
    if(!rows.length){el.innerHTML='<div class="empty">暂无缓存数据</div>';return;}
    const totalFiles=rows.reduce((s,r)=>s+Number(r.files||0),0);
    const totalBytes=rows.reduce((s,r)=>s+Number(r.bytes||0),0);
    el.innerHTML=`
        <div class="stat-row" style="margin-bottom:16px">
            <div class="stat-card"><div class="label">缓存项目</div><div class="value blue">${rows.length}</div></div>
            <div class="stat-card"><div class="label">缓存文件</div><div class="value">${totalFiles}</div></div>
            <div class="stat-card"><div class="label">缓存体积</div><div class="value purple">${cacheSizeText(totalBytes)}</div></div>
        </div>
        <table>
            <thead><tr><th>#</th><th>项目</th><th>文件数</th><th>体积</th><th>路径</th></tr></thead>
            <tbody>${rows.map((row,i)=>`<tr>
                <td>${i+1}</td>
                <td><b>${esc(row.label||'-')}</b></td>
                <td>${Number(row.files||0)}</td>
                <td>${cacheSizeText(row.bytes||0)}</td>
                <td style="font-size:12px;color:var(--muted)">${esc(row.path||'-')}</td>
            </tr>`).join('')}</tbody>
        </table>`;
}

async function loadCacheOverview(){
    const r=await authFetch(BASE+'?act=cache_overview');
    const d=await r.json();
    if(!d.ok) return;
    document.getElementById('cacheResult').textContent='上传详情缓存已启用，新上传可在日志中查看响应。';
    renderCacheOverview(d.data||[]);
}

async function cleanupCache(mode){
    const text=mode==='deep'
        ? '深度清理会额外清空转发日志和旧调试缓存，确定继续吗？'
        : '确定清理已废弃缓存吗？';
    if(!confirm(text)) return;
    const resultEl=document.getElementById('cacheResult');
    resultEl.textContent='清理中...';
    const r=await authFetch(BASE+'?act=cleanup_cache&mode='+encodeURIComponent(mode));
    const d=await r.json();
    if(!d.ok){
        resultEl.textContent=d.msg||'清理失败';
        return;
    }
    const parts=(d.steps||[]).map(step=>{
        const item=step.result||{};
        return `${step.label}: ${Number(item.deleted_files||0)} 项 / ${cacheSizeText(item.freed_bytes||0)}`;
    });
    resultEl.textContent=`${d.msg||'清理完成'}，共清理 ${Number(d.deleted_files||0)} 项，释放 ${cacheSizeText(d.freed_bytes||0)}。${parts.length?' '+parts.join('；'):''}`;
    renderCacheOverview(d.overview||[]);
}
</script>
</body>
</html>
<?php
}

function renderPasswordPage(): void {
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ajie 修改密码</title>
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0f172a;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;color:#0f172a}.box{width:min(420px,calc(100vw - 28px));background:#fff;border-radius:16px;padding:26px;box-shadow:0 28px 70px rgba(0,0,0,.32)}h1{margin:0 0 6px;font-size:22px}.sub{margin:0 0 22px;color:#64748b;font-size:13px}.field{display:grid;gap:7px;margin-bottom:14px}label{font-size:13px;font-weight:700;color:#334155}input{height:44px;border:1px solid #cbd5e1;border-radius:10px;padding:0 12px;font:inherit;outline:none}input:focus{border-color:#2563eb;box-shadow:0 0 0 3px rgba(37,99,235,.12)}button{width:100%;height:46px;border:0;border-radius:10px;background:#111827;color:#fff;font:inherit;font-weight:800;cursor:pointer}.msg{min-height:22px;margin-top:12px;font-size:13px;color:#64748b}.ok{color:#047857}.err{color:#b91c1c}a{display:inline-block;margin-top:14px;color:#2563eb;text-decoration:none;font-size:13px}
</style>
</head>
<body>
<main class="box">
  <h1>Ajie 修改密码</h1>
  <p class="sub">输入当前后台密码，然后设置新密码。</p>
  <div class="field"><label>当前密码</label><input id="currentPwd" type="password" autocomplete="current-password"></div>
  <div class="field"><label>新密码</label><input id="newPwd" type="password" autocomplete="new-password" placeholder="至少 6 位"></div>
  <div class="field"><label>确认新密码</label><input id="confirmPwd" type="password" autocomplete="new-password"></div>
  <button type="button" onclick="submitPasswordChange()">保存新密码</button>
  <div id="msg" class="msg"></div>
  <a href="?act=view">返回后台</a>
</main>
<script>
async function submitPasswordChange(){
  const current=document.getElementById('currentPwd').value.trim();
  const next=document.getElementById('newPwd').value.trim();
  const confirm=document.getElementById('confirmPwd').value.trim();
  const msg=document.getElementById('msg');
  msg.className='msg';
  if(!current||!next||!confirm){msg.textContent='请填写当前密码和新密码';msg.classList.add('err');return}
  const fd=new FormData();
  fd.append('act','change_password');
  fd.append('current_password',current);
  fd.append('new_password',next);
  fd.append('confirm_password',confirm);
  msg.textContent='保存中...';
  try{
    const r=await fetch(location.pathname,{method:'POST',headers:{'X-Auth-Key':current},body:fd});
    const d=await r.json();
    msg.textContent=d.msg||(d.ok?'密码已修改':'修改失败');
    msg.classList.add(d.ok?'ok':'err');
    if(d.ok){
      localStorage.setItem('admin_key',next);
      localStorage.setItem('h5_admin_key',next);
      document.getElementById('currentPwd').value=next;
      document.getElementById('newPwd').value='';
      document.getElementById('confirmPwd').value='';
    }
  }catch(e){
    msg.textContent='网络错误';
    msg.classList.add('err');
  }
}
</script>
</body>
</html>
<?php
}
