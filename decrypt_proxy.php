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
$UPDATE_FILE = __DIR__ . '/app_update.json';
$VERSION_CTRL_FILE = __DIR__ . '/version_controls.json';
$APK_DIR = __DIR__ . '/app_updates';
$STATS_DIR = __DIR__ . '/daily_stats';
$FP_ENV_STATS_DIR = __DIR__ . '/fingerprint_env_stats';
$API1_TOKEN_FILE = __DIR__ . '/api1_token.json';
$API1_TOKEN_MAP_FILE = __DIR__ . '/api1_token_map.json';
$API1_ACCOUNTS_FILE = __DIR__ . '/api1_allowed_accounts.json';
$API2_ACCOUNTS_FILE = __DIR__ . '/api2_allowed_accounts.json';
$API2_NUMBERS_FILE = __DIR__ . '/api2_number_remarks.json';
$API2_FIXED_USERNAME = "\xE7\xB1\xB3\xE4\xB9\x90\xE7\xB1\xB3\xE4\xB9\x90";
$MAX_LOGS = 500;
$FORWARD_TIMEOUT = 8;
$FORWARD_CONNECT_TIMEOUT = 6;
$LOGIN_TIMEOUT = 8;
$LOGIN_CONNECT_TIMEOUT = 6;
$HEARTBEAT_WRITE_INTERVAL = 20;
$SAVE_SUCCESS_DECRYPT_DUMPS = false;
$SAVE_SUCCESS_UPLOAD_DUMPS = false;
$MAX_STAT_RECORDS_PER_DEVICE = 50;
$MAX_LOG_RESPONSE_BYTES = 1200;
$API1_PARSE_TIMEOUT_MAX_ATTEMPTS = 2;
$API1_PARSE_TIMEOUT_RETRY_DELAY_US = 150000;

$API1_AUTH = [
    'login_url' => 'https://zb1.eqwofaygdsjko.uk:443/api/user/login',
    'username'  => 'youngdenise',
    'password'  => '@dzaM3mT9I',
];

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
        if (strpos($line, '|') !== false) {
            [$name, $remark] = array_pad(explode('|', $line, 2), 2, '');
        } else {
            $parts = preg_split('/\s+/', $line, 2) ?: [];
            $name = $parts[0] ?? '';
            $remark = $parts[1] ?? '';
        }
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
    global $API1_ACCOUNTS_FILE, $API2_ACCOUNTS_FILE, $API2_NUMBERS_FILE;
    if ($apiType === 2) {
        return api2DisplayRemark(
            $username,
            accountRemarkMap(readApi1AllowedAccounts($API2_ACCOUNTS_FILE)),
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
        accountRemarkMap(readApi1AllowedAccounts($API2_ACCOUNTS_FILE)),
        accountRemarkMap(readApi1AllowedAccounts($API2_NUMBERS_FILE)),
        $groupId
    );
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
    $accountRemark = displayAccountRemark($apiType, $username, $groupId);
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

function elapsedMs(float $start): int {
    return (int)round((microtime(true) - $start) * 1000);
}

function durationMs(float $start, float $end): int {
    return (int)round(($end - $start) * 1000);
}

function api2ForwardPayload(string $username, string $groupId, array $taskInfo, array $actualData): array {
    return [
        "\xE9\x90\xA2\xE3\x84\xA6\xE5\x9F\x9B\xE9\x8D\x9A\x3F" => $username,
        "\xE7\xBC\x81\xE5\x87\xA6\x44" => $groupId,
        "\xE6\xB5\xA0\xE8\xAF\xB2\xE5\xA7\x9F\xE9\x8F\x81\xE7\x89\x88\xE5\xB5\x81" => $taskInfo,
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

function api2ForwardSuccess($serverResp): bool {
    if (!is_array($serverResp)) return false;
    $ok = $serverResp['ok'] ?? null;
    if ($ok === true || $ok === 1 || $ok === '1') return true;
    if (is_string($ok) && strtolower(trim($ok)) === 'true') return true;
    $code = (string)($serverResp['code'] ?? '');
    return $code === '200' || strcasecmp($code, 'SUCCESS') === 0;
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
    global $MAX_STAT_RECORDS_PER_DEVICE;
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

// ===== 前端页面 =====
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['act'])) {
    $act = $_GET['act'];

    if ($act === 'view') {
        renderPage();
        exit;
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

    $key = getAuthKeyFromRequest();
    if (!verifyAuthKey($key)) jsonResp(['ok' => false, 'msg' => '密码错误']);

    if ($act === 'logs') {
        $limit = min(200, max(1, (int)($_GET['limit'] ?? 50)));
        $logs = readLogs($LOG_FILE, $limit);
        foreach ($logs as &$log) {
            if (!empty($log['username'])) {
                $u = (string)$log['username'];
                $remark = displayAccountRemark((int)($log['api_type'] ?? 0), $u, (string)($log['group_id'] ?? ''));
                $log['account_remark'] = $remark !== '' ? $remark : ($log['account_remark'] ?? '');
            }
        }
        unset($log);
        jsonResp(['ok' => true, 'data' => $logs]);
    }

    if ($act === 'devices') {
        $devices = array_values(readDeviceControls($DEVICE_FILE));
        foreach ($devices as &$device) {
            $u = (string)($device['username'] ?? '');
            $device['account_remark'] = displayAccountRemark((int)($device['api_type'] ?? 0), $u, (string)($device['group_id'] ?? '')) ?: ($device['account_remark'] ?? '');
        }
        unset($device);
        $now = time();
        $onlineThreshold = 120;
        $devices = array_filter($devices, function($d) use ($now, $onlineThreshold) {
            $lastSeen = strtotime($d['last_seen'] ?? '');
            return $lastSeen && ($now - $lastSeen) <= $onlineThreshold;
        });
        $devices = array_values($devices);
        usort($devices, fn($a, $b) => strcmp((string)($b['last_seen'] ?? ''), (string)($a['last_seen'] ?? '')));
        jsonResp(['ok' => true, 'data' => $devices, 'online_count' => count($devices)]);
    }

    if ($act === 'device_toggle') {
        $deviceKey = (string)($_GET['device_key'] ?? '');
        $disabled = (int)($_GET['disabled'] ?? 0) === 1;
        $reason = trim((string)($_GET['reason'] ?? ''));
        jsonResp(updateDeviceControl($DEVICE_FILE, $deviceKey, $disabled, $reason));
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
        jsonResp(['ok' => true, 'data' => readApi1AllowedAccounts($API1_ACCOUNTS_FILE)]);
    }

    if ($act === 'save_api1_accounts') {
        jsonResp(saveApi1AllowedAccounts($API1_ACCOUNTS_FILE, (string)($_GET['accounts'] ?? '')));
    }

    if ($act === 'api2_accounts') {
        jsonResp(['ok' => true, 'data' => readApi1AllowedAccounts($API2_ACCOUNTS_FILE)]);
    }

    if ($act === 'save_api2_accounts') {
        jsonResp(saveApiAccounts($API2_ACCOUNTS_FILE, parseAccountLines((string)($_GET['accounts'] ?? ''))));
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
        $id = $_GET['id'] ?? '';
        $dumpFile = __DIR__ . '/upload_dumps/' . basename($id) . '.json';
        if (!$id || !is_file($dumpFile)) jsonResp(['ok' => false, 'msg' => '上传详情不存在']);
        header('Content-Type: application/json; charset=utf-8');
        $detail = json_decode((string)@file_get_contents($dumpFile), true);
        if (isset($_GET['full'])) {
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

// ===== 代理转发逻辑 =====
header('Content-Type: application/json; charset=utf-8');

$requestStart = microtime(true);
$stageMark = $requestStart;
$rawBody = file_get_contents('php://input');
if (!$rawBody) jsonResp(['ok' => false, 'msg' => '空请求体']);
$rawReadMs = durationMs($stageMark, microtime(true));

$stageMark = microtime(true);
$input = json_decode($rawBody, true);
if (!$input) jsonResp(['ok' => false, 'msg' => 'JSON解析失败']);
$requestJsonMs = durationMs($stageMark, microtime(true));

$postAct = (string)($input['act'] ?? '');
if ($postAct === 'api1_login') {
    $username = trim((string)($input['username'] ?? ''));
    $password = (string)($input['password'] ?? '');
    if ($username === '' || $password === '') {
        jsonResp(['code' => '400', 'data' => null, 'msg' => '账号或密码为空']);
    }

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
    global $API2_FIXED_USERNAME;
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
        jsonResp(['code' => '403', 'data' => null, 'msg' => "接口2编号需在{$api2Min}-{$api2Max}范围内"]);
    }

    $allowed = readApi1AllowedAccounts($API2_ACCOUNTS_FILE);
    if (!in_array($username, accountNames($allowed), true)) {
        appendLog($LOG_FILE, [
            'time' => date('Y-m-d H:i:s'),
            'api_type' => 2,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'username' => $username,
            'status' => 'login_rejected',
            'error' => '账号未在后台调速白名单',
        ], $MAX_LOGS);
        jsonResp(['code' => '403', 'data' => null, 'msg' => '账号未授权，请联系管理员']);
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
    $serverTaskId = is_array($respData) ? trim((string)($respData['task_id'] ?? $respData['trace_id'] ?? $respData['id'] ?? '')) : '';
    $serverReceivedId = is_array($respData) ? trim((string)($respData['submit_id'] ?? '')) : '';
    $proxyContextMatch = $taskId !== '' ? (($serverTaskId !== '' && $serverTaskId === $taskId) || ($serverReceivedId !== '' && $serverReceivedId === $submitId)) : true;
    if (!$proxyContextMatch) {
        $isForwardSuccess = false;
    }

    $uploadId = date('Ymd_His') . '_' . substr(md5($rawBody . '|ios_submit'), 0, 8);
    $logEntry = [
        'time' => date('Y-m-d H:i:s'),
        'api_type' => 1,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
        'username' => $username,
        'account_remark' => displayAccountRemark(1, $username),
        'device_id' => $input['device_id'] ?? '',
        'fingerprint_key' => $input['fingerprint_key'] ?? '',
        'status' => $result['error'] ? 'forward_fail' : ($isForwardSuccess ? 'success' : 'task_server_error'),
        'source' => 'ios_submit',
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
        'source' => 'ios_submit',
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
    $payload = api2ForwardPayload((string)$username, (string)$groupId, is_array($taskInfo) ? $taskInfo : [], $actualData);
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

if ($serverResp) {
    jsonResp($serverResp);
} else {
    jsonResp(['ok' => false, 'msg' => '任务服务器响应异常', 'raw' => $result['response']]);
}

// ===== 前端页面渲染 =====
function renderPage(): void {
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>格界APP控制台</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--primary:#6366f1;--primary-light:#818cf8;--primary-dark:#4f46e5;--success:#10b981;--danger:#ef4444;--warning:#f59e0b;--info:#8b5cf6;--sidebar:#0f172a;--sidebar-w:250px;--header-h:60px;--bg:#f1f5f9;--card:#ffffff;--border:#e2e8f0;--text:#1e293b;--muted:#94a3b8;--font:'Inter',-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB",sans-serif;--radius:12px;--shadow:0 1px 3px rgba(0,0,0,.04),0 1px 2px rgba(0,0,0,.06);--shadow-md:0 4px 6px -1px rgba(0,0,0,.07),0 2px 4px -2px rgba(0,0,0,.05);--shadow-lg:0 10px 15px -3px rgba(0,0,0,.08),0 4px 6px -4px rgba(0,0,0,.04)}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--font);background:var(--bg);color:var(--text);font-size:14px;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}
::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:3px}::-webkit-scrollbar-thumb:hover{background:#94a3b8}

/* Login */
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0a0a0a url('bj.jpeg') center/cover no-repeat fixed;position:relative;overflow:hidden}
.login-wrap::before{content:'';position:absolute;inset:0;background:rgba(0,0,0,.45)}
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
.sidebar-menu{padding:12px 10px 270px}
.menu-item{display:flex;align-items:center;height:42px;padding:0 14px;color:rgba(255,255,255,.55);cursor:pointer;font-size:14px;font-weight:500;transition:all .2s;gap:12px;border-radius:8px;margin-bottom:2px}
.menu-item:hover{color:rgba(255,255,255,.9);background:rgba(255,255,255,.06)}
.menu-item.active{color:#fff;background:linear-gradient(135deg,rgba(99,102,241,.3),rgba(139,92,246,.2));box-shadow:0 2px 8px rgba(99,102,241,.15)}
.menu-icon{width:20px;text-align:center;font-style:normal;font-size:15px;opacity:.8}
.side-pet{position:absolute;left:0;right:0;top:60px;bottom:0;overflow:hidden;pointer-events:none;--pet-x:0px;--pet-y:0px;--pet-tilt:0deg}
.side-pet::before{content:'';position:absolute;left:10px;right:10px;bottom:-54px;height:230px;background:radial-gradient(ellipse at 50% 45%,rgba(59,130,246,.18),rgba(30,64,175,.08) 42%,transparent 70%);filter:blur(1px);opacity:.9;transition:opacity .25s}
.side-pet::after{content:'';position:absolute;left:28px;right:28px;bottom:16px;height:1px;background:linear-gradient(90deg,transparent,rgba(148,163,184,.35),transparent)}
.side-pet:hover::before{opacity:1;background:radial-gradient(ellipse at 50% 45%,rgba(59,130,246,.28),rgba(220,38,38,.12) 44%,transparent 72%)}
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
.main{margin-left:var(--sidebar-w);flex:1;min-width:0}
.header{height:var(--header-h);background:rgba(255,255,255,.85);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;padding:0 28px;position:sticky;top:0;z-index:50}
.header-left{font-size:18px;font-weight:700;letter-spacing:-0.3px;color:#0f172a}
.header-right{display:flex;align-items:center;gap:20px;font-size:13px;color:var(--muted)}
.header-right a{color:var(--danger);text-decoration:none;cursor:pointer;font-weight:600;padding:6px 14px;border-radius:6px;transition:all .2s;font-size:13px}
.header-right a:hover{background:rgba(239,68,68,.06)}
.content{padding:24px 28px}

/* Cards */
.stat-row{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.stat-card{background:var(--card);border-radius:var(--radius);padding:22px 24px;border:1px solid var(--border);box-shadow:var(--shadow);transition:all .25s;position:relative;overflow:hidden}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--primary),var(--info));opacity:0;transition:opacity .25s}
.stat-card:hover{box-shadow:var(--shadow-md);transform:translateY(-2px)}
.stat-card:hover::before{opacity:1}
.stat-card .label{font-size:12px;color:var(--muted);margin-bottom:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px}
.stat-card .value{font-size:30px;font-weight:800;letter-spacing:-1px}
.stat-card .value.green{color:var(--success)}.stat-card .value.red{color:var(--danger)}.stat-card .value.blue{color:var(--primary)}.stat-card .value.purple{color:var(--info)}
.card{background:var(--card);border-radius:var(--radius);border:1px solid var(--border);margin-bottom:20px;box-shadow:var(--shadow);transition:box-shadow .25s}
.card:hover{box-shadow:var(--shadow-md)}
.card-head{padding:18px 24px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.card-head h3{font-size:15px;font-weight:700;letter-spacing:-0.2px;color:#0f172a}
.card-body{padding:20px 24px}
.card-toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}

/* Table */
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:12px 14px;border-bottom:1px solid #f1f5f9;font-size:13px;white-space:nowrap}
th{background:#f8fafc;font-weight:600;color:#64748b;white-space:nowrap;text-transform:uppercase;font-size:11px;letter-spacing:0.5px}
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
.btn-primary{background:linear-gradient(135deg,var(--primary),var(--primary-dark));box-shadow:0 2px 8px rgba(99,102,241,.25)}.btn-success{background:linear-gradient(135deg,var(--success),#059669);box-shadow:0 2px 8px rgba(16,185,129,.25)}.btn-danger{background:linear-gradient(135deg,var(--danger),#dc2626);box-shadow:0 2px 8px rgba(239,68,68,.25)}.btn-warning{background:linear-gradient(135deg,var(--warning),#d97706);color:#fff;box-shadow:0 2px 8px rgba(245,158,11,.25)}.btn-info{background:linear-gradient(135deg,var(--info),#7c3aed);box-shadow:0 2px 8px rgba(139,92,246,.25)}.btn-default{background:#fff;color:var(--text);border:1px solid var(--border);box-shadow:var(--shadow)}
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
pre.resp{background:#f8fafc;padding:12px 14px;border-radius:8px;font-size:12px;overflow-x:auto;max-height:160px;margin-top:8px;color:#334155;border:1px solid #e2e8f0;line-height:1.6}

/* Device */
.device-card{padding:14px 16px;border:1px solid var(--border);border-radius:10px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}
.device-info{flex:1;min-width:200px}
.device-info b{font-size:15px}
.device-meta{font-size:12px;color:var(--muted);margin-top:4px;display:flex;gap:12px;flex-wrap:wrap}

/* Stats user row */
.stats-user{padding:18px 20px;border:1px solid var(--border);border-radius:10px;margin-bottom:12px;background:#fff;transition:all .2s;box-shadow:var(--shadow)}
.stats-user:hover{box-shadow:var(--shadow-md);border-color:#cbd5e1}
.stats-user-head{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}
.stats-nums{display:flex;gap:24px;font-size:14px}
.stats-records{margin-top:8px;font-size:12px;color:var(--muted)}

.empty{text-align:center;padding:48px;color:var(--muted);font-size:14px}
.hidden{display:none !important}
@media(max-width:768px){.sidebar{width:0;overflow:hidden}.main{margin-left:0}.stat-row{grid-template-columns:repeat(2,1fr)}.form-grid{grid-template-columns:1fr}.login-box{width:90vw;padding:32px 24px}.header{padding:0 16px}.content{padding:16px}}

.modal-mask{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(15,23,42,.5);backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px);z-index:200;display:flex;align-items:center;justify-content:center;animation:fadeIn .2s ease}
@keyframes fadeIn{0%{opacity:0}100%{opacity:1}}
.modal-box{background:#fff;border-radius:16px;padding:28px;width:480px;max-width:90vw;max-height:80vh;overflow-y:auto;box-shadow:0 25px 60px rgba(0,0,0,.2);animation:modalIn .3s cubic-bezier(.16,1,.3,1)}
@keyframes modalIn{0%{opacity:0;transform:scale(.95) translateY(10px)}100%{opacity:1;transform:scale(1) translateY(0)}}
.modal-box h3{margin-bottom:20px;font-size:17px;font-weight:700;color:#0f172a}
.modal-footer{margin-top:20px;display:flex;justify-content:flex-end;gap:10px}
</style>
</head>
<body>

<!-- Login Page -->
<div class="login-wrap" id="loginPage">
<div class="login-box">
    <div style="text-align:center;margin-bottom:20px">
        <img src="1777990327149137925.png" alt="logo" style="width:80px;height:80px;border-radius:16px;object-fit:cover;box-shadow:0 8px 24px rgba(0,0,0,.15)">
    </div>
    <h1>格界APP控制台</h1>
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
        格界控制台
    </div>
    <div class="sidebar-menu">
        <div class="menu-item active" onclick="switchPage('dashboard',this)"><i class="menu-icon">&#9632;</i>仪表盘</div>
        <div class="menu-item" onclick="switchPage('logs',this)"><i class="menu-icon">&#9776;</i>转发日志</div>
        <div class="menu-item" onclick="switchPage('devices',this)"><i class="menu-icon">&#9679;</i>在线设备</div>
        <div class="menu-item" onclick="switchPage('stats',this)"><i class="menu-icon">&#9733;</i>环境统计</div>
        <div class="menu-item" onclick="switchPage('accounts',this)"><i class="menu-icon">&#9737;</i>账号授权</div>
        <div class="menu-item" onclick="switchPage('update',this)"><i class="menu-icon">&#8679;</i>更新发布</div>
        <div class="menu-item" onclick="switchPage('verctrl',this)"><i class="menu-icon">&#9881;</i>版本控制</div>
        <div class="menu-item" onclick="switchPage('data',this)"><i class="menu-icon">&#128196;</i>解密数据</div>
        <div class="menu-item" onclick="switchPage('submitstats',this)"><i class="menu-icon">&#9851;</i>数量查看</div>
    </div>
    <div class="side-pet" aria-hidden="true">
        <div class="rocket-trail"></div>
        <div class="pet-shadow"></div>
        <div class="pet-hit">
            <div class="pet-time" id="petTime"></div>
            <div class="pet-stage">
                <div class="pet-spark s1"></div>
                <div class="pet-spark s2"></div>
                <div class="pet-spark s3"></div>
                <div class="pet-anim"></div>
            </div>
        </div>
    </div>
</div>
<div class="main">
    <div class="header">
        <div class="header-left" id="pageTitle">仪表盘</div>
        <div class="header-right">
            <span id="headerTime"></span>
            <a onclick="doLogout()">退出登录</a>
        </div>
    </div>
    <div class="content">

    <!-- Dashboard -->
    <div class="page" id="page-dashboard">
        <div class="stat-row" id="dashStats"></div>
        <div class="card"><div class="card-head"><h3>最近转发</h3><div class="card-toolbar"><button class="btn btn-primary btn-sm" onclick="switchPage('logs',document.querySelectorAll('.menu-item')[1])">查看全部</button></div></div><div class="card-body"><div id="dashLogs" style="max-height:400px;overflow-y:auto"><div class="empty">加载中...</div></div></div></div>
    </div>

    <!-- Logs -->
    <div class="page hidden" id="page-logs">
        <div class="card"><div class="card-head"><h3>转发日志</h3><div class="card-toolbar"><button class="btn btn-primary btn-sm" onclick="loadLogs()">刷新</button><button class="btn btn-success btn-sm" onclick="toggleAutoLog()" id="autoLogBtn">自动刷新</button><button class="btn btn-danger btn-sm" onclick="clearLogs()">清空</button></div></div><div class="card-body" style="padding:0"><div id="logList"><div class="empty">点击刷新加载日志</div></div></div></div>
    </div>

    <!-- Devices -->
    <div class="page hidden" id="page-devices">
        <div class="card"><div class="card-head"><h3>在线设备 <span id="onlineCount" style="color:var(--success);font-size:14px"></span></h3><div class="card-toolbar"><span style="font-size:12px;color:var(--muted)">每10秒自动刷新，仅显示最近2分钟有心跳的设备</span></div></div><div class="card-body"><div id="deviceList"><div class="empty">加载中...</div></div></div></div>
    </div>

    <!-- Stats -->
    <div class="page hidden" id="page-stats">
        <div class="card"><div class="card-head"><h3>指纹环境管理</h3><div class="card-toolbar"><select id="statsDate" onchange="loadStats()" style="height:34px;border:2px solid #e2e8f0;border-radius:8px;padding:0 12px;font-size:13px;font-family:var(--font);background:#f8fafc"></select><button class="btn btn-danger btn-sm" onclick="clearStats()">清除统计</button></div></div><div class="card-body"><div id="statsBody"><div class="empty">加载中...</div></div></div></div>
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
                </div>
            </div>
            <div class="card-body" style="padding:0"><div style="font-size:12px;color:var(--muted);padding:10px 12px 0">未设置账号会拒绝登录</div><div id="api1Table"><div class="empty">加载中...</div></div></div>
        </div>
        <div class="card">
            <div class="card-head">
                <h3>调速账号白名单 <span id="api2Count" style="font-size:13px;color:var(--muted)"></span></h3>
                <div class="card-toolbar">
                    <button class="btn btn-primary btn-sm" onclick="showAddAccount(2)">单独添加</button>
                    <button class="btn btn-info btn-sm" onclick="showBatchAdd(2)">批量添加</button>
                </div>
            </div>
            <div class="card-body" style="padding:0"><div id="api2LoginRangeTip" style="font-size:12px;color:var(--muted);padding:10px 12px 0">用于接口2登录账号白名单；登录密码为后台设置范围内的用户编号</div><div id="api2Table"><div class="empty">加载中...</div></div></div>
        </div>
        <div class="card">
            <div class="card-head">
                <h3>调速编号备注 <span id="api2NumberCount" style="font-size:13px;color:var(--muted)"></span></h3>
                <div class="card-toolbar">
                    <button class="btn btn-primary btn-sm" onclick="showAddAccount(3)">单独添加</button>
                    <button class="btn btn-info btn-sm" onclick="showBatchAdd(3)">批量添加</button>
                </div>
            </div>
            <div class="card-body" style="padding:0"><div style="font-size:12px;color:var(--muted);padding:10px 12px 0">用于7000、7029这类接口2用户编号备注显示</div><div id="api2NumberTable"><div class="empty">加载中...</div></div></div>
        </div>
        </div>
    </div>

    <!-- Update -->
    <div class="page hidden" id="page-update">
        <div class="card"><div class="card-head"><h3>在线更新发布</h3></div><div class="card-body"><div id="updateBody"><div class="empty">加载中...</div></div></div></div>
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

    <!-- Submit Stats -->
    <div class="page hidden" id="page-submitstats">
        <div class="card"><div class="card-head"><h3>提交数量统计</h3><div class="card-toolbar"><select id="submitStatsDate" onchange="loadSubmitStats()" style="height:34px;border:2px solid #e2e8f0;border-radius:8px;padding:0 12px;font-size:13px;font-family:var(--font);background:#f8fafc"></select><button class="btn btn-primary btn-sm" onclick="loadSubmitStats()">刷新</button></div></div><div class="card-body"><div id="submitStatsBody"><div class="empty">加载中...</div></div></div></div>
    </div>

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
let KEY = localStorage.getItem('admin_key') || '';
let autoLogTimer = null, deviceTimer = null;

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
function initSidePet() {
    const pet = document.querySelector('.side-pet');
    if (!pet || pet.dataset.ready) return;
    pet.dataset.ready = '1';
    const hit = pet.querySelector('.pet-hit');
    const timeEl = pet.querySelector('#petTime');
    const updatePetMetrics = () => {
        const r = pet.getBoundingClientRect();
        pet.style.setProperty('--pet-rise', Math.max(560, Math.round(r.height + 220)) + 'px');
    };
    const updatePetTime = () => {
        if (!timeEl) return;
        const now = new Date();
        const pad = n => String(n).padStart(2, '0');
        timeEl.textContent = `${now.getFullYear()}-${pad(now.getMonth()+1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
    };
    updatePetMetrics();
    updatePetTime();
    window.addEventListener('resize', updatePetMetrics);
    setInterval(updatePetTime, 1000);
    hit.addEventListener('mousemove', e => {
        const r = hit.getBoundingClientRect();
        const px = (e.clientX - r.left) / r.width - .5;
        const py = (e.clientY - r.top) / r.height - .5;
        pet.style.setProperty('--pet-x', (px * 18).toFixed(1) + 'px');
        pet.style.setProperty('--pet-y', (py * 10).toFixed(1) + 'px');
        pet.style.setProperty('--pet-tilt', (px * 7).toFixed(1) + 'deg');
    });
    hit.addEventListener('mouseleave', () => {
        pet.style.setProperty('--pet-x', '0px');
        pet.style.setProperty('--pet-y', '0px');
        pet.style.setProperty('--pet-tilt', '0deg');
    });
    hit.addEventListener('click', e => {
        if (pet.classList.contains('is-launching')) return;
        const r = pet.getBoundingClientRect();
        const pulse = document.createElement('span');
        pulse.className = 'pet-pulse';
        pulse.style.left = (e.clientX - r.left) + 'px';
        pulse.style.top = (e.clientY - r.top) + 'px';
        pet.appendChild(pulse);
        pet.classList.remove('is-launching');
        void pet.offsetWidth;
        pet.classList.add('is-launching');
        setTimeout(() => pulse.remove(), 700);
        setTimeout(() => pet.classList.remove('is-launching'), 3650);
    });
}
function showAdmin() {
    document.getElementById('loginPage').classList.add('hidden');
    document.getElementById('adminLayout').classList.remove('hidden');
    initSidePet();
    loadDashboard();
    setInterval(()=>{ document.getElementById('headerTime').textContent = new Date().toLocaleTimeString(); }, 1000);
}

if (KEY) { authFetch(BASE+'?act=logs&limit=1').then(r=>r.json()).then(d=>{ if(d.ok!==false||d.msg!=='密码错误') showAdmin(); else { KEY=''; localStorage.removeItem('admin_key'); }}).catch(()=>{}); }

const pageTitles = {dashboard:'仪表盘',logs:'转发日志',devices:'在线设备',stats:'指纹环境管理',accounts:'账号授权',update:'更新发布',verctrl:'版本控制',data:'解密数据',submitstats:'数量查看'};
let currentPage = 'dashboard';
function switchPage(name, el) {
    if (deviceTimer && name !== 'devices') { clearInterval(deviceTimer); deviceTimer = null; }
    currentPage = name;
    document.querySelectorAll('.page').forEach(p=>p.classList.add('hidden'));
    document.getElementById('page-'+name).classList.remove('hidden');
    document.querySelectorAll('.menu-item').forEach(m=>m.classList.remove('active'));
    if (el) el.classList.add('active');
    document.getElementById('pageTitle').textContent = pageTitles[name]||name;
    if (name==='dashboard') loadDashboard();
    else if (name==='logs') loadLogs();
    else if (name==='devices') { loadDevices(); if(!deviceTimer) deviceTimer=setInterval(loadDevices,10000); }
    else if (name==='stats') loadStats();
    else if (name==='accounts') loadApi1Accounts();
    else if (name==='update') loadUpdateConfig();
    else if (name==='verctrl') loadVerCtrl();
    else if (name==='data') loadDumpList();
    else if (name==='submitstats') loadSubmitStats();
}

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function escAttr(s){return esc(s).replace(/"/g,'&quot;');}
function authFetch(url,opts){opts=opts||{};if(!opts.headers)opts.headers={};opts.headers['X-Auth-Key']=KEY;return fetch(url,opts);}
async function viewJson(act,id){
    try{
        const r=await authFetch(BASE+'?act='+act+'&id='+id);
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
        let stTag = '';
        if(st==='success') stTag='<span class="tag tag-success">成功</span>';
        else if(st==='decrypt_fail'||st==='json_fail') stTag=`<span class="tag tag-danger">${st}</span>`;
        else if(st) stTag=`<span class="tag tag-warning">${st}</span>`;
        let body='';
        if(l.username) body+=`<b>用户:</b><code>${esc(l.username)}</code>${l.account_remark?'<span style="color:var(--danger);font-weight:600;font-size:12px;margin-left:4px">'+esc(l.account_remark)+'</span>':''} `;
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
        const dH=l.dump_id?`<a href="javascript:void(0)" onclick="viewJson('dump','${encodeURIComponent(l.dump_id)}')">解密数据</a>`:'';
        const uH=l.upload_id?`<a href="javascript:void(0)" onclick="viewJson('upload','${encodeURIComponent(l.upload_id)}')">上传详情</a>`:'';
        return `<div class="log-entry"><div class="log-meta">${apiTag} ${stTag} <span style="color:var(--muted);font-size:12px">${l.time||''} &nbsp; IP:${l.ip||'-'}</span></div><div class="log-detail">${body}</div>${(dH||uH)?`<div class="log-actions">${dH} ${uH}</div>`:''} ${resp}</div>`;
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
    if(!devs.length){el.innerHTML='<div class="empty">当前没有在线设备</div>';return;}

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
            const st=dis?'<span class="tag tag-danger" style="font-size:11px">禁用</span>':'<span class="tag tag-success" style="font-size:11px">在线</span>';
            const deviceLabel=dv.device_label||(String(dv.platform||dv.device_type||'').toLowerCase()==='ios'?'iOS设备':'-');
            const singleBtn=dis
                ?`<button class="btn btn-success btn-sm" onclick="toggleDevice('${esc(dv.key)}',0)">启用</button>`
                :`<button class="btn btn-danger btn-sm" onclick="toggleDevice('${esc(dv.key)}',1)">禁用</button>`;
            return `<tr>
                <td>${st}</td>
                <td>${esc(deviceLabel)} ${esc(dv.fingerprint_name||((dv.fingerprint_id||dv.fingerprint_key||'').substring(0,14))||'-')}</td>
                <td style="font-size:12px">${esc((dv.device_id||'-').substring(0,14))}</td>
                <td style="font-size:12px">${esc(dv.ip||'-')}</td>
                <td style="font-size:12px;color:var(--muted)">${esc((dv.last_seen||'').substring(11)||'-')}</td>
                <td style="display:flex;gap:6px">${singleBtn}</td>
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

// ===== Stats =====
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
let api1Data=[], api2Data=[], api2NumberData=[];
let acctModalMode='', acctEditApiType=0, acctEditUsername='';
const accountPager={1:{page:1,size:10},2:{page:1,size:10},3:{page:1,size:10}};

function accountDataByType(apiType){
    return apiType===1?api1Data:(apiType===2?api2Data:api2NumberData);
}

function accountTargetByType(apiType){
    return apiType===1?'api1Table':(apiType===2?'api2Table':'api2NumberTable');
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

function updateApi2RangeTip(config){
    const el=document.getElementById('api2LoginRangeTip');
    if(!el)return;
    const min=(config&&config.api2_login_min!==undefined)?config.api2_login_min:0;
    const max=config&&config.api2_login_max?config.api2_login_max:10000;
    el.textContent='用于接口2登录账号白名单；登录密码为 '+min+'-'+max+' 内的用户编号';
}

async function loadApi1Accounts(){
    const [r1,r2,r3,r4]=await Promise.all([
        authFetch(BASE+'?act=api1_accounts').then(r=>r.json()),
        authFetch(BASE+'?act=api2_accounts').then(r=>r.json()),
        authFetch(BASE+'?act=api2_numbers').then(r=>r.json()),
        authFetch(BASE+'?act=version_controls').then(r=>r.json())
    ]);
    if(r1.ok){ api1Data=r1.data||[]; renderAccountTable(api1Data,'api1Table',1); }
    if(r2.ok){ api2Data=r2.data||[]; renderAccountTable(api2Data,'api2Table',2); }
    if(r3.ok){ api2NumberData=r3.data||[]; renderAccountTable(api2NumberData,'api2NumberTable',3); }
    if(r4.ok){ updateApi2RangeTip(r4.data||{}); }
    document.getElementById('api1Count').textContent='('+api1Data.length+'个)';
    document.getElementById('api2Count').textContent='('+api2Data.length+'个)';
    document.getElementById('api2NumberCount').textContent='('+api2NumberData.length+'个)';
}

function renderAccountTable(accounts, targetId, apiType){
    const el=document.getElementById(targetId);
    const label=apiType===3?'编号':'账号';
    if(!accounts.length){el.innerHTML='<div class="empty">暂无'+label+'</div>';return;}
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
    if(!accounts.length){el.innerHTML='<div class="empty">暂无'+label+'</div>';return;}
    const pager=accountPager[apiType]||{page:1,size:10};
    const total=accounts.length;
    const totalPages=Math.max(1,Math.ceil(total/pager.size));
    pager.page=Math.min(Math.max(1,pager.page),totalPages);
    const start=(pager.page-1)*pager.size;
    const pageRows=accounts.slice(start,start+pager.size);
    const from=start+1;
    const to=Math.min(start+pager.size,total);
    el.innerHTML=`<table><thead><tr><th style="width:50px">#</th><th>${label}</th><th>备注</th><th style="width:78px;text-align:center">修改</th><th style="width:78px;text-align:center">操作</th></tr></thead><tbody>${
        pageRows.map((a,i)=>{
            const name=a.username||a;
            const remark=a.remark||'';
            return `<tr><td>${start+i+1}</td><td><code>${esc(name)}</code></td><td>${esc(remark||'-')}</td><td style="text-align:center">
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
    const sample=apiType===3?'7000 张三\n7029|李四':'user1 备注1\nuser2|备注2\nuser3';
    document.getElementById('acctModalTitle').textContent=title;
    document.getElementById('acctModalBody').innerHTML=`
        <div class="form-item"><label>每行一个${label}，格式：${label} 备注 或 ${label}|备注</label>
        <textarea id="acctBatchInput" rows="10" placeholder="${sample}" style="height:220px;width:100%;border:2px solid #e2e8f0;border-radius:8px;padding:10px 12px;font-size:14px;resize:vertical;font-family:monospace;background:#f8fafc;transition:all .2s"></textarea></div>`;
    document.getElementById('accountModal').classList.remove('hidden');
    setTimeout(()=>{const inp=document.getElementById('acctBatchInput');if(inp)inp.focus();},100);
}

function showEditAccountRemark(apiType, username){
    acctModalMode='edit';
    acctEditApiType=apiType;
    acctEditUsername=username;
    const label=apiType===3?'编号':'账号';
    const data=apiType===1?api1Data:(apiType===2?api2Data:api2NumberData);
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
    if(acctModalMode.startsWith('add')){
        const apiType=parseInt(acctModalMode.replace('add',''));
        const label=apiType===3?'编号':'账号';
        const name=(document.getElementById('acctInputName').value||'').trim();
        const remark=(document.getElementById('acctInputRemark').value||'').trim();
        if(!name) return alert('请输入'+label);
        const data=apiType===1?api1Data:(apiType===2?api2Data:api2NumberData);
        if(data.some(a=>(a.username||a)===name)) return alert(label+'已存在');
        data.push({username:name,remark:remark});
        await saveAccountList(apiType,data);
    }else if(acctModalMode.startsWith('batch')){
        const apiType=parseInt(acctModalMode.replace('batch',''));
        const label=apiType===3?'编号':'账号';
        const text=(document.getElementById('acctBatchInput').value||'').trim();
        if(!text) return alert('请输入'+label);
        const data=apiType===1?[...api1Data]:(apiType===2?[...api2Data]:[...api2NumberData]);
        const existingNames=new Set(data.map(a=>a.username||a));
        let added=0;
        for(const line of text.split(/\r?\n/)){
            const trimmed=line.trim();
            if(!trimmed) continue;
            let name,remark;
            if(trimmed.includes('|')){[name,remark]=trimmed.split('|',2);}
            else{const parts=trimmed.split(/\s+/,2);name=parts[0];remark=parts[1]||'';}
            name=(name||'').trim(); remark=(remark||'').trim();
            if(name&&!existingNames.has(name)){data.push({username:name,remark:remark});existingNames.add(name);added++;}
        }
        if(apiType===1) api1Data=data; else if(apiType===2) api2Data=data; else api2NumberData=data;
        await saveAccountList(apiType,data);
        alert('已添加 '+added+' 个'+label);
    }else if(acctModalMode==='edit'){
        const apiType=acctEditApiType;
        const username=acctEditUsername;
        const remark=(document.getElementById('acctEditRemark').value||'').trim();
        let data=apiType===1?[...api1Data]:(apiType===2?[...api2Data]:[...api2NumberData]);
        let found=false;
        data=data.map(a=>{
            const name=a.username||a;
            if(name!==username) return a;
            found=true;
            return {username:name,remark:remark};
        });
        if(!found) return alert('未找到要修改的账号');
        if(apiType===1) api1Data=data; else if(apiType===2) api2Data=data; else api2NumberData=data;
        await saveAccountList(apiType,data);
    }
    closeAccountModal();
    loadApi1Accounts();
}

async function deleteAccount(apiType,username){
    const label=apiType===3?'编号':'账号';
    if(!confirm('确定删除'+label+' '+username+' ?')) return;
    let data=apiType===1?api1Data:(apiType===2?api2Data:api2NumberData);
    data=data.filter(a=>(a.username||a)!==username);
    if(apiType===1) api1Data=data; else if(apiType===2) api2Data=data; else api2NumberData=data;
    await saveAccountList(apiType,data);
    loadApi1Accounts();
}

async function saveAccountList(apiType,data){
    const text=data.map(a=>(a.username||a)+(a.remark?'|'+a.remark:'')).join('\n');
    const act=apiType===1?'save_api1_accounts':(apiType===2?'save_api2_accounts':'save_api2_numbers');
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
    const r=await authFetch(BASE+'?act=update_config');
    const d=await r.json();
    if(!d.ok)return;
    const c=d.data||{};
    document.getElementById('updateBody').innerHTML=`
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
        </div></form>`;
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

// ===== Submit Stats =====
async function loadSubmitStats(){
    const sel=document.getElementById('submitStatsDate');
    const date=sel.value||'';
    const r=await authFetch(BASE+'?act=submit_stats'+(date?'&date='+encodeURIComponent(date):''));
    const d=await r.json();
    if(!d.ok)return;
    if(d.dates&&d.dates.length){const cv=sel.value||d.date;sel.innerHTML=d.dates.map(dt=>`<option value="${dt}" ${dt===cv?'selected':''}>${dt}</option>`).join('');}
    const el=document.getElementById('submitStatsBody');
    const users=d.data||[];
    if(!users.length){el.innerHTML='<div class="empty">当天暂无提交记录</div>';return;}

    const totals={total:0,success:0,fail:0,api1_total:0,api1_success:0,api2_total:0,api2_success:0};
    users.forEach(u=>{totals.total+=u.total;totals.success+=u.success;totals.fail+=u.fail;totals.api1_total+=u.api1_total;totals.api1_success+=u.api1_success;totals.api2_total+=u.api2_total;totals.api2_success+=u.api2_success;});

    let html=`<div class="stat-row" style="margin-bottom:16px">
        <div class="stat-card"><div class="label">日期</div><div class="value" style="font-size:18px">${esc(d.date)}</div></div>
        <div class="stat-card"><div class="label">总提交</div><div class="value">${totals.total}</div></div>
        <div class="stat-card"><div class="label">聚星成功</div><div class="value blue">${totals.api1_success}<span style="font-size:14px;color:var(--muted);margin-left:4px">/ ${totals.api1_total}</span></div></div>
        <div class="stat-card"><div class="label">调速成功</div><div class="value purple">${totals.api2_success}<span style="font-size:14px;color:var(--muted);margin-left:4px">/ ${totals.api2_total}</span></div></div>
    </div>`;

    html+=`<table><thead><tr>
        <th style="width:50px">#</th><th>用户名</th><th>备注</th>
        <th style="text-align:center">聚星提交</th><th style="text-align:center">聚星成功</th>
        <th style="text-align:center">调速提交</th><th style="text-align:center">调速成功</th>
        <th style="text-align:center">总提交</th><th style="text-align:center">总成功</th><th style="text-align:center">失败</th>
    </tr></thead><tbody>`;
    users.forEach((u,i)=>{
        const rate=u.total>0?Math.round(u.success/u.total*100):0;
        html+=`<tr>
            <td>${i+1}</td>
            <td><b>${esc(u.username)}</b></td>
            <td>${u.account_remark?'<span style="color:var(--danger);font-weight:600">'+esc(u.account_remark)+'</span>':'-'}</td>
            <td style="text-align:center">${u.api1_total||'-'}</td>
            <td style="text-align:center;color:var(--primary);font-weight:700">${u.api1_success||'-'}</td>
            <td style="text-align:center">${u.api2_total||'-'}</td>
            <td style="text-align:center;color:var(--info);font-weight:700">${u.api2_success||'-'}</td>
            <td style="text-align:center"><b>${u.total}</b></td>
            <td style="text-align:center;color:var(--success);font-weight:700">${u.success}</td>
            <td style="text-align:center;color:${u.fail?'var(--danger)':'var(--muted)'}">${u.fail||'-'}</td>
        </tr>`;
    });
    html+='</tbody></table>';
    el.innerHTML=html;
}
</script>
</body>
</html>
<?php
}
