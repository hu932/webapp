<?php
/*
 * 公共账号查询页
 * - 只允许后台白名单账号查询
 * - 最近三天数据从聚星上游接口（同 cx.php）拉取，后台统一缓存
 * - 前端 120s 无感刷新，无手动刷新按钮
 */

session_start();

$STATS_DIR = __DIR__ . '/daily_stats';
$API1_ACCOUNTS_FILE = __DIR__ . '/api1_allowed_accounts.json';
$API2_ACCOUNTS_FILE = __DIR__ . '/api2_allowed_accounts.json';

// 聚星上游接口（与 cx.php 对齐）
$CX_API_BASE = 'https://zb1.eqwofaygdsjko.uk/api';
$CX_USERNAME = 'amberorr069';
$CX_PASSWORD = 'Wi80^O+x!8';
$CX_CACHE_TTL = 120;      // 后端缓存 120s,与 cx.php 对齐
$FRONT_REFRESH_MS = 120000; // 前端 120s 无感刷新

// 防刷：HMAC 签名 + 速率限制
$QUERY_SECRET = 'gj-pq-2026-please-change-this-to-a-long-random-string';
$TOKEN_TTL    = 3600;   // 1 小时，过期前端会自动重新登录拿新 token
$RL_LOGIN_WINDOW = 30;  // 未带 token 时按 IP+账号 30s 内最多 3 次（足够首次登录用）
$RL_LOGIN_MAX    = 3;
$RL_QUERY_WINDOW = 60;  // 带 token 后按账号 60s 内最多 30 次（前端 120s 才请求一次，留余量）
$RL_QUERY_MAX    = 30;

function jsonResp(array $data): void {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

// ===== 防刷：HMAC token + 滑动窗口速率限制 =====
function pqClientIp(): string {
    foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'] as $h) {
        $v = (string)($_SERVER[$h] ?? '');
        if ($v === '') continue;
        $ip = trim(explode(',', $v)[0]);
        if ($ip !== '') return $ip;
    }
    return '0.0.0.0';
}

function pqIssueToken(string $account, int $ttl): string {
    global $QUERY_SECRET;
    $exp = time() + $ttl;
    $payload = $account . '|' . $exp;
    $sig = hash_hmac('sha256', $payload, $QUERY_SECRET);
    // 不可逆短码：只把 exp+sig 给前端；账号前端自己有
    return $exp . '.' . substr($sig, 0, 32);
}

function pqVerifyToken(string $account, string $token): bool {
    global $QUERY_SECRET;
    if ($account === '' || $token === '' || strpos($token, '.') === false) return false;
    [$expStr, $sigGiven] = explode('.', $token, 2);
    $exp = (int)$expStr;
    if ($exp <= time()) return false;
    $payload = $account . '|' . $exp;
    $sigExpect = substr(hash_hmac('sha256', $payload, $QUERY_SECRET), 0, 32);
    return hash_equals($sigExpect, $sigGiven);
}

function pqRateFile(string $key): string {
    return sys_get_temp_dir() . '/pq_rl_' . md5($key) . '.json';
}

// 滑动窗口：在 windowSec 内最多 max 次，超了返回 false
function pqRateAllow(string $key, int $windowSec, int $max): bool {
    $file = pqRateFile($key);
    $now = time();
    $hits = [];
    $fh = @fopen($file, 'c+');
    if (!$fh) return true; // 文件系统异常时不挡，避免误伤
    @flock($fh, LOCK_EX);
    $raw = stream_get_contents($fh);
    $data = $raw !== false ? json_decode($raw, true) : null;
    if (is_array($data) && is_array($data['hits'] ?? null)) {
        foreach ($data['hits'] as $t) {
            $t = (int)$t;
            if ($t > $now - $windowSec) $hits[] = $t;
        }
    }
    $allow = count($hits) < $max;
    if ($allow) $hits[] = $now;
    rewind($fh);
    ftruncate($fh, 0);
    fwrite($fh, json_encode(['hits' => $hits], JSON_UNESCAPED_SLASHES));
    @flock($fh, LOCK_UN);
    fclose($fh);
    return $allow;
}

function readAllowedAccounts(string $file): array {
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

function accountRemarkMap(array $accounts): array {
    $map = [];
    foreach ($accounts as $account) {
        if (!is_array($account)) continue;
        $username = (string)($account['username'] ?? '');
        if ($username !== '') $map[$username] = (string)($account['remark'] ?? '');
    }
    return $map;
}

function accountNames(array $accounts): array {
    return array_values(array_filter(array_map(fn($a) => is_array($a) ? (string)($a['username'] ?? '') : (string)$a, $accounts)));
}

function getAccountAccess(string $username): array {
    global $API1_ACCOUNTS_FILE, $API2_ACCOUNTS_FILE;
    $api1 = readAllowedAccounts($API1_ACCOUNTS_FILE);
    $api2 = readAllowedAccounts($API2_ACCOUNTS_FILE);
    $api1Map = accountRemarkMap($api1);
    $api2Map = accountRemarkMap($api2);
    $hasApi1 = in_array($username, accountNames($api1), true);
    $hasApi2 = in_array($username, accountNames($api2), true);
    $remark = $api1Map[$username] ?? ($api2Map[$username] ?? '');
    return [
        'allowed' => $hasApi1 || $hasApi2,
        'api1' => $hasApi1,
        'api2' => $hasApi2,
        'remark' => $remark,
    ];
}

function getStatsFile(string $date = ''): string {
    global $STATS_DIR;
    if ($date === '') $date = date('Y-m-d');
    return rtrim($STATS_DIR, '/\\') . '/' . $date . '.json';
}

function readDayStats(string $date = ''): array {
    $file = getStatsFile($date);
    if (!is_file($file)) return [];
    $data = json_decode((string)@file_get_contents($file), true);
    return is_array($data) ? $data : [];
}

function rowBelongsToAccount(array $row, string $account, array $access): bool {
    $username = (string)($row['username'] ?? '');
    $groupId = (string)($row['group_id'] ?? '');
    $apiType = (int)($row['api_type'] ?? $row['api'] ?? 0);
    if ($access['api1'] && $username === $account) return true;
    if ($access['api2'] && ($groupId === $account || $username === $account)) return true;
    if ($apiType === 0 && ($username === $account || $groupId === $account)) return true;
    return false;
}

// ===== 聚星上游接口（与 cx.php 对齐） =====
function cxHttpPost(string $url, array $data, array $headers = []): ?array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_HTTPHEADER => array_merge(['Content-Type: application/json', 'Accept: application/json'], $headers),
    ]);
    $res = curl_exec($ch);
    $err = curl_error($ch);
    curl_close($ch);
    if ($err || $res === false) return null;
    $json = json_decode((string)$res, true);
    return is_array($json) ? $json : null;
}

function cxCacheFile(string $key): string {
    return sys_get_temp_dir() . '/pq_cx_cache_' . md5($key) . '.json';
}

function cxCacheRead(string $key): ?array {
    $file = cxCacheFile($key);
    if (!is_file($file)) return null;
    $data = json_decode((string)@file_get_contents($file), true);
    if (!is_array($data)) return null;
    return is_array($data['payload'] ?? null) ? $data['payload'] : null;
}

function cxCacheGet(string $key, int $ttl): ?array {
    $file = cxCacheFile($key);
    if (!is_file($file)) return null;
    $data = json_decode((string)@file_get_contents($file), true);
    if (!is_array($data) || (time() - (int)($data['_ts'] ?? 0)) > $ttl) return null;
    return is_array($data['payload'] ?? null) ? $data['payload'] : null;
}

function cxCacheSet(string $key, array $payload): void {
    @file_put_contents(
        cxCacheFile($key),
        json_encode(['_ts' => time(), 'payload' => $payload], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        LOCK_EX
    );
}

// 上次成功快照：按账号+日期保留最近一次"有数据"的结果，
// 用于上游异常时兜底，避免每次刷新失败就把界面打成 0。
function cxLastGoodFile(string $key): string {
    return sys_get_temp_dir() . '/pq_cx_lastgood_' . md5($key) . '.json';
}

function cxLastGoodGet(string $key): ?array {
    $file = cxLastGoodFile($key);
    if (!is_file($file)) return null;
    $data = json_decode((string)@file_get_contents($file), true);
    if (!is_array($data)) return null;
    return is_array($data['payload'] ?? null) ? $data['payload'] : null;
}

function cxLastGoodSet(string $key, array $payload): void {
    @file_put_contents(
        cxLastGoodFile($key),
        json_encode(['_ts' => time(), 'payload' => $payload], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        LOCK_EX
    );
}

// ===== 共享 cx.php 的全量缓存,避免重复打上游 =====
// cx.php 的 key 形如 cx_v2_<date>_<md5(authorizedAccounts JSON)>
// authorizedAccounts 来自 readAuthorizedJuxingAccounts(API1_ACCOUNTS_FILE),
// 这里复刻同样的读取/排序逻辑,保证 md5 一致。
function cxBuildAuthorizedAccounts(string $file): array {
    if (!is_file($file)) return [];
    $data = json_decode((string)@file_get_contents($file), true);
    if (!is_array($data)) return [];
    $accounts = $data['accounts'] ?? $data;
    if (!is_array($accounts)) return [];

    $result = [];
    foreach ($accounts as $account) {
        if (is_array($account)) {
            $username = trim((string)($account['username'] ?? $account['name'] ?? ''));
            $remark = trim((string)($account['remark'] ?? ''));
        } else {
            $username = trim((string)$account);
            $remark = '';
        }
        if ($username !== '') $result[$username] = $remark;
    }
    ksort($result);
    return $result;
}

function cxSharedCacheFile(string $key): string {
    return sys_get_temp_dir() . '/cx_cache_' . md5($key) . '.json';
}

function cxSharedLastGoodFile(string $key): string {
    return sys_get_temp_dir() . '/cx_lastgood_' . md5($key) . '.json';
}

function cxSharedKey(string $date): string {
    global $API1_ACCOUNTS_FILE;
    $authorized = cxBuildAuthorizedAccounts($API1_ACCOUNTS_FILE);
    return 'cx_v2_' . $date . '_' . md5(json_encode($authorized, JSON_UNESCAPED_UNICODE));
}

// 从 cx.php 的全量缓存里抽出指定账号的那一行;返回 null 表示未命中
function cxSharedItemFor(string $username, string $date, int $ttl): ?array {
    $key = cxSharedKey($date);
    $file = cxSharedCacheFile($key);
    if (!is_file($file)) return null;
    $data = json_decode((string)@file_get_contents($file), true);
    if (!is_array($data)) return null;
    $ts = (int)($data['_ts'] ?? 0);
    if ((time() - $ts) > $ttl) return null;
    $payload = $data['payload'] ?? null;
    if (!is_array($payload)) return null;

    $rows = [];
    if (is_array($payload['batchItems'] ?? null) && !empty($payload['batchItems'])) {
        $rows = $payload['batchItems'];
    } elseif (is_array($payload['items'] ?? null)) {
        $rows = $payload['items'];
    }
    foreach ($rows as $row) {
        if (!is_array($row)) continue;
        if ((string)($row['username'] ?? '') === $username) {
            return [
                'item' => $row,
                'fetched_at' => (int)($payload['fetchTime'] ?? $ts),
                'cache_age' => time() - (int)($payload['fetchTime'] ?? $ts),
            ];
        }
    }
    return null;
}

// 上游异常时,也试试 cx.php 的 last-good 全量快照
function cxSharedLastGoodItemFor(string $username, string $date): ?array {
    $key = cxSharedKey($date);
    $file = cxSharedLastGoodFile($key);
    if (!is_file($file)) return null;
    $data = json_decode((string)@file_get_contents($file), true);
    if (!is_array($data)) return null;
    $payload = $data['payload'] ?? null;
    if (!is_array($payload)) return null;

    $rows = [];
    if (is_array($payload['batchItems'] ?? null) && !empty($payload['batchItems'])) {
        $rows = $payload['batchItems'];
    } elseif (is_array($payload['items'] ?? null)) {
        $rows = $payload['items'];
    }
    foreach ($rows as $row) {
        if (!is_array($row)) continue;
        if ((string)($row['username'] ?? '') === $username) {
            return [
                'item' => $row,
                'fetched_at' => (int)($payload['fetchTime'] ?? $data['_ts'] ?? 0),
            ];
        }
    }
    return null;
}

function cxGetToken(): string {
    global $CX_API_BASE, $CX_USERNAME, $CX_PASSWORD;
    if (!empty($_SESSION['pq_cx_token']) && (time() - (int)($_SESSION['pq_cx_token_ts'] ?? 0)) < 3500) {
        return (string)$_SESSION['pq_cx_token'];
    }
    $loginRes = cxHttpPost($CX_API_BASE . '/user/login', [
        'username' => $CX_USERNAME,
        'password' => $CX_PASSWORD,
    ]);
    $token = '';
    if ($loginRes && (($loginRes['code'] ?? '') === '200' || (int)($loginRes['code'] ?? 0) === 200)) {
        $token = (string)($loginRes['token'] ?? $loginRes['data']['token'] ?? $loginRes['data']['accessToken'] ?? '');
    }
    if ($token !== '') {
        $_SESSION['pq_cx_token'] = $token;
        $_SESSION['pq_cx_token_ts'] = time();
    }
    return $token;
}

function fetchUpstreamSettleForAccount(string $username, string $date): array {
    global $CX_API_BASE, $CX_CACHE_TTL;
    $startTime = $date . ' 00:00:00';
    $endTime = $date . ' 23:59:59';
    $cacheKey = 'settle_' . $username . '_' . $date;
    $staleCache = cxCacheRead($cacheKey);
    $cached = cxCacheGet($cacheKey, $CX_CACHE_TTL);
    if (is_array($cached)) {
        $cached['source'] = $cached['source'] ?? 'local_cache';
        $cached['cached'] = true;
        return $cached;
    }

    // 优先用 cx.php 的全量缓存 —— 后台任意一次刷新都覆盖到所有用户
    $shared = cxSharedItemFor($username, $date, $CX_CACHE_TTL);
    if ($shared !== null) {
        $payload = [
            'ok' => true,
            'item' => $shared['item'],
            'fetched_at' => (int)$shared['fetched_at'],
            'source' => 'cx_shared',
        ];
        cxCacheSet($cacheKey, $payload);
        cxLastGoodSet($cacheKey, $payload);
        return $payload;
    }

    $lastGood = cxLastGoodGet($cacheKey);
    if ($lastGood === null && is_array($staleCache)) {
        $lastGood = $staleCache;
    }
    // 本地没 last-good,再试 cx.php 的全量 last-good
    if ($lastGood === null) {
        $sharedLg = cxSharedLastGoodItemFor($username, $date);
        if ($sharedLg !== null) {
            $lastGood = ['item' => $sharedLg['item'], 'fetched_at' => (int)$sharedLg['fetched_at']];
        }
    }

    $token = cxGetToken();
    if ($token === '') {
        if ($lastGood) return ['ok' => true, 'item' => $lastGood['item'] ?? null, 'fetched_at' => (int)($lastGood['fetched_at'] ?? 0), 'stale' => true, 'source' => 'last_good', 'msg' => '上游登录失败，使用最近一次缓存数据'];
        return ['ok' => false, 'msg' => '上游登录失败', 'item' => null, 'fetched_at' => 0, 'source' => 'upstream_error'];
    }
    $authHeaders = ['Authorization: Bearer ' . $token, 'token: ' . $token];
    $res = cxHttpPost($CX_API_BASE . '/user/settle/view', [
        'pageNum' => 1,
        'pageSize' => 50,
        'userList' => [$username],
        'startTime' => $startTime,
        'endTime' => $endTime,
    ], $authHeaders);
    if (!$res) {
        if ($lastGood) return ['ok' => true, 'item' => $lastGood['item'] ?? null, 'fetched_at' => (int)($lastGood['fetched_at'] ?? 0), 'stale' => true, 'source' => 'last_good', 'msg' => '查询接口无响应，使用最近一次缓存数据'];
        return ['ok' => false, 'msg' => '查询接口无响应', 'item' => null, 'fetched_at' => 0, 'source' => 'upstream_error'];
    }
    if (($res['code'] ?? '') === '200' || (int)($res['code'] ?? 0) === 200) {
        $items = $res['data']['items'] ?? [];
        $item = null;
        foreach ($items as $row) {
            if (is_array($row) && (string)($row['username'] ?? '') === $username) {
                $item = $row;
                break;
            }
        }

        // 上游成功但本次返回是空/全 0：尝试用 last-good 顶上，避免界面被刷成 0
        $hasData = is_array($item) && (
            (int)($item['takeCount'] ?? 0) +
            (int)($item['completeCount'] ?? 0) +
            (int)($item['checkSuccessCount'] ?? 0) +
            (int)($item['checkFailCount'] ?? 0)
        ) > 0;
        if (!$hasData && $lastGood && is_array($lastGood['item'] ?? null)) {
            $payload = ['ok' => true, 'item' => $lastGood['item'], 'fetched_at' => (int)($lastGood['fetched_at'] ?? 0), 'stale' => true, 'source' => 'last_good', 'msg' => '上游本次无数据，使用最近一次缓存'];
            cxCacheSet($cacheKey, $payload);
            return $payload;
        }

        $payload = ['ok' => true, 'item' => $item, 'fetched_at' => time(), 'source' => 'upstream'];
        cxCacheSet($cacheKey, $payload);
        cxLastGoodSet($cacheKey, $payload);
        return $payload;
    }
    if ((string)($res['code'] ?? '') === '401') {
        $_SESSION['pq_cx_token'] = '';
    }
    if ($lastGood) {
        return ['ok' => true, 'item' => $lastGood['item'] ?? null, 'fetched_at' => (int)($lastGood['fetched_at'] ?? 0), 'stale' => true, 'source' => 'last_good', 'msg' => (string)($res['msg'] ?? '查询失败') . '，使用最近一次缓存数据'];
    }
    $msg = (string)($res['msg'] ?? $res['message'] ?? '查询失败');
    return ['ok' => false, 'msg' => $msg, 'item' => null, 'fetched_at' => 0, 'source' => 'upstream_error'];
}

function recentDateList(int $days = 3, string $endDate = ''): array {
    $endTs = $endDate !== '' ? strtotime($endDate . ' 00:00:00') : strtotime(date('Y-m-d') . ' 00:00:00');
    if (!$endTs) $endTs = strtotime(date('Y-m-d') . ' 00:00:00');
    $dates = [];
    for ($i = $days - 1; $i >= 0; $i--) {
        $dates[] = date('Y-m-d', strtotime("-{$i} days", $endTs));
    }
    return $dates;
}

function buildSubmitStatsForDate(string $account, array $access, string $date = ''): array {
    $date = $date !== '' ? $date : date('Y-m-d');
    $upstream = fetchUpstreamSettleForAccount($account, $date);

    $item = is_array($upstream['item'] ?? null) ? $upstream['item'] : null;
    $take = (int)($item['takeCount'] ?? 0);
    $complete = (int)($item['completeCount'] ?? 0);
    $success = (int)($item['checkSuccessCount'] ?? 0);
    $fail = (int)($item['checkFailCount'] ?? 0);

    // 用本地日志中的最新一条作为 last_seen（与原行为保持一致）
    $stats = readDayStats($date);
    $lastSeen = '';
    foreach ($stats as $info) {
        if (!is_array($info) || !rowBelongsToAccount($info, $account, $access)) continue;
        $cur = (string)($info['last_seen'] ?? '');
        if ($cur !== '' && strcmp($cur, $lastSeen) > 0) $lastSeen = $cur;
    }

    return [
        'date' => $date,
        'take' => $take,
        'complete' => $complete,
        'total' => $take,            // 兼容旧字段：total = 领取数
        'success' => $success,
        'fail' => $fail,
        'success_rate' => $complete > 0 ? round($success * 100 / $complete, 1) : 0,
        'complete_rate' => $take > 0 ? round($complete * 100 / $take, 1) : 0,
        'last_seen' => $lastSeen,
        'fetched_at' => (int)($upstream['fetched_at'] ?? 0),
        'stale' => !empty($upstream['stale']),
        'ok' => !empty($upstream['ok']),
        'source' => (string)($upstream['source'] ?? ''),
        'upstream_msg' => !empty($upstream['msg']) ? (string)$upstream['msg'] : '',
    ];
}

function buildSubmitStats(string $account, array $access, string $date = ''): array {
    $dates = $date !== '' ? [$date] : recentDateList(3);
    $take = 0;
    $complete = 0;
    $success = 0;
    $fail = 0;
    $lastSeen = '';
    $fetchedAt = 0;
    $stale = false;
    $hasError = false;
    $hasCache = false;
    $messages = [];
    $daily = [];
    $todayStats = null;

    foreach ($dates as $day) {
        $stats = buildSubmitStatsForDate($account, $access, $day);
        $take += (int)($stats['take'] ?? 0);
        $complete += (int)($stats['complete'] ?? 0);
        $success += (int)($stats['success'] ?? 0);
        $fail += (int)($stats['fail'] ?? 0);

        $curSeen = (string)($stats['last_seen'] ?? '');
        if ($curSeen !== '' && strcmp($curSeen, $lastSeen) > 0) $lastSeen = $curSeen;

        $fetchedAt = max($fetchedAt, (int)($stats['fetched_at'] ?? 0));
        if (!empty($stats['stale'])) $stale = true;
        if (empty($stats['ok'])) $hasError = true;
        if (in_array((string)($stats['source'] ?? ''), ['local_cache', 'cx_shared', 'last_good'], true)) $hasCache = true;
        $msg = trim((string)($stats['upstream_msg'] ?? ''));
        if ($msg !== '' && !in_array($msg, $messages, true)) $messages[] = $msg;

        $daily[] = [
            'date' => $day,
            'take' => (int)($stats['take'] ?? 0),
            'complete' => (int)($stats['complete'] ?? 0),
            'success' => (int)($stats['success'] ?? 0),
            'fail' => (int)($stats['fail'] ?? 0),
            'complete_rate' => (float)($stats['complete_rate'] ?? 0),
            'success_rate' => (float)($stats['success_rate'] ?? 0),
            'last_seen' => (string)($stats['last_seen'] ?? ''),
            'fetched_at' => (int)($stats['fetched_at'] ?? 0),
            'stale' => !empty($stats['stale']),
            'ok' => !empty($stats['ok']),
            'source' => (string)($stats['source'] ?? ''),
            'upstream_msg' => $msg,
        ];
        if ($day === date('Y-m-d')) {
            $todayStats = end($daily);
        }
    }

    $startDate = reset($dates) ?: date('Y-m-d');
    $endDate = end($dates) ?: $startDate;
    $dateText = count($dates) > 1 ? ($startDate . ' 至 ' . $endDate) : $endDate;

    return [
        'date' => $dateText,
        'days' => $dates,
        'daily' => $daily,
        'today' => $todayStats ?: (end($daily) ?: []),
        'take' => $take,
        'complete' => $complete,
        'total' => $take,
        'success' => $success,
        'fail' => $fail,
        'success_rate' => $complete > 0 ? round($success * 100 / $complete, 1) : 0,
        'complete_rate' => $take > 0 ? round($complete * 100 / $take, 1) : 0,
        'last_seen' => $lastSeen,
        'fetched_at' => $fetchedAt,
        'stale' => $stale,
        'has_error' => $hasError,
        'has_cache' => $hasCache,
        'upstream_msg' => implode('；', array_slice($messages, 0, 3)),
    ];
}

function buildQueryData(string $account): array {
    $access = getAccountAccess($account);
    if (!$access['allowed']) {
        return ['ok' => false, 'msg' => '账号不在白名单，无法查询'];
    }
    return [
        'ok' => true,
        'account' => $account,
        'remark' => $access['remark'],
        'api_scope' => [
            'api1' => $access['api1'],
            'api2' => $access['api2'],
        ],
        'stats' => buildSubmitStats($account, $access),
        'cache_ttl' => $GLOBALS['CX_CACHE_TTL'],
        'front_refresh_ms' => $GLOBALS['FRONT_REFRESH_MS'],
        'server_time' => date('Y-m-d H:i:s'),
    ];
}

$act = (string)($_GET['act'] ?? '');

// 登录：只校验白名单 + 限频，发 token，不返回任何业务数据
if ($act === 'login') {
    $account = trim((string)($_GET['account'] ?? ''));
    if ($account === '') jsonResp(['ok' => false, 'msg' => '请输入授权账号']);

    $ip = pqClientIp();
    if (!pqRateAllow('login:' . $ip . ':' . $account, $RL_LOGIN_WINDOW, $RL_LOGIN_MAX)) {
        jsonResp(['ok' => false, 'msg' => '尝试次数过多，请稍后再试']);
    }

    $access = getAccountAccess($account);
    if (empty($access['allowed'])) {
        jsonResp(['ok' => false, 'msg' => '账号不在白名单，无法查询']);
    }

    jsonResp([
        'ok' => true,
        'account' => $account,
        'remark' => $access['remark'],
        'token' => pqIssueToken($account, $TOKEN_TTL),
        'token_expires_in' => $TOKEN_TTL,
        'cache_ttl' => $GLOBALS['CX_CACHE_TTL'],
        'front_refresh_ms' => $GLOBALS['FRONT_REFRESH_MS'],
    ]);
}

// 查询：必须带有效 token；签名错误/缺失一律拒绝，绝不返回业务数据
if ($act === 'query') {
    $account = trim((string)($_GET['account'] ?? ''));
    $token   = trim((string)($_GET['t'] ?? ''));
    if ($account === '' || $token === '') {
        jsonResp(['ok' => false, 'msg' => '会话已过期，请重新登录', 'need_relogin' => true]);
    }

    $ip = pqClientIp();
    if (!pqVerifyToken($account, $token)) {
        // 签名失败计入登录窗口，防猜签名
        pqRateAllow('login:' . $ip . ':' . $account, $RL_LOGIN_WINDOW, $RL_LOGIN_MAX);
        jsonResp(['ok' => false, 'msg' => '会话已过期，请重新登录', 'need_relogin' => true]);
    }
    if (!pqRateAllow('q:' . $account, $RL_QUERY_WINDOW, $RL_QUERY_MAX)) {
        jsonResp(['ok' => false, 'msg' => '请求过于频繁，请稍后再试']);
    }

    $resp = buildQueryData($account);
    if (!empty($resp['ok'])) {
        // 临到 token 过期时下发新 token，前端无感续期
        $resp['token'] = pqIssueToken($account, $TOKEN_TTL);
        $resp['token_expires_in'] = $TOKEN_TTL;
    }
    jsonResp($resp);
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ajie公共查询</title>
<style>
:root{--primary:#6366f1;--primary-dark:#4f46e5;--info:#7c3aed;--success:#10b981;--danger:#ef4444;--warning:#f59e0b;--ink:#111827;--muted:#64748b;--soft:#f8fafc;--line:#e2e8f0;--card:#fff;--shadow:0 18px 45px rgba(15,23,42,.12);--font:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",Arial,sans-serif;--bg-image:url('1777990939581269311.png');--bg-tint:linear-gradient(120deg,rgba(238,242,255,.24),rgba(240,253,250,.18));--card-bg:rgba(255,255,255,.88);--card-border:rgba(226,232,240,.82);--topbar-bg:linear-gradient(135deg,rgba(255,255,255,.84),rgba(248,250,252,.62));--topbar-border:rgba(255,255,255,.68);--brand-color:#0f172a;--stat-value-color:#0f172a;--log-border:#f1f5f9;--log-text:#334155;--code-bg:#f1f5f9;--code-border:#e2e8f0;--code-color:#0f172a;--upload-bg:#fff;--upload-border:#cbd5e1}
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;font-family:var(--font);color:var(--ink);background:var(--bg-tint),var(--bg-image) center/cover fixed no-repeat;font-size:14px;transition:background-color .35s ease}
body[data-theme="dark"]{--ink:#e6edf6;--muted:#9aa6ba;--line:rgba(148,163,184,.18);--shadow:0 18px 45px rgba(0,0,0,.45);--bg-tint:linear-gradient(135deg,rgba(15,23,42,.62),rgba(30,41,59,.55)),linear-gradient(180deg,rgba(15,23,42,.32),rgba(2,6,23,.45));--card-bg:rgba(20,28,46,.78);--card-border:rgba(148,163,184,.22);--topbar-bg:linear-gradient(135deg,rgba(20,28,46,.78),rgba(15,23,42,.62));--topbar-border:rgba(148,163,184,.22);--brand-color:#f2f5f8;--stat-value-color:#f2f5f8;--log-border:rgba(148,163,184,.14);--log-text:#cbd5e1;--code-bg:rgba(148,163,184,.14);--code-border:rgba(148,163,184,.22);--code-color:#e6edf6;--upload-bg:rgba(15,23,42,.7);--upload-border:rgba(148,163,184,.22)}
body[data-theme="ocean"]{--ink:#edf6ff;--muted:#b8cde3;--line:rgba(125,211,252,.2);--shadow:0 18px 45px rgba(6,17,29,.4);--bg-tint:linear-gradient(135deg,rgba(8,47,73,.55),rgba(30,64,175,.42)),linear-gradient(180deg,rgba(2,6,23,.18),rgba(30,58,138,.32));--card-bg:rgba(14,34,56,.72);--card-border:rgba(125,211,252,.24);--topbar-bg:linear-gradient(135deg,rgba(14,34,56,.78),rgba(9,26,45,.62));--topbar-border:rgba(125,211,252,.24);--brand-color:#edf6ff;--stat-value-color:#edf6ff;--log-border:rgba(125,211,252,.16);--log-text:#cfe1f5;--code-bg:rgba(125,211,252,.14);--code-border:rgba(125,211,252,.24);--code-color:#edf6ff;--upload-bg:rgba(6,17,29,.65);--upload-border:rgba(125,211,252,.24)}
body[data-theme="graphite"]{--ink:#f1f5f9;--muted:#b1bac8;--line:rgba(203,213,225,.16);--shadow:0 18px 45px rgba(0,0,0,.4);--bg-tint:linear-gradient(135deg,rgba(30,41,59,.55),rgba(51,65,85,.45)),linear-gradient(180deg,rgba(15,23,42,.22),rgba(2,6,23,.36));--card-bg:rgba(26,31,39,.78);--card-border:rgba(203,213,225,.18);--topbar-bg:linear-gradient(135deg,rgba(32,38,49,.78),rgba(21,26,34,.62));--topbar-border:rgba(203,213,225,.2);--brand-color:#f1f5f9;--stat-value-color:#f1f5f9;--log-border:rgba(203,213,225,.12);--log-text:#cbd5e1;--code-bg:rgba(203,213,225,.12);--code-border:rgba(203,213,225,.2);--code-color:#f1f5f9;--upload-bg:rgba(13,17,23,.7);--upload-border:rgba(203,213,225,.2)}
body[data-theme="cream"]{--ink:#3f2d10;--muted:#7a5b2a;--line:rgba(245,158,11,.22);--shadow:0 18px 45px rgba(180,120,30,.2);--bg-tint:linear-gradient(135deg,rgba(254,243,199,.55),rgba(254,215,170,.45)),linear-gradient(180deg,rgba(255,251,235,.28),rgba(253,224,71,.18));--card-bg:rgba(255,251,235,.86);--card-border:rgba(245,158,11,.22);--topbar-bg:linear-gradient(135deg,rgba(255,251,235,.92),rgba(254,243,199,.78));--topbar-border:rgba(245,158,11,.26);--brand-color:#3f2d10;--stat-value-color:#3f2d10;--log-border:rgba(245,158,11,.18);--log-text:#5a4316;--code-bg:rgba(254,243,199,.78);--code-border:rgba(245,158,11,.22);--code-color:#3f2d10;--upload-bg:rgba(255,251,235,.95);--upload-border:rgba(245,158,11,.22)}
body[data-theme="rose"]{--ink:#3f1d2e;--muted:#8a3a5e;--line:rgba(244,114,182,.22);--shadow:0 18px 45px rgba(190,80,140,.2);--bg-tint:linear-gradient(135deg,rgba(255,228,230,.55),rgba(252,231,243,.48)),linear-gradient(180deg,rgba(254,205,211,.32),rgba(253,164,175,.22));--card-bg:rgba(255,241,242,.88);--card-border:rgba(244,114,182,.22);--topbar-bg:linear-gradient(135deg,rgba(255,241,242,.92),rgba(252,231,243,.78));--topbar-border:rgba(244,114,182,.26);--brand-color:#3f1d2e;--stat-value-color:#3f1d2e;--log-border:rgba(244,114,182,.18);--log-text:#6a3252;--code-bg:rgba(252,231,243,.78);--code-border:rgba(244,114,182,.22);--code-color:#3f1d2e;--upload-bg:rgba(255,241,242,.95);--upload-border:rgba(244,114,182,.22)}
.hidden{display:none!important}
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0a0a0a url('bj.jpeg') center/cover no-repeat fixed;position:relative;overflow:hidden}
.login-wrap::before{content:'';position:absolute;inset:0;background:rgba(0,0,0,.48)}
.login-box{background:rgba(18,18,18,.92);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border-radius:20px;padding:48px 40px;width:min(400px,calc(100vw - 36px));box-shadow:0 25px 60px rgba(0,0,0,.5),0 0 0 1px rgba(180,150,80,.15),inset 0 1px 0 rgba(180,150,80,.08);position:relative;z-index:1;animation:loginIn .6s cubic-bezier(.16,1,.3,1)}
@keyframes loginIn{0%{opacity:0;transform:translateY(30px) scale(.96)}100%{opacity:1;transform:translateY(0) scale(1)}}
.login-box h1{font-size:24px;text-align:center;margin-bottom:6px;color:#e8e0d0;font-weight:700;letter-spacing:0}
.login-box p{text-align:center;color:#8a7e6e;margin-bottom:32px;font-size:14px;font-weight:400}
.login-box input{width:100%;height:48px;border:1px solid rgba(180,150,80,.2);border-radius:10px;padding:0 16px;font-size:15px;margin-bottom:16px;transition:all .25s;background:rgba(255,255,255,.06);font-family:var(--font);color:#e8e0d0}
.login-box input:focus{outline:none;border-color:rgba(180,150,80,.5);box-shadow:0 0 0 4px rgba(180,150,80,.1);background:rgba(255,255,255,.08)}
.login-box input::placeholder{color:#6a6050}
.login-box button{width:100%;height:48px;background:linear-gradient(135deg,#b4964f 0%,#8a7030 50%,#c4a660 100%);color:#fff;border:none;border-radius:10px;font-size:16px;font-weight:600;cursor:pointer;transition:all .25s;font-family:var(--font);box-shadow:0 4px 14px rgba(180,150,80,.3);text-shadow:0 1px 2px rgba(0,0,0,.2)}
.login-box button:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(180,150,80,.4)}
.login-error{min-height:20px;margin-top:12px;text-align:center;color:#fca5a5;font-size:13px}
.app{min-height:100vh;padding:28px;background:linear-gradient(180deg,rgba(255,255,255,.02),rgba(248,250,252,.08))}
.shell{max-width:1180px;margin:0 auto}
.topbar{display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:18px;margin-bottom:22px;padding:18px;border:1px solid var(--topbar-border);background:var(--topbar-bg);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border-radius:20px;box-shadow:var(--shadow)}
.brand-block{display:contents}
.brand-mark{width:46px;height:46px;border-radius:14px;background:rgba(255,255,255,.78);box-shadow:0 12px 26px rgba(79,70,229,.2);display:flex;align-items:center;justify-content:center;overflow:hidden;flex:0 0 auto;border:1px solid rgba(255,255,255,.75)}
.brand-mark img{width:100%;height:100%;object-fit:cover;display:block}
.brand-copy{min-width:0;text-align:center;justify-self:center}
.brand-title{font-size:24px;font-weight:850;letter-spacing:0;color:var(--brand-color);line-height:1.1}
.brand-sub{margin-top:8px;color:var(--muted);font-size:13px;display:flex;align-items:center;justify-content:center;gap:8px;flex-wrap:wrap}
.account-chip{display:inline-flex;align-items:center;min-height:28px;border-radius:999px;background:#f8fafc;border:1px solid #e2e8f0;color:#0f172a;padding:0 11px;font-weight:800}
.account-chip span{font-weight:700;color:#64748b}
.top-actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap;justify-content:flex-end}
.status-stack{display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:flex-end}
.button-stack{display:flex;align-items:center;gap:8px}
.pill{height:34px;display:inline-flex;align-items:center;border-radius:999px;padding:0 13px;background:rgba(238,242,255,.9);color:#4338ca;font-weight:800;font-size:12px;border:1px solid #c7d2fe;white-space:nowrap}
.pill-soft{background:rgba(240,253,250,.9);color:#047857;border-color:#99f6e4}
.btn{height:38px;border:0;border-radius:11px;padding:0 17px;font-family:var(--font);font-weight:800;cursor:pointer;transition:.2s;white-space:nowrap}
.btn-primary{background:linear-gradient(135deg,var(--primary),var(--primary-dark));color:#fff;box-shadow:0 10px 22px rgba(99,102,241,.26)}
.btn-default{background:rgba(255,255,255,.86);color:#334155;border:1px solid var(--line)}
.btn:hover{transform:translateY(-1px);box-shadow:0 12px 26px rgba(15,23,42,.1)}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:18px}
.stat{background:var(--card-bg);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);border:1px solid var(--card-border);border-radius:16px;padding:20px;box-shadow:0 10px 26px rgba(15,23,42,.06);position:relative;overflow:hidden}
.stat::before{content:'';position:absolute;left:0;right:0;top:0;height:3px;background:linear-gradient(90deg,var(--primary),var(--success))}
.stat .label{font-size:12px;color:var(--muted);font-weight:700;margin-bottom:10px}
.stat .value{font-size:30px;font-weight:850;color:var(--stat-value-color);letter-spacing:0}
.stat .hint{margin-top:6px;color:var(--muted);font-size:12px}
.layout{display:grid;grid-template-columns:1.35fr 1fr;gap:16px;margin-bottom:18px}
.card{background:var(--card-bg);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);border:1px solid var(--card-border);border-radius:18px;box-shadow:0 10px 26px rgba(15,23,42,.06);padding:22px 22px 24px;position:relative;overflow:hidden}
.card-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:18px}
.card-head h2{font-size:15px;letter-spacing:0;color:var(--brand-color)}
.card-note{font-size:12px;color:var(--muted)}
.rings{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.ring-box{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:14px 8px;border-radius:14px;background:linear-gradient(160deg,rgba(99,102,241,.06),rgba(16,185,129,.04));border:1px dashed var(--card-border)}
body[data-theme="dark"] .ring-box,body[data-theme="ocean"] .ring-box,body[data-theme="graphite"] .ring-box{background:linear-gradient(160deg,rgba(148,163,184,.08),rgba(99,102,241,.05))}
body[data-theme="cream"] .ring-box{background:linear-gradient(160deg,rgba(245,158,11,.1),rgba(254,215,170,.18))}
body[data-theme="rose"] .ring-box{background:linear-gradient(160deg,rgba(244,114,182,.1),rgba(252,231,243,.22))}
.ring{position:relative;width:148px;height:148px;display:flex;align-items:center;justify-content:center}
.ring svg{transform:rotate(-90deg);width:100%;height:100%}
.ring .track{stroke:rgba(148,163,184,.25);fill:none;stroke-width:12}
.ring .bar{fill:none;stroke-width:12;stroke-linecap:round;transition:stroke-dashoffset .8s cubic-bezier(.16,1,.3,1)}
.ring .bar.bar-complete{stroke:url(#gradComplete)}
.ring .bar.bar-success{stroke:url(#gradSuccess)}
.ring-label{position:absolute;text-align:center;display:flex;flex-direction:column;align-items:center;line-height:1.1}
.ring-label .pct{font-size:30px;font-weight:850;color:var(--stat-value-color);letter-spacing:0}
.ring-label .pct small{font-size:14px;font-weight:700;margin-left:1px;color:var(--muted)}
.ring-label .name{margin-top:4px;font-size:12px;color:var(--muted);font-weight:700}
.ring-foot{margin-top:10px;font-size:12px;color:var(--muted);font-weight:700}
.ring-foot b{color:var(--stat-value-color);font-weight:850}
.info-list{display:flex;flex-direction:column;gap:10px}
.info-row{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 14px;border-radius:12px;background:rgba(255,255,255,.45);border:1px solid var(--card-border)}
body[data-theme="dark"] .info-row,body[data-theme="ocean"] .info-row,body[data-theme="graphite"] .info-row{background:rgba(15,23,42,.35)}
body[data-theme="cream"] .info-row{background:rgba(255,251,235,.65)}
body[data-theme="rose"] .info-row{background:rgba(255,241,242,.6)}
.info-row .k{color:var(--muted);font-size:12px;font-weight:700}
.info-row .v{color:var(--stat-value-color);font-size:13px;font-weight:850;text-align:right;word-break:break-all}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:middle}
.dot-ok{background:#10b981;box-shadow:0 0 0 3px rgba(16,185,129,.18)}
.dot-warn{background:#f59e0b;box-shadow:0 0 0 3px rgba(245,158,11,.18)}
.foot-tip{margin-top:12px;font-size:12px;color:var(--muted);text-align:center}
.daily-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.daily-item{border:1px solid var(--card-border);background:rgba(255,255,255,.42);border-radius:14px;padding:16px;min-width:0}
body[data-theme="dark"] .daily-item,body[data-theme="ocean"] .daily-item,body[data-theme="graphite"] .daily-item{background:rgba(15,23,42,.32)}
body[data-theme="cream"] .daily-item{background:rgba(255,251,235,.62)}
body[data-theme="rose"] .daily-item{background:rgba(255,241,242,.58)}
.daily-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px}
.daily-date{font-size:14px;font-weight:850;color:var(--brand-color)}
.daily-status{font-size:12px;font-weight:850;color:#047857;background:rgba(240,253,250,.9);border:1px solid #99f6e4;border-radius:999px;padding:4px 9px;white-space:nowrap}
.daily-status.warn{color:#92400e;background:rgba(254,243,199,.9);border-color:#fbbf24}
.daily-metrics{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
.daily-metric{border-radius:12px;background:rgba(248,250,252,.62);border:1px solid var(--card-border);padding:10px}
body[data-theme="dark"] .daily-metric,body[data-theme="ocean"] .daily-metric,body[data-theme="graphite"] .daily-metric{background:rgba(2,6,23,.22)}
.daily-metric .mk{font-size:11px;color:var(--muted);font-weight:750;margin-bottom:5px}
.daily-metric .mv{font-size:20px;color:var(--stat-value-color);font-weight:850}
.daily-foot{margin-top:12px;color:var(--muted);font-size:12px;line-height:1.7;min-height:34px}
.theme-switch{display:inline-flex;align-items:center;gap:4px;padding:4px;border:1px solid var(--card-border);border-radius:999px;background:var(--card-bg)}
.theme-btn{min-width:44px;height:30px;padding:0 10px;border:0;border-radius:999px;background:transparent;color:var(--muted);font-family:var(--font);font-size:12px;font-weight:800;cursor:pointer;transition:.18s ease}
.theme-btn:hover{color:var(--ink)}
.theme-btn.active{background:linear-gradient(135deg,var(--primary),var(--primary-dark));color:#fff;box-shadow:0 6px 14px rgba(99,102,241,.25)}
@media(max-width:900px){.app{padding:16px}.topbar{grid-template-columns:auto 1fr;align-items:center}.top-actions{grid-column:1 / -1;width:100%;justify-content:space-between}.grid{grid-template-columns:repeat(2,1fr)}.layout{grid-template-columns:1fr}.daily-grid{grid-template-columns:1fr}}
@media(max-width:680px){.brand-mark{width:40px;height:40px;border-radius:12px;font-size:18px}.brand-copy{text-align:left;justify-self:start}.brand-sub{justify-content:flex-start}.top-actions,.status-stack,.button-stack{width:100%;justify-content:flex-start}.button-stack .btn{flex:1}.theme-switch{width:100%;justify-content:space-between;flex-wrap:wrap}.theme-btn{flex:1 1 56px}.rings{grid-template-columns:1fr}}
@media(max-width:560px){.grid{grid-template-columns:1fr}.login-box{padding:40px 26px}.brand-title{font-size:21px}.stat .value{font-size:26px}.ring{width:130px;height:130px}.ring-label .pct{font-size:26px}}
</style>
</head>
<body>
<div class="login-wrap" id="loginPage">
    <div class="login-box">
        <h1>Ajie查询</h1>
        <p>输入授权账号查看自己的提交情况</p>
        <input id="accountInput" autocomplete="username" placeholder="请输入白名单账号">
        <button id="loginBtn" onclick="login()">进入查询</button>
        <div class="login-error" id="loginError"></div>
    </div>
</div>

<main class="app hidden" id="queryPage">
    <div class="shell">
        <section class="topbar">
            <div class="brand-block">
                <div class="brand-mark"><img src="1777990327149137925.png" alt=""></div>
                <div class="brand-copy">
                    <div class="brand-title">Ajie查询</div>
                    <div class="brand-sub"><span class="account-chip"><span>账号</span>&nbsp;<b id="accountName"></b></span><span id="accountRemark"></span></div>
                </div>
            </div>
            <div class="top-actions">
                <div class="status-stack">
                    <span class="pill">授权账号</span>
                    <span class="pill pill-soft" id="refreshText" title="无感刷新倒计时">下次刷新 -- s</span>
                </div>
                <div class="theme-switch" aria-label="主题切换">
                    <button class="theme-btn" type="button" data-theme-value="default" title="默认">默认</button>
                    <button class="theme-btn" type="button" data-theme-value="dark" title="暗夜">暗夜</button>
                    <button class="theme-btn" type="button" data-theme-value="ocean" title="深海">深海</button>
                    <button class="theme-btn" type="button" data-theme-value="graphite" title="钛灰">钛灰</button>
                    <button class="theme-btn" type="button" data-theme-value="cream" title="米黄">米黄</button>
                    <button class="theme-btn" type="button" data-theme-value="rose" title="玫瑰">玫瑰</button>
                </div>
                <div class="button-stack">
                    <button class="btn btn-default" onclick="logout()">退出</button>
                </div>
            </div>
        </section>

        <section class="grid">
            <div class="stat"><div class="label">今日领取</div><div class="value" id="takeCount">0</div><div class="hint" id="dateText">今日</div></div>
            <div class="stat"><div class="label">今日完成</div><div class="value" id="completeCount">0</div><div class="hint" id="completeRateText">完成率 0%</div></div>
            <div class="stat"><div class="label">今日通过</div><div class="value" id="successCount">0</div><div class="hint" id="rateCount">通过率 0%</div></div>
            <div class="stat"><div class="label">今日失败</div><div class="value" id="failCount">0</div><div class="hint" id="lastSeenText">暂无最近提交</div></div>
        </section>

        <svg width="0" height="0" style="position:absolute" aria-hidden="true">
            <defs>
                <linearGradient id="gradComplete" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" stop-color="#6366f1"/>
                    <stop offset="100%" stop-color="#22d3ee"/>
                </linearGradient>
                <linearGradient id="gradSuccess" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" stop-color="#10b981"/>
                    <stop offset="100%" stop-color="#84cc16"/>
                </linearGradient>
            </defs>
        </svg>

        <section class="layout">
            <div class="card">
                <div class="card-head">
                    <h2>今日完成情况</h2>
                    <span class="card-note" id="ringNote">完成率 / 通过率</span>
                </div>
                <div class="rings">
                    <div class="ring-box">
                        <div class="ring">
                            <svg viewBox="0 0 120 120">
                                <circle class="track" cx="60" cy="60" r="52"></circle>
                                <circle class="bar bar-complete" id="ringComplete" cx="60" cy="60" r="52" stroke-dasharray="326.7" stroke-dashoffset="326.7"></circle>
                            </svg>
                            <div class="ring-label">
                                <div class="pct"><span id="completePct">0</span><small>%</small></div>
                                <div class="name">完成率</div>
                            </div>
                        </div>
                        <div class="ring-foot">完成 <b id="ringComplete2">0</b> / 领取 <b id="ringTake">0</b></div>
                    </div>
                    <div class="ring-box">
                        <div class="ring">
                            <svg viewBox="0 0 120 120">
                                <circle class="track" cx="60" cy="60" r="52"></circle>
                                <circle class="bar bar-success" id="ringSuccess" cx="60" cy="60" r="52" stroke-dasharray="326.7" stroke-dashoffset="326.7"></circle>
                            </svg>
                            <div class="ring-label">
                                <div class="pct"><span id="successPct">0</span><small>%</small></div>
                                <div class="name">通过率</div>
                            </div>
                        </div>
                        <div class="ring-foot">通过 <b id="ringSuccess2">0</b> / 完成 <b id="ringComplete3">0</b></div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-head">
                    <h2>查询信息</h2>
                    <span class="card-note" id="upstreamBadge"><span class="dot dot-ok"></span>实时</span>
                </div>
                <div class="info-list">
                    <div class="info-row"><span class="k">查询账号</span><span class="v" id="infoAccount">--</span></div>
                    <div class="info-row"><span class="k">账号备注</span><span class="v" id="infoRemark">--</span></div>
                    <div class="info-row"><span class="k">统计日期</span><span class="v" id="infoDate">--</span></div>
                    <div class="info-row"><span class="k">最近提交</span><span class="v" id="infoLastSeen">暂无</span></div>
                    <div class="info-row"><span class="k">服务器时间</span><span class="v" id="infoServerTime">--</span></div>
                    <div class="info-row"><span class="k">数据状态</span><span class="v" id="infoUpstream">实时数据</span></div>
                </div>
                <div class="foot-tip" id="foot-tip">数据每 120 秒自动更新一次</div>
            </div>
        </section>

        <section class="card">
            <div class="card-head">
                <h2>近三天每日明细</h2>
                <span class="card-note">每天领取 / 完成 / 通过 / 失败</span>
            </div>
            <div class="daily-grid" id="dailyGrid"></div>
        </section>

    </div>
</main>

<script>
const BASE = location.pathname;
const FRONT_REFRESH_MS = <?= (int)$FRONT_REFRESH_MS ?>;
const FRONT_REFRESH_SEC = Math.max(1, Math.round(FRONT_REFRESH_MS / 1000));
let account = localStorage.getItem('public_query_account') || '';
let queryToken = '';       // 内存级签名 token，刷新页面会用账号重换
let timer = null;          // 倒计时（每秒一次）
let countdown = FRONT_REFRESH_SEC;
let isLoading = false;

const THEME_KEY = 'public_query_theme';
const ALLOWED_THEMES = new Set(['default','dark','ocean','graphite','cream','rose']);
function applyTheme(theme){
    const value = ALLOWED_THEMES.has(theme) ? theme : 'default';
    if(value === 'default') document.body.removeAttribute('data-theme');
    else document.body.setAttribute('data-theme', value);
    localStorage.setItem(THEME_KEY, value);
    document.querySelectorAll('[data-theme-value]').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.themeValue === value);
    });
}
function bindThemeSwitch(){
    document.querySelectorAll('[data-theme-value]').forEach(btn => {
        btn.addEventListener('click', () => applyTheme(btn.dataset.themeValue || 'default'));
    });
    applyTheme(localStorage.getItem(THEME_KEY) || 'default');
}
bindThemeSwitch();

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function setLoginError(msg){document.getElementById('loginError').textContent=msg||'';}

function logout(){
    account='';
    queryToken='';
    localStorage.removeItem('public_query_account');
    if(timer){clearInterval(timer);timer=null;}
    document.getElementById('queryPage').classList.add('hidden');
    document.getElementById('loginPage').classList.remove('hidden');
    document.getElementById('accountInput').focus();
}

function showQuery(){
    document.getElementById('loginPage').classList.add('hidden');
    document.getElementById('queryPage').classList.remove('hidden');
    if(timer)clearInterval(timer);
    countdown = FRONT_REFRESH_SEC;
    renderCountdown();
    timer = setInterval(tickCountdown, 1000);
}

function renderCountdown(){
    const el = document.getElementById('refreshText');
    if(!el) return;
    if(isLoading){ el.textContent = '刷新中…'; return; }
    el.textContent = '下次刷新 ' + countdown + ' s';
}

function tickCountdown(){
    if(isLoading) return;
    countdown--;
    if(countdown <= 0){
        loadData();
        countdown = FRONT_REFRESH_SEC;
    }
    renderCountdown();
}

async function doLogin(name){
    const r=await fetch(BASE+'?act=login&account='+encodeURIComponent(name),{cache:'no-store'});
    const data = await r.json();
    if(data && data.ok && data.token){ queryToken = data.token; }
    return data;
}

async function fetchData(name){
    if(!queryToken){
        return { ok:false, need_relogin:true, msg:'缺少会话凭证' };
    }
    const url = BASE+'?act=query&account='+encodeURIComponent(name)+'&t='+encodeURIComponent(queryToken);
    const r=await fetch(url,{cache:'no-store'});
    const data = await r.json();
    if(data && typeof data === 'object' && data.token){ queryToken = data.token; }
    return data;
}

async function login(){
    const input=document.getElementById('accountInput');
    const name=(input.value||'').trim();
    if(!name){setLoginError('请输入白名单账号');return;}
    document.getElementById('loginBtn').disabled=true;
    setLoginError('正在校验账号...');
    try{
        const lg = await doLogin(name);
        if(!lg.ok){ setLoginError(lg.msg||'账号无法查询'); return; }
        account = name;
        localStorage.setItem('public_query_account', account);
        // 立即拉一次数据
        const data = await fetchData(account);
        if(!data.ok){ setLoginError(data.msg||'查询失败，请稍后重试'); return; }
        // 把 login 拿到的 remark 兜底塞给 render 用（query 接口也会自带）
        if(!data.remark && lg.remark) data.remark = lg.remark;
        if(!data.account) data.account = account;
        showQuery();
        render(data);
    }catch(e){
        setLoginError('查询失败，请稍后重试');
    }finally{
        document.getElementById('loginBtn').disabled=false;
    }
}

async function loadData(){
    if(!account)return;
    isLoading = true;
    renderCountdown();
    try{
        let data = await fetchData(account);
        if(!data.ok && data.need_relogin){
            // 自动续期：重新登录拿新 token，再查一次
            queryToken = '';
            const lg = await doLogin(account);
            if(!lg.ok){
                if(lg.msg && lg.msg.indexOf('白名单')!==-1){ logout(); setLoginError(lg.msg); }
                return;
            }
            data = await fetchData(account);
        }
        if(!data.ok){
            if(data.msg && data.msg.indexOf('白名单')!==-1){
                logout();
                setLoginError(data.msg);
            }
            return;
        }
        render(data);
    }catch(e){
        // 静默：保持当前数据不变，等下个周期再试
    }finally{
        isLoading = false;
        countdown = FRONT_REFRESH_SEC;
        renderCountdown();
    }
}

function render(data){
    const s=data.stats||{};
    const today=s.today||{};
    const take=Number(today.take||0), complete=Number(today.complete||0);
    const success=Number(today.success||0), fail=Number(today.fail||0);
    const completeRate=Number(today.complete_rate||0);
    const successRate=Number(today.success_rate||0);

    document.getElementById('accountName').textContent=data.account||account;
    document.getElementById('accountRemark').textContent=data.remark?' / '+data.remark:'';
    document.getElementById('takeCount').textContent=take;
    document.getElementById('completeCount').textContent=complete;
    document.getElementById('successCount').textContent=success;
    document.getElementById('failCount').textContent=fail;
    document.getElementById('rateCount').textContent='通过率 '+successRate+'%';
    document.getElementById('completeRateText').textContent='完成率 '+completeRate+'%';
    document.getElementById('dateText').textContent=today.date||'今日';
    document.getElementById('lastSeenText').textContent=today.last_seen?'最近 '+today.last_seen:'暂无最近提交';

    setRing('ringComplete', completeRate);
    setRing('ringSuccess', successRate);
    document.getElementById('completePct').textContent=completeRate;
    document.getElementById('successPct').textContent=successRate;
    document.getElementById('ringTake').textContent=take;
    document.getElementById('ringComplete2').textContent=complete;
    document.getElementById('ringComplete3').textContent=complete;
    document.getElementById('ringSuccess2').textContent=success;
    renderDaily(s.daily||[]);

    document.getElementById('infoAccount').textContent=data.account||account;
    document.getElementById('infoRemark').textContent=data.remark||'--';
    document.getElementById('infoDate').textContent=s.date||'--';
    document.getElementById('infoLastSeen').textContent=s.last_seen||'暂无';
    document.getElementById('infoServerTime').textContent=data.server_time||'--';

    const stale=!!s.stale;
    const hasError=!!s.has_error;
    const hasCache=!!s.has_cache;
    const upstreamMsg=s.upstream_msg||'';
    const badge=document.getElementById('upstreamBadge');
    const upText=document.getElementById('infoUpstream');
    if((stale||hasCache) && !hasError){
        badge.innerHTML='<span class="dot dot-warn"></span>缓存';
        upText.textContent=upstreamMsg||'部分日期使用缓存数据';
    }else if(stale||hasCache){
        badge.innerHTML='<span class="dot dot-warn"></span>缓存';
        upText.textContent=upstreamMsg||'上游限速，已显示缓存数据';
    }else if(hasError){
        badge.innerHTML='<span class="dot dot-warn"></span>异常';
        upText.textContent=upstreamMsg||'部分日期请求上游失败';
    }else{
        badge.innerHTML='<span class="dot dot-ok"></span>实时';
        upText.textContent=upstreamMsg||'实时数据';
    }
    document.getElementById('foot-tip').textContent='数据每 '+FRONT_REFRESH_SEC+' 秒自动更新一次';
}

function sourceText(row){
    const source=String(row.source||'');
    if(row.stale) return '缓存';
    if(source==='local_cache') return '缓存';
    if(source==='cx_shared') return '共享缓存';
    if(source==='upstream') return '实时';
    if(!row.ok) return '异常';
    return '实时';
}

function renderDaily(rows){
    const el=document.getElementById('dailyGrid');
    if(!el) return;
    if(!Array.isArray(rows)||!rows.length){
        el.innerHTML='<div class="daily-item"><div class="daily-foot">暂无每日明细</div></div>';
        return;
    }
    el.innerHTML=rows.map(row=>{
        const take=Number(row.take||0);
        const complete=Number(row.complete||0);
        const success=Number(row.success||0);
        const fail=Number(row.fail||0);
        const completeRate=Number(row.complete_rate||0);
        const successRate=Number(row.success_rate||0);
        const status=sourceText(row);
        const warn=(row.stale||!row.ok||status==='缓存'||status==='异常');
        const msg=row.upstream_msg?`<div>${esc(row.upstream_msg)}</div>`:'';
        const last=row.last_seen?`最近 ${esc(row.last_seen)}`:'暂无最近提交';
        return `<div class="daily-item">
            <div class="daily-head">
                <div class="daily-date">${esc(row.date||'--')}</div>
                <div class="daily-status ${warn?'warn':''}">${esc(status)}</div>
            </div>
            <div class="daily-metrics">
                <div class="daily-metric"><div class="mk">领取</div><div class="mv">${take}</div></div>
                <div class="daily-metric"><div class="mk">完成</div><div class="mv">${complete}</div></div>
                <div class="daily-metric"><div class="mk">通过</div><div class="mv">${success}</div></div>
                <div class="daily-metric"><div class="mk">失败</div><div class="mv">${fail}</div></div>
            </div>
            <div class="daily-foot">
                <div>完成率 ${completeRate}% ｜ 通过率 ${successRate}%</div>
                <div>${last}</div>
                ${msg}
            </div>
        </div>`;
    }).join('');
}

function setRing(id, pct){
    const el=document.getElementById(id);
    if(!el) return;
    const r=52, c=2*Math.PI*r;
    const v=Math.max(0, Math.min(100, Number(pct)||0));
    el.setAttribute('stroke-dasharray', c.toFixed(2));
    el.setAttribute('stroke-dashoffset', (c*(1-v/100)).toFixed(2));
}

document.getElementById('accountInput').addEventListener('keydown',e=>{if(e.key==='Enter')login();});
if(account){
    document.getElementById('accountInput').value=account;
    (async () => {
        try{
            const lg = await doLogin(account);
            if(!lg.ok){
                localStorage.removeItem('public_query_account'); account='';
                document.getElementById('accountInput').focus();
                if(lg.msg) setLoginError(lg.msg);
                return;
            }
            const data = await fetchData(account);
            if(data.ok){
                if(!data.remark && lg.remark) data.remark = lg.remark;
                if(!data.account) data.account = account;
                showQuery(); render(data);
            }else{
                localStorage.removeItem('public_query_account'); account='';
                document.getElementById('accountInput').focus();
            }
        }catch(e){
            document.getElementById('accountInput').focus();
        }
    })();
}else{
    document.getElementById('accountInput').focus();
}
</script>
</body>
</html>
