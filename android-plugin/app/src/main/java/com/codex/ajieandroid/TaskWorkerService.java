package com.codex.ajieandroid;

import android.app.Notification;
import android.app.Notification.Builder;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.webkit.CookieManager;
import org.json.JSONObject;

public class TaskWorkerService extends Service {
    public static final String ACTION_START = "start";
    public static final String ACTION_STOP = "stop";
    public static final String ACTION_RUN_ONCE = "run_once";
    private final Handler handler = new Handler(Looper.getMainLooper());
    private boolean running;
    private boolean busy;
    private int pollIntervalMs = 30000;
    private final Runnable loop = new Runnable() {
        @Override public void run() {
            if (!running) return;
            runCycle(false);
            handler.postDelayed(this, pollIntervalMs);
        }
    };

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent != null ? intent.getAction() : null;
        if (ACTION_STOP.equals(action)) { running = false; stopSelf(); return START_NOT_STICKY; }
        if (ACTION_RUN_ONCE.equals(action)) { runCycle(true); return START_NOT_STICKY; }
        if (!running) {
            running = true;
            startForeground(1, buildNotification("\u5df2\u542f\u52a8\uff0c\u7b49\u5f85\u670d\u52a1\u5668\u63a7\u5236"));
            handler.post(loop);
        }
        return START_STICKY;
    }

    private void runCycle(boolean forceOnce) {
        if (busy) return;
        busy = true;
        new Thread(() -> {
            try {
                syncSessionIfPossible();
                JSONObject poll = pollServer();
                String command = poll.optString("command", poll.optString("cmd", "run"));
                SessionStore.put(this, "last_command", command);
                JSONObject data = poll.optJSONObject("data");
                if (data != null) {
                    pollIntervalMs = Math.max(10, data.optInt("poll_interval_seconds", poll.optInt("poll_interval_seconds", 30))) * 1000;
                    command = data.optString("command", command);
                    SessionStore.put(this, "last_command", command);
                }
                if ("clear_session".equals(command)) { clearSession(); return; }
                if ("stop".equals(command)) { running = false; stopSelf(); return; }
                if (!forceOnce && "sync_session".equals(command)) return;
                if (!forceOnce && "pause".equals(command)) return;
                String cookie = currentCookie();
                if (cookie.isEmpty()) return;
                JSONObject take = takeTask();
                JSONObject task = extractTask(take);
                String taskUrl = task.optString("taskUrl", task.optString("url", ""));
                String taskId = task.optString("taskId", task.optString("task_id", task.optString("deal_id", "")));
                if (taskUrl.isEmpty()) return;
                submitTask(taskUrl, taskId, cookie);
            } catch (Exception ignored) {
            } finally {
                busy = false;
            }
        }, "ajie-managed-cycle").start();
    }

    private JSONObject pollServer() throws Exception {
        JSONObject body = new JSONObject();
        body.put("act", "android_device_poll");
        body.put("username", SessionStore.username(this));
        body.put("has_cookie", !currentCookie().isEmpty());
        body.put("has_task_token", !SessionStore.get(this, "token", "").isEmpty());
        return new ApiClient(this).post(body);
    }

    private void syncSessionIfPossible() throws Exception {
        String cookieUrl = SessionStore.get(this, "web_cookie_url", "");
        String cookie = currentCookie();
        if (cookie.isEmpty()) return;
        JSONObject body = new JSONObject();
        body.put("act", "android_session_sync");
        body.put("username", SessionStore.username(this));
        body.put("cookie", cookie);
        body.put("cookies", cookie);
        body.put("cookie_url", cookieUrl);
        body.put("cookie_host", hostOf(cookieUrl));
        body.put("user_agent", "Mozilla/5.0 (Linux; Android 15; Mobile) AppleWebKit/537.36 Chrome/150.0.0.0 Mobile Safari/537.36");
        JSONObject resp = new ApiClient(this).post(body);
        if (ApiClient.ok(resp)) SessionStore.put(this, "session_synced_at", String.valueOf(System.currentTimeMillis() / 1000));
    }

    private JSONObject takeTask() throws Exception {
        ensureTaskLogin();
        JSONObject body = new JSONObject();
        body.put("act", "api1_take");
        body.put("username", SessionStore.username(this));
        JSONObject resp = new ApiClient(this).post(body);
        String code = resp.optString("code", "");
        String msg = resp.optString("msg", resp.optString("error", ""));
        if ("401".equals(code) || msg.contains("login") || msg.contains("\u767b\u5f55")) {
            SessionStore.put(this, "token", "");
            ensureTaskLogin();
            resp = new ApiClient(this).post(body);
        }
        return resp;
    }

    private void ensureTaskLogin() throws Exception {
        if (!SessionStore.get(this, "token", "").isEmpty()) return;
        String username = SessionStore.username(this);
        String password = SessionStore.get(this, "password", "");
        if (username.isEmpty() || password.isEmpty()) return;
        JSONObject body = new JSONObject();
        body.put("act", "api1_login");
        body.put("username", username);
        body.put("password", password);
        JSONObject json = new ApiClient(this).post(body);
        String token = json.optJSONObject("data") == null ? json.optString("token", "") : json.optJSONObject("data").optString("token", "");
        if (token.isEmpty()) token = json.optString("auth_token", "");
        if (!token.isEmpty()) SessionStore.put(this, "token", token);
    }

    private void submitTask(String taskUrl, String taskId, String cookie) throws Exception {
        JSONObject body = new JSONObject();
        body.put("act", "android_session_fetch_submit");
        body.put("username", SessionStore.username(this));
        body.put("task_id", taskId);
        body.put("url", taskUrl);
        body.put("cookies", cookie);
        body.put("cookie_url", SessionStore.get(this, "web_cookie_url", ""));
        body.put("user_agent", "Mozilla/5.0 (Linux; Android 15; Mobile) AppleWebKit/537.36 Chrome/150.0.0.0 Mobile Safari/537.36");
        new ApiClient(this).post(body);
    }

    private JSONObject extractTask(JSONObject json) {
        JSONObject task = json.optJSONObject("task");
        JSONObject data = json.optJSONObject("data");
        if (task == null && data != null) task = data.optJSONObject("task");
        if (task == null && data != null && (data.has("taskUrl") || data.has("url"))) task = data;
        return task == null ? new JSONObject() : task;
    }

    private String currentCookie() {
        String url = SessionStore.get(this, "web_cookie_url", "");
        String saved = SessionStore.get(this, "web_cookie", "");
        boolean imported = SessionStore.getBool(this, "web_cookie_imported", false);
        if (!url.isEmpty()) {
            try {
                String live = CookieManager.getInstance().getCookie(url);
                if (live != null && !live.trim().isEmpty()) {
                    if (imported && saved.length() > live.length()) return saved;
                    SessionStore.put(this, "web_cookie", live);
                    return live;
                }
            } catch (Exception ignored) {}
        }
        return saved;
    }

    private void clearSession() {
        SessionStore.put(this, "web_cookie", "");
        SessionStore.put(this, "web_cookie_raw", "");
        SessionStore.put(this, "web_cookie_url", "");
        SessionStore.putBool(this, "web_cookie_imported", false);
        SessionStore.put(this, "session_synced_at", "");
        try { CookieManager.getInstance().removeAllCookies(null); CookieManager.getInstance().flush(); } catch (Exception ignored) {}
        try {
            JSONObject body = new JSONObject();
            body.put("act", "android_session_clear");
            body.put("username", SessionStore.username(this));
            new ApiClient(this).post(body);
        } catch (Exception ignored) {}
    }

    private String hostOf(String url) {
        try { return android.net.Uri.parse(url).getHost(); } catch (Exception e) { return ""; }
    }

    private Notification buildNotification(String text) {
        String ch = "ajie_plugin";
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26 && nm != null && nm.getNotificationChannel(ch) == null) {
            nm.createNotificationChannel(new NotificationChannel(ch, "Ajie \u5b89\u5353\u4efb\u52a1\u52a9\u624b", NotificationManager.IMPORTANCE_LOW));
        }
        Builder builder = Build.VERSION.SDK_INT >= 26 ? new Builder(this, ch) : new Builder(this);
        return builder.setContentTitle("Ajie \u5b89\u5353\u4efb\u52a1\u52a9\u624b")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .build();
    }

    @Override public IBinder onBind(Intent intent) { return null; }
    @Override public void onDestroy() { running = false; handler.removeCallbacksAndMessages(null); super.onDestroy(); }
}
