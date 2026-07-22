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
import org.json.JSONObject;

public class TaskWorkerService extends Service {
    public static final String ACTION_START = "start";
    public static final String ACTION_STOP = "stop";
    private final Handler handler = new Handler(Looper.getMainLooper());
    private boolean running;
    private final Runnable loop = new Runnable() {
        @Override public void run() {
            if (!running) return;
            tryLoop();
            handler.postDelayed(this, 30000);
        }
    };

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent != null ? intent.getAction() : null;
        if (ACTION_STOP.equals(action)) { stopSelf(); return START_NOT_STICKY; }
        if (!running) {
            running = true;
            startForeground(1, buildNotification("???"));
            handler.post(loop);
        }
        return START_STICKY;
    }

    private void tryLoop() {
        new Thread(() -> {
            try {
                JSONObject take = new JSONObject();
                take.put("act", "api1_take");
                take.put("username", SessionStore.get(this, "username", ""));
                JSONObject takeResp = new ApiClient(this).post(take);
                JSONObject data = takeResp.optJSONObject("data");
                String taskUrl = data != null ? data.optString("taskUrl", data.optString("url", "")) : "";
                String taskId = data != null ? data.optString("taskId", data.optString("task_id", "")) : "";
                String cookie = SessionStore.get(this, "web_cookie", "");
                if (taskUrl.isEmpty() || cookie.isEmpty()) return;
                JSONObject submit = new JSONObject();
                submit.put("act", "android_session_fetch_submit");
                submit.put("username", SessionStore.get(this, "username", ""));
                submit.put("task_id", taskId);
                submit.put("url", taskUrl);
                submit.put("cookies", cookie);
                submit.put("cookie_url", SessionStore.get(this, "web_cookie_url", ""));
                submit.put("user_agent", "Mozilla/5.0 (Linux; Android 15; Mobile) AppleWebKit/537.36 Chrome/150.0.0.0 Mobile Safari/537.36");
                new ApiClient(this).post(submit);
            } catch (Exception ignored) {}
        }, "ajie-loop").start();
    }

    private Notification buildNotification(String text) {
        String ch = "ajie_plugin";
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26 && nm != null && nm.getNotificationChannel(ch) == null) {
            nm.createNotificationChannel(new NotificationChannel(ch, "Ajie Plugin", NotificationManager.IMPORTANCE_LOW));
        }
        Builder builder = Build.VERSION.SDK_INT >= 26 ? new Builder(this, ch) : new Builder(this);
        return builder.setContentTitle("Ajie Android Plugin")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .build();
    }

    @Override public IBinder onBind(Intent intent) { return null; }
    @Override public void onDestroy() { running = false; handler.removeCallbacksAndMessages(null); super.onDestroy(); }
}
