package com.codex.ajieandroid;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import org.json.JSONObject;

public class MainActivity extends Activity {
    private TextView log, status;
    private EditText serverUrl, username, password, webLoginUrl;

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(28, 28, 28, 28);
        sv.addView(root);

        TextView title = new TextView(this);
        title.setText("Ajie \u5b89\u5353\u4efb\u52a1\u52a9\u624b");
        title.setTextSize(22);
        title.setTextColor(Color.rgb(10, 39, 111));
        root.addView(title);

        TextView tip = new TextView(this);
        tip.setText("\u5148\u5728 App \u91cc\u767b\u5f55\u4efb\u52a1\u8d26\u6237\u5e76\u4fdd\u5b58\u672c\u5730 token\uff0c\u518d\u7528 WebView \u767b\u5f55\u867e\u76ae\u4f1a\u8bdd\u3002\u4e4b\u540e\u670d\u52a1\u5668\u53ea\u8d1f\u8d23\u63a7\u5236\u8fd9\u53f0 App \u542f\u52a8\u3001\u6682\u505c\u3001\u540c\u6b65\u548c\u5faa\u73af\u3002");
        tip.setPadding(0, 8, 0, 16);
        root.addView(tip);

        status = new TextView(this);
        status.setText("\u72b6\u6001\uff1a\u672a\u540c\u6b65\u4f1a\u8bdd");
        status.setPadding(0, 0, 0, 12);
        root.addView(status);

        TextView deviceInfo = new TextView(this);
        deviceInfo.setText("\u8bbe\u5907\u6807\u8bc6\uff1a" + DeviceInfo.fingerprintKey(this) + "\nAndroid ID\uff1a" + DeviceInfo.androidId(this));
        deviceInfo.setTextIsSelectable(true);
        deviceInfo.setPadding(0, 0, 0, 12);
        root.addView(deviceInfo);

        serverUrl = makeEdit("\u670d\u52a1\u5668\u63a5\u53e3\u5730\u5740", SessionStore.get(this, "server_url", SessionStore.DEFAULT_SERVER));
        String savedUsername = SessionStore.username(this);
        username = makeEdit("\u4efb\u52a1\u8d26\u6237\uff08\u624b\u52a8\u586b\u5199\uff0c\u4e0d\u518d\u5360\u7528\u8bbe\u5907\u6807\u8bc6\uff09", savedUsername);
        password = makeEdit("\u4efb\u52a1\u5bc6\u7801\uff08\u4ec5\u4fdd\u5b58\u5728\u672c\u673a\uff09", SessionStore.get(this, "password", ""));
        password.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        webLoginUrl = makeEdit("WebView \u767b\u5f55\u9875", SessionStore.get(this, "web_login_url", SessionStore.DEFAULT_WEB_LOGIN));
        log = new TextView(this);
        log.setTextIsSelectable(true);
        log.setPadding(0, 14, 0, 0);

        root.addView(serverUrl);
        root.addView(username);
        root.addView(password);
        root.addView(webLoginUrl);
        root.addView(button("\u4fdd\u5b58\u8bbe\u7f6e", v -> save()));
        root.addView(button("\u767b\u5f55\u4efb\u52a1\u8d26\u6237", v -> loginTaskAccount()));
        root.addView(button("\u6253\u5f00 WebView \u767b\u5f55\u867e\u76ae", v -> startActivity(new Intent(this, WebLoginActivity.class))));
        root.addView(button("\u542f\u52a8\u6258\u7ba1\u6a21\u5f0f", v -> startWorker(TaskWorkerService.ACTION_START)));
        root.addView(button("\u7acb\u5373\u6267\u884c\u4e00\u6b21", v -> startWorker(TaskWorkerService.ACTION_RUN_ONCE)));
        root.addView(button("\u505c\u6b62\u672c\u673a\u540e\u53f0\u670d\u52a1", v -> startService(new Intent(this, TaskWorkerService.class).setAction(TaskWorkerService.ACTION_STOP))));
        root.addView(log);
        setContentView(sv);
    }

    @Override protected void onResume() {
        super.onResume();
        refreshStatus();
    }

    private EditText makeEdit(String hint, String value) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setText(value);
        e.setSingleLine(false);
        e.setMinLines(1);
        return e;
    }

    private Button button(String text, View.OnClickListener l) {
        Button b = new Button(this);
        b.setText(text);
        b.setAllCaps(false);
        b.setOnClickListener(l);
        return b;
    }

    private void save() {
        SessionStore.put(this, "server_url", serverUrl.getText().toString().trim());
        SessionStore.put(this, "username", username.getText().toString().trim());
        SessionStore.put(this, "password", password.getText().toString());
        SessionStore.put(this, "web_login_url", webLoginUrl.getText().toString().trim());
        append("\u8bbe\u7f6e\u5df2\u4fdd\u5b58");
        refreshStatus();
    }

    private void loginTaskAccount() {
        save();
        try {
            String u = username.getText().toString().trim();
            String p = password.getText().toString();
            if (u.isEmpty() || p.isEmpty()) { append("\u8bf7\u5148\u586b\u5199\u4efb\u52a1\u8d26\u6237\u548c\u4efb\u52a1\u5bc6\u7801"); return; }
            JSONObject body = new JSONObject();
            body.put("act", "api1_login");
            body.put("username", u);
            body.put("password", p);
            new ApiClient(this).postAsync(body, (json, err) -> runOnUiThread(() -> {
                if (err != null) { append("\u4efb\u52a1\u8d26\u6237\u767b\u5f55\u5931\u8d25\uff1a" + err.getMessage()); return; }
                String token = json.optJSONObject("data") == null ? json.optString("token", "") : json.optJSONObject("data").optString("token", "");
                if (token.isEmpty()) token = json.optString("auth_token", "");
                if (!token.isEmpty()) SessionStore.put(this, "token", token);
                append(ApiClient.ok(json) ? "\u4efb\u52a1\u8d26\u6237\u767b\u5f55\u6210\u529f" : "\u767b\u5f55\u8fd4\u56de\uff1a" + ApiClient.compact(json));
                refreshStatus();
            }));
        } catch (Exception e) { append("\u4efb\u52a1\u8d26\u6237\u767b\u5f55\u5f02\u5e38\uff1a" + e.getMessage()); }
    }

    private void startWorker(String action) {
        save();
        Intent it = new Intent(this, TaskWorkerService.class).setAction(action);
        if (Build.VERSION.SDK_INT >= 26 && !TaskWorkerService.ACTION_RUN_ONCE.equals(action)) startForegroundService(it); else startService(it);
        append(TaskWorkerService.ACTION_RUN_ONCE.equals(action) ? "\u5df2\u8bf7\u6c42\u7acb\u5373\u6267\u884c\u4e00\u6b21": "\u6258\u7ba1\u6a21\u5f0f\u5df2\u542f\u52a8\uff0c\u7b49\u5f85\u670d\u52a1\u5668\u63a7\u5236\u547d\u4ee4");
        refreshStatus();
    }

    private void refreshStatus() {
        String cookie = SessionStore.get(this, "web_cookie", "");
        String syncedAt = SessionStore.get(this, "session_synced_at", "");
        String lastCmd = SessionStore.get(this, "last_command", "-");
        String token = SessionStore.get(this, "token", "");
        String s = "\u72b6\u6001\uff1a" + (token.isEmpty() ? "\u4efb\u52a1\u8d26\u6237\u672a\u767b\u5f55" : "\u4efb\u52a1\u8d26\u6237\u5df2\u767b\u5f55")
            + " / " + (cookie.isEmpty() ? "\u672a\u767b\u5f55\u867e\u76ae / \u672a\u4fdd\u5b58\u4f1a\u8bdd" : "\u5df2\u4fdd\u5b58\u867e\u76ae\u4f1a\u8bdd")
            + " / \u6700\u8fd1\u540c\u6b65\uff1a" + (syncedAt.isEmpty() ? "-" : syncedAt)
            + " / \u670d\u52a1\u5668\u547d\u4ee4\uff1a" + lastCmd;
        if (status != null) status.setText(s);
    }

    private void append(String s) { if (log != null) log.append(s + "\n"); }
}
