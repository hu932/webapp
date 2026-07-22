package com.codex.ajieandroid;

import android.app.Activity;
import android.content.Intent;
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
    private TextView log;
    private EditText serverUrl, authKey, username, password, webLoginUrl;

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(24, 24, 24, 24);
        sv.addView(root);

        serverUrl = makeEdit("?????", SessionStore.get(this, "server_url", SessionStore.DEFAULT_SERVER));
        authKey = makeEdit("X-Auth-Key", SessionStore.get(this, "auth_key", "a1998510"));
        username = makeEdit("???", SessionStore.get(this, "username", ""));
        password = makeEdit("??", SessionStore.get(this, "password", ""));
        password.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        webLoginUrl = makeEdit("WebView ???", SessionStore.get(this, "web_login_url", SessionStore.DEFAULT_WEB_LOGIN));
        log = new TextView(this);
        log.setTextIsSelectable(true);

        root.addView(serverUrl); root.addView(authKey); root.addView(username); root.addView(password); root.addView(webLoginUrl);
        root.addView(button("????", v -> save()));
        root.addView(button("?? WebView ??", v -> startActivity(new Intent(this, WebLoginActivity.class))));
        root.addView(button("?????", v -> loginServer()));
        root.addView(button("???????", v -> takeOnce()));
        root.addView(button("??????", v -> {
            Intent it = new Intent(this, TaskWorkerService.class).setAction(TaskWorkerService.ACTION_START);
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(it); else startService(it);
        }));
        root.addView(button("??????", v -> startService(new Intent(this, TaskWorkerService.class).setAction(TaskWorkerService.ACTION_STOP))));
        root.addView(log);
        setContentView(sv);
    }

    private EditText makeEdit(String hint, String value) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setText(value);
        return e;
    }

    private Button button(String text, View.OnClickListener l) {
        Button b = new Button(this);
        b.setText(text);
        b.setOnClickListener(l);
        return b;
    }

    private void save() {
        SessionStore.put(this, "server_url", serverUrl.getText().toString().trim());
        SessionStore.put(this, "auth_key", authKey.getText().toString().trim());
        SessionStore.put(this, "username", username.getText().toString().trim());
        SessionStore.put(this, "password", password.getText().toString());
        SessionStore.put(this, "web_login_url", webLoginUrl.getText().toString().trim());
        append("???");
    }

    private void loginServer() {
        save();
        try {
            JSONObject body = new JSONObject();
            body.put("act", "api1_login");
            body.put("username", username.getText().toString().trim());
            body.put("password", password.getText().toString());
            new ApiClient(this).postAsync(body, (json, err) -> runOnUiThread(() -> {
                if (err != null) { append("????: " + err.getMessage()); return; }
                SessionStore.put(this, "token", json.optJSONObject("data") == null ? json.optString("token", "") : json.optJSONObject("data").optString("token", ""));
                append(json.toString());
            }));
        } catch (Exception e) { append("????: " + e.getMessage()); }
    }

    private void takeOnce() {
        save();
        try {
            JSONObject body = new JSONObject();
            body.put("act", "api1_take");
            body.put("username", username.getText().toString().trim());
            new ApiClient(this).postAsync(body, (takeJson, err) -> runOnUiThread(() -> {
                if (err != null) { append("?????: " + err.getMessage()); return; }
                append("???: " + takeJson.toString());
                JSONObject data = takeJson.optJSONObject("data");
                String taskUrl = data != null ? data.optString("taskUrl", data.optString("url", "")) : takeJson.optString("taskUrl", takeJson.optString("url", ""));
                String taskId = data != null ? data.optString("taskId", data.optString("task_id", "")) : takeJson.optString("taskId", takeJson.optString("task_id", ""));
                if (taskUrl.isEmpty()) { append("???? URL"); return; }
                submitViaServer(taskUrl, taskId);
            }));
        } catch (Exception e) { append("?????: " + e.getMessage()); }
    }

    private void submitViaServer(String taskUrl, String taskId) {
        try {
            JSONObject body = new JSONObject();
            body.put("act", "android_session_fetch_submit");
            body.put("username", username.getText().toString().trim());
            body.put("task_id", taskId);
            body.put("url", taskUrl);
            body.put("cookies", SessionStore.get(this, "web_cookie", ""));
            body.put("cookie_url", SessionStore.get(this, "web_cookie_url", ""));
            body.put("user_agent", "Mozilla/5.0 (Linux; Android 15; Mobile) AppleWebKit/537.36 Chrome/150.0.0.0 Mobile Safari/537.36");
            new ApiClient(this).postAsync(body, (json, err) -> runOnUiThread(() -> {
                if (err != null) { append("????: " + err.getMessage()); return; }
                append("????: " + json.toString());
            }));
        } catch (Exception e) { append("????: " + e.getMessage()); }
    }

    private void append(String s) { log.append(s + "\n"); }
}
