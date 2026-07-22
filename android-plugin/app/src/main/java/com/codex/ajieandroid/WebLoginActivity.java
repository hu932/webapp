package com.codex.ajieandroid;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.webkit.CookieManager;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import org.json.JSONObject;

public class WebLoginActivity extends Activity {
    private TextView status;
    private EditText cookieInput;
    private WebView webView;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private long lastSyncAt = 0;

    @SuppressLint("SetJavaScriptEnabled")
    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        status = new TextView(this);
        status.setText("\u8bf7\u5728\u4e0b\u65b9 WebView \u767b\u5f55\u867e\u76ae\u8d26\u53f7\uff0c\u4e5f\u53ef\u4ee5\u76f4\u63a5\u7c98\u8d34 CK \u7f6e\u5165\u767b\u5f55\u3002");
        status.setPadding(18, 18, 18, 10);
        cookieInput = new EditText(this);
        cookieInput.setHint("\u7c98\u8d34 CK\uff0c\u683c\u5f0f\uff1aa=b; c=d");
        cookieInput.setMinLines(2);
        cookieInput.setSingleLine(false);
        cookieInput.setText(SessionStore.get(this, "web_cookie", ""));

        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.addView(button("\u7f6e CK \u767b\u5f55", v -> setCookieLogin()), new LinearLayout.LayoutParams(0, -2, 1f));
        bar.addView(button("\u6e05\u9664 CK", v -> clearWebCookies()), new LinearLayout.LayoutParams(0, -2, 1f));

        webView = new WebView(this);
        root.addView(status, new LinearLayout.LayoutParams(-1, -2));
        root.addView(cookieInput, new LinearLayout.LayoutParams(-1, -2));
        root.addView(bar, new LinearLayout.LayoutParams(-1, -2));
        root.addView(webView, new LinearLayout.LayoutParams(-1, 0, 1f));
        setContentView(root);

        WebSettings s = webView.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setDatabaseEnabled(true);
        s.setUseWideViewPort(true);
        s.setLoadWithOverviewMode(true);
        CookieManager cm = CookieManager.getInstance();
        cm.setAcceptCookie(true);
        cm.setAcceptThirdPartyCookies(webView, true);

        webView.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) { return false; }
            @Override public void onPageFinished(WebView view, String url) { captureAndSync(url); }
        });
        webView.loadUrl(SessionStore.get(this, "web_login_url", SessionStore.DEFAULT_WEB_LOGIN));
    }

    private Button button(String text, View.OnClickListener l) {
        Button b = new Button(this);
        b.setText(text);
        b.setAllCaps(false);
        b.setOnClickListener(l);
        return b;
    }

    private void setCookieLogin() {
        String raw = cookieInput.getText().toString().trim();
        if (raw.isEmpty()) { status.setText("CK \u4e3a\u7a7a"); return; }
        String url = SessionStore.get(this, "web_login_url", SessionStore.DEFAULT_WEB_LOGIN);
        CookieManager cm = CookieManager.getInstance();
        cm.setAcceptCookie(true);
        cm.setAcceptThirdPartyCookies(webView, true);
        int count = 0;
        String normalized = raw.replace("Cookie:", "").replace("cookie:", "").replace('\n', ';').replace('\r', ';');
        String[] parts = normalized.split(";");
        for (String part : parts) {
            String item = part.trim();
            if (item.isEmpty() || !item.contains("=")) continue;
            String lower = item.toLowerCase();
            if (lower.startsWith("path=") || lower.startsWith("domain=") || lower.startsWith("expires=") || lower.startsWith("max-age=") || lower.equals("secure") || lower.equals("httponly") || lower.startsWith("samesite=")) continue;
            cm.setCookie(url, item + "; Path=/");
            count++;
        }
        cm.flush();
        SessionStore.put(this, "web_cookie", normalized);
        SessionStore.put(this, "web_cookie_url", url);
        status.setText("\u5df2\u7f6e\u5165 CK\uff1a" + count + " \u9879\uff0c\u6b63\u5728\u540c\u6b65\u670d\u52a1\u5668");
        syncSession(url, normalized, hostOf(url));
        webView.loadUrl(url);
    }

    private void clearWebCookies() {
        CookieManager cm = CookieManager.getInstance();
        cm.removeAllCookies(value -> handler.post(() -> {
            cm.flush();
            SessionStore.put(WebLoginActivity.this, "web_cookie", "");
            SessionStore.put(WebLoginActivity.this, "web_cookie_url", "");
            SessionStore.put(WebLoginActivity.this, "session_synced_at", "");
            cookieInput.setText("");
            notifyServerClearSession();
            status.setText("CK \u5df2\u6e05\u9664");
            webView.loadUrl(SessionStore.get(WebLoginActivity.this, "web_login_url", SessionStore.DEFAULT_WEB_LOGIN));
        }));
    }

    private void notifyServerClearSession() {
        try {
            JSONObject body = new JSONObject();
            body.put("act", "android_session_clear");
            body.put("username", SessionStore.username(this));
            new ApiClient(this).postAsync(body, (json, err) -> {});
        } catch (Exception ignored) {}
    }

    private void captureAndSync(String url) {
        String host = hostOf(url);
        CookieManager cm = CookieManager.getInstance();
        String cookie = cm.getCookie(url);
        if (cookie == null || cookie.trim().isEmpty()) return;
        cm.flush();
        SessionStore.put(this, "web_cookie", cookie);
        SessionStore.put(this, "web_cookie_url", url);
        cookieInput.setText(cookie);
        status.setText("Cookie \u5df2\u4fdd\u5b58\uff0c\u6b63\u5728\u540c\u6b65\u5230\u670d\u52a1\u5668\uff1a" + host);
        long now = System.currentTimeMillis();
        if (now - lastSyncAt < 5000) return;
        lastSyncAt = now;
        syncSession(url, cookie, host);
    }

    private void syncSession(String url, String cookie, String host) {
        try {
            JSONObject body = new JSONObject();
            body.put("act", "android_session_sync");
            body.put("username", SessionStore.username(this));
            body.put("cookie", cookie);
            body.put("cookies", cookie);
            body.put("cookie_url", url);
            body.put("cookie_host", host);
            body.put("user_agent", webView.getSettings().getUserAgentString());
            new ApiClient(this).postAsync(body, (json, err) -> handler.post(() -> {
                if (err != null) { status.setText("\u4f1a\u8bdd\u540c\u6b65\u5931\u8d25\uff1a" + err.getMessage()); return; }
                if (ApiClient.ok(json)) {
                    SessionStore.put(WebLoginActivity.this, "session_synced_at", String.valueOf(System.currentTimeMillis() / 1000));
                    status.setText("\u4f1a\u8bdd\u5df2\u540c\u6b65\u5230\u670d\u52a1\u5668\uff0c\u540e\u53f0\u6258\u7ba1\u5df2\u542f\u52a8\u3002");
                    Intent it = new Intent(WebLoginActivity.this, TaskWorkerService.class).setAction(TaskWorkerService.ACTION_START);
                    if (Build.VERSION.SDK_INT >= 26) startForegroundService(it); else startService(it);
                } else {
                    status.setText("\u4f1a\u8bdd\u540c\u6b65\u8fd4\u56de\uff1a" + ApiClient.compact(json));
                }
            }));
        } catch (Exception e) { status.setText("\u4f1a\u8bdd\u540c\u6b65\u5f02\u5e38\uff1a" + e.getMessage()); }
    }

    private String hostOf(String url) {
        try { String host = Uri.parse(url).getHost(); return host == null ? "" : host; }
        catch (Exception e) { return ""; }
    }

    @Override protected void onDestroy() {
        if (webView != null) webView.destroy();
        super.onDestroy();
    }
}
