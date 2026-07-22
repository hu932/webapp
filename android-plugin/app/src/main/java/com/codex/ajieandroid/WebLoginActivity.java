package com.codex.ajieandroid;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.webkit.CookieManager;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.LinearLayout;
import android.widget.TextView;
import org.json.JSONObject;

public class WebLoginActivity extends Activity {
    private TextView status;
    private WebView webView;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private long lastSyncAt = 0;

    @SuppressLint("SetJavaScriptEnabled")
    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        status = new TextView(this);
        status.setText("\u8bf7\u5728\u4e0b\u65b9 WebView \u767b\u5f55\u867e\u76ae\u8d26\u53f7\uff0c\u767b\u5f55\u540e App \u4f1a\u81ea\u52a8\u4fdd\u5b58\u5e76\u540c\u6b65\u4f1a\u8bdd\u3002");
        status.setPadding(18, 18, 18, 18);
        webView = new WebView(this);
        root.addView(status, new LinearLayout.LayoutParams(-1, -2));
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

    private void captureAndSync(String url) {
        String host = "";
        try { host = Uri.parse(url).getHost(); } catch (Exception ignored) {}
        CookieManager cm = CookieManager.getInstance();
        String cookie = cm.getCookie(url);
        if (cookie == null || cookie.trim().isEmpty()) return;
        cm.flush();
        SessionStore.put(this, "web_cookie", cookie);
        SessionStore.put(this, "web_cookie_url", url);
        status.setText("Cookie \u5df2\u4fdd\u5b58\uff0c\u6b63\u5728\u540c\u6b65\u5230\u670d\u52a1\u5668\uff1a" + (host == null ? "" : host));
        long now = System.currentTimeMillis();
        if (now - lastSyncAt < 5000) return;
        lastSyncAt = now;
        syncSession(url, cookie, host == null ? "" : host);
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

    @Override protected void onDestroy() {
        if (webView != null) webView.destroy();
        super.onDestroy();
    }
}
