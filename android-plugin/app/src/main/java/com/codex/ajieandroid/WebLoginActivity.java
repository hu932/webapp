package com.codex.ajieandroid;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.View;
import android.webkit.CookieManager;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.List;

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
        status.setText("\u8bf7\u5728\u4e0b\u65b9 WebView \u624b\u52a8\u767b\u5f55\u867e\u76ae\u8d26\u53f7\uff1b\u5982\u679c\u5df2\u6709\u5f88\u957f\u7684 CK\uff0c\u70b9\u51fb\u3010\u5bfc\u5165 CK \u767b\u5f55\u3011\u5f39\u7a97\u7c98\u8d34\uff0cApp \u4f1a\u81ea\u52a8\u89e3\u6790\u3001\u7f6e\u5165\u3001\u540c\u6b65\u670d\u52a1\u5668\u3002");
        status.setPadding(18, 18, 18, 10);

        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.addView(button("\u5bfc\u5165 CK \u767b\u5f55", v -> showCookieDialog()), new LinearLayout.LayoutParams(0, -2, 1f));
        bar.addView(button("\u6e05\u9664 CK", v -> clearWebCookies()), new LinearLayout.LayoutParams(0, -2, 1f));

        webView = new WebView(this);
        root.addView(status, new LinearLayout.LayoutParams(-1, -2));
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

    private void showCookieDialog() {
        EditText input = new EditText(this);
        input.setHint("Cookie: a=b; c=d\n\u4e5f\u652f\u6301\u591a\u884c Set-Cookie \u6216\u76f4\u63a5\u7c98\u8d34\u6574\u6bb5 CK");
        input.setText(SessionStore.get(this, "web_cookie", ""));
        input.setSingleLine(false);
        input.setMinLines(8);
        input.setMaxLines(16);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        input.setHorizontallyScrolling(false);
        input.setSelectAllOnFocus(false);
        input.setPadding(18, 8, 18, 8);

        ScrollView box = new ScrollView(this);
        int pad = 22;
        box.setPadding(pad, pad, pad, 0);
        box.addView(input, new ScrollView.LayoutParams(-1, -2));

        AlertDialog dialog = new AlertDialog.Builder(this)
            .setTitle("\u5bfc\u5165 / \u7f6e\u5165 CK")
            .setMessage("\u7c98\u8d34\u957f CK \u540e\u70b9\u51fb\u3010\u5bfc\u5165\u5e76\u767b\u5f55\u3011\uff0c\u4f1a\u81ea\u52a8\u53bb\u6389 Cookie:/Set-Cookie: \u524d\u7f00\u548c path/domain/expires \u7b49\u5c5e\u6027\u3002")
            .setView(box)
            .setNegativeButton("\u53d6\u6d88", null)
            .setPositiveButton("\u5bfc\u5165\u5e76\u767b\u5f55", null)
            .create();
        dialog.setOnShowListener(d -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String raw = input.getText().toString();
            if (raw.trim().isEmpty()) {
                input.setError("CK \u4e0d\u80fd\u4e3a\u7a7a");
                return;
            }
            dialog.dismiss();
            setCookieLogin(raw);
        }));
        dialog.show();
    }

    private void setCookieLogin(String raw) {
        List<String> items = parseCookieItems(raw);
        if (items.isEmpty()) { status.setText("CK \u89e3\u6790\u5931\u8d25\uff0c\u8bf7\u68c0\u67e5\u683c\u5f0f\uff1aa=b; c=d"); return; }
        String url = SessionStore.get(this, "web_login_url", SessionStore.DEFAULT_WEB_LOGIN);
        CookieManager cm = CookieManager.getInstance();
        cm.setAcceptCookie(true);
        cm.setAcceptThirdPartyCookies(webView, true);
        int count = 0;
        StringBuilder normalized = new StringBuilder();
        for (String item : items) {
            cm.setCookie(url, item + "; Path=/");
            if (normalized.length() > 0) normalized.append("; ");
            normalized.append(item);
            count++;
        }
        cm.flush();
        String cookie = normalized.toString();
        SessionStore.put(this, "web_cookie", cookie);
        SessionStore.put(this, "web_cookie_url", url);
        status.setText("\u5df2\u7f6e\u5165 CK\uff1a" + count + " \u9879\uff0c\u6b63\u5728\u540c\u6b65\u670d\u52a1\u5668");
        syncSession(url, cookie, hostOf(url));
        webView.loadUrl(url);
    }

    private List<String> parseCookieItems(String raw) {
        ArrayList<String> out = new ArrayList<>();
        String text = raw == null ? "" : raw.replace('\r', '\n').trim();
        StringBuilder cookieLines = new StringBuilder();
        String[] lines = text.split("\\n");
        for (String line : lines) {
            String t = line.trim();
            if (t.isEmpty()) continue;
            String lower = t.toLowerCase();
            if (lower.startsWith("set-cookie:")) {
                String one = t.substring(t.indexOf(':') + 1).trim();
                int semi = one.indexOf(';');
                if (semi > 0) one = one.substring(0, semi).trim();
                addCookieItem(out, one);
            } else if (lower.startsWith("cookie:")) {
                if (cookieLines.length() > 0) cookieLines.append(';');
                cookieLines.append(t.substring(t.indexOf(':') + 1).trim());
            } else if (t.contains("=") && (t.contains(";") || lines.length == 1)) {
                if (cookieLines.length() > 0) cookieLines.append(';');
                cookieLines.append(t);
            }
        }
        if (cookieLines.length() == 0 && text.contains("=")) cookieLines.append(text);
        String merged = cookieLines.toString().replace('\n', ';').replace('\t', ' ');
        for (String part : merged.split(";")) addCookieItem(out, part.trim());
        return out;
    }

    private void addCookieItem(List<String> out, String item) {
        item = item == null ? "" : item.trim();
        if (item.isEmpty() || !item.contains("=")) return;
        String lower = item.toLowerCase();
        if (lower.startsWith("path=") || lower.startsWith("domain=") || lower.startsWith("expires=") || lower.startsWith("max-age=") || lower.equals("secure") || lower.equals("httponly") || lower.startsWith("samesite=")) return;
        out.add(item);
    }

    private void clearWebCookies() {
        CookieManager cm = CookieManager.getInstance();
        cm.removeAllCookies(value -> handler.post(() -> {
            cm.flush();
            SessionStore.put(WebLoginActivity.this, "web_cookie", "");
            SessionStore.put(WebLoginActivity.this, "web_cookie_url", "");
            SessionStore.put(WebLoginActivity.this, "session_synced_at", "");
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
