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
import android.webkit.WebChromeClient;
import android.webkit.WebView.WebViewTransport;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import org.json.JSONArray;
import org.json.JSONObject;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

public class WebLoginActivity extends Activity {
    public static final String ENV_ANDROID = "android_chrome";
    public static final String ENV_IOS = "ios_safari";
    private TextView status;
    private WebView webView;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private long lastSyncAt = 0;

    private static class CookieSpec {
        String name = "";
        String value = "";
        String domain = "";
        String path = "/";
        String sameSite = "";
        String expiresText = "";
        long expirationSeconds = 0;
        boolean secure = true;
        boolean httpOnly = false;
    }

    @SuppressLint("SetJavaScriptEnabled")
    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        status = new TextView(this);
        status.setText(statusText());
        status.setPadding(18, 18, 18, 10);

        LinearLayout envBar = new LinearLayout(this);
        envBar.setOrientation(LinearLayout.HORIZONTAL);
        envBar.addView(button("\u5b89\u5353\u73af\u5883", v -> switchBrowserEnv(ENV_ANDROID)), new LinearLayout.LayoutParams(0, -2, 1f));
        envBar.addView(button("iOS \u73af\u5883", v -> switchBrowserEnv(ENV_IOS)), new LinearLayout.LayoutParams(0, -2, 1f));

        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.addView(button("\u5bfc\u5165 CK \u767b\u5f55", v -> showCookieDialog()), new LinearLayout.LayoutParams(0, -2, 1f));
        bar.addView(button("\u5237\u65b0", v -> reloadLoginPage()), new LinearLayout.LayoutParams(0, -2, 1f));
        bar.addView(button("\u6e05\u9664 CK", v -> clearWebCookies()), new LinearLayout.LayoutParams(0, -2, 1f));

        webView = new WebView(this);
        root.addView(status, new LinearLayout.LayoutParams(-1, -2));
        root.addView(envBar, new LinearLayout.LayoutParams(-1, -2));
        root.addView(bar, new LinearLayout.LayoutParams(-1, -2));
        root.addView(webView, new LinearLayout.LayoutParams(-1, 0, 1f));
        setContentView(root);

        configureWebView(webView);
        CookieManager cm = CookieManager.getInstance();
        cm.setAcceptCookie(true);
        cm.setAcceptThirdPartyCookies(webView, true);

        webView.setWebChromeClient(new WebChromeClient() {
            @Override public boolean onCreateWindow(WebView view, boolean isDialog, boolean isUserGesture, android.os.Message resultMsg) {
                WebView child = new WebView(WebLoginActivity.this);
                configureWebView(child);
                CookieManager.getInstance().setAcceptThirdPartyCookies(child, true);
                final AlertDialog[] popup = new AlertDialog[1];
                child.setWebViewClient(new WebViewClient() {
                    @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                        return false;
                    }
                    @Override public void onPageFinished(WebView view, String url) {
                        captureAndSync(url);
                    }
                });
                child.setWebChromeClient(new WebChromeClient() {
                    @Override public void onCloseWindow(WebView window) {
                        if (popup[0] != null && popup[0].isShowing()) popup[0].dismiss();
                        webView.reload();
                    }
                });
                popup[0] = new AlertDialog.Builder(WebLoginActivity.this)
                    .setTitle("\u8d26\u53f7\u6388\u6743\u767b\u5f55")
                    .setView(child)
                    .setNegativeButton("\u5173\u95ed", (d, which) -> webView.reload())
                    .create();
                popup[0].setOnDismissListener(d -> {
                    try { child.destroy(); } catch (Exception ignored) {}
                });
                WebViewTransport transport = (WebViewTransport) resultMsg.obj;
                transport.setWebView(child);
                resultMsg.sendToTarget();
                popup[0].show();
                if (popup[0].getWindow() != null) popup[0].getWindow().setLayout(-1, -1);
                return true;
            }
        });

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

    private void reloadLoginPage() {
        String url = SessionStore.get(this, "web_login_url", SessionStore.DEFAULT_WEB_LOGIN);
        status.setText("\u5df2\u4f7f\u7528 " + envLabel(this) + " UA \u5237\u65b0\u767b\u5f55\u9875\uff0c\u6b63\u5728\u91cd\u65b0\u52a0\u8f7d\u3002");
        webView.loadUrl(url);
    }

    private void configureWebView(WebView view) {
        WebSettings s = view.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setDatabaseEnabled(true);
        s.setUseWideViewPort(true);
        s.setLoadWithOverviewMode(true);
        s.setJavaScriptCanOpenWindowsAutomatically(true);
        s.setSupportMultipleWindows(true);
        s.setUserAgentString(selectedUserAgent(this));
        if (Build.VERSION.SDK_INT >= 21) s.setMixedContentMode(WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE);
    }

    private String statusText() {
        return "\u8bf7\u5728\u4e0b\u65b9 WebView \u624b\u52a8\u767b\u5f55\u867e\u76ae\u8d26\u53f7\uff1b\u5f53\u524d\u6d4f\u89c8\u5668\u73af\u5883\uff1a" + envLabel(this) + "\u3002CK \u6765\u81ea\u54ea\u79cd\u6d4f\u89c8\u5668\uff0c\u5c31\u5148\u5207\u5230\u5bf9\u5e94\u73af\u5883\u518d\u5bfc\u5165\u3002";
    }

    private void switchBrowserEnv(String env) {
        SessionStore.put(this, "browser_env", ENV_IOS.equals(env) ? ENV_IOS : ENV_ANDROID);
        if (webView != null) {
            webView.getSettings().setUserAgentString(selectedUserAgent(this));
            status.setText("\u5df2\u5207\u6362\u5230 " + envLabel(this) + "\uff0c\u5df2\u91cd\u65b0\u52a0\u8f7d\u767b\u5f55\u9875\u3002\u5982\u679c CK \u6765\u81ea\u53e6\u4e00\u79cd\u73af\u5883\uff0c\u8bf7\u5148\u6e05\u9664 CK \u518d\u5bfc\u5165\u3002");
            webView.loadUrl(SessionStore.get(this, "web_login_url", SessionStore.DEFAULT_WEB_LOGIN));
        }
    }

    public static String androidChromeUserAgent() {
        return "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36";
    }

    public static String iosSafariUserAgent() {
        return "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";
    }

    public static String selectedUserAgent(android.content.Context c) {
        String env = SessionStore.get(c, "browser_env", ENV_ANDROID);
        return ENV_IOS.equals(env) ? iosSafariUserAgent() : androidChromeUserAgent();
    }

    public static String envLabel(android.content.Context c) {
        String env = SessionStore.get(c, "browser_env", ENV_ANDROID);
        return ENV_IOS.equals(env) ? "iPhone Safari" : "Android Chrome";
    }

    private void showCookieDialog() {
        EditText input = new EditText(this);
        input.setHint("Cookie-Editor JSON \u6216 Cookie: a=b; c=d\n\u652f\u6301\u591a\u884c Set-Cookie\uff0c\u63a8\u8350\u7c98\u8d34 Cookie-Editor \u5bfc\u51fa JSON");
        input.setText(SessionStore.get(this, "web_cookie_raw", SessionStore.get(this, "web_cookie", "")));
        input.setSingleLine(false);
        input.setMinLines(10);
        input.setMaxLines(18);
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
            .setMessage("\u5982\u679c\u4f60\u5728\u6d4f\u89c8\u5668 Cookie-Editor \u53ef\u4ee5\u767b\u5f55\uff0c\u8bf7\u4f18\u5148\u7c98\u8d34\u5b83\u5bfc\u51fa\u7684 JSON\uff0cApp \u4f1a\u6309 domain/path/secure/httpOnly \u81ea\u52a8\u5904\u7406\u3002")
            .setView(box)
            .setNegativeButton("\u53d6\u6d88", null)
            .setPositiveButton("\u5bfc\u5165\u5e76\u767b\u5f55", null)
            .create();
        dialog.setOnShowListener(d -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String raw = input.getText().toString();
            if (raw.trim().isEmpty()) { input.setError("CK \u4e0d\u80fd\u4e3a\u7a7a"); return; }
            dialog.dismiss();
            setCookieLogin(raw);
        }));
        dialog.show();
    }

    private void setCookieLogin(String raw) {
        String loginUrl = SessionStore.get(this, "web_login_url", SessionStore.DEFAULT_WEB_LOGIN);
        List<CookieSpec> items = parseCookieSpecs(raw, loginUrl);
        if (items.isEmpty()) { status.setText("CK \u89e3\u6790\u5931\u8d25\uff0c\u8bf7\u7c98\u8d34 Cookie-Editor JSON \u6216 a=b; c=d"); return; }
        CookieManager cm = CookieManager.getInstance();
        cm.setAcceptCookie(true);
        cm.setAcceptThirdPartyCookies(webView, true);
        int count = 0;
        StringBuilder normalized = new StringBuilder();
        for (CookieSpec c : items) {
            if (c.name.isEmpty()) continue;
            String target = targetUrlForCookie(c, loginUrl);
            cm.setCookie(target, toSetCookieHeader(c));
            if (normalized.length() > 0) normalized.append("; ");
            normalized.append(c.name).append("=").append(c.value);
            count++;
        }
        cm.flush();
        String cookie = normalized.toString();
        SessionStore.put(this, "web_cookie_raw", raw);
        SessionStore.put(this, "web_cookie", cookie);
        SessionStore.put(this, "web_cookie_url", loginUrl);
        SessionStore.putBool(this, "web_cookie_imported", true);
        status.setText("\u5df2\u6309 domain/path \u7f6e\u5165 CK\uff1a" + count + " \u9879\uff0c\u6b63\u5728\u6253\u5f00\u767b\u5f55\u9875\u5e76\u540c\u6b65\u670d\u52a1\u5668");
        syncSession(loginUrl, cookie, hostOf(loginUrl));
        handler.postDelayed(() -> webView.loadUrl(loginUrl), 350);
    }

    private List<CookieSpec> parseCookieSpecs(String raw, String loginUrl) {
        ArrayList<CookieSpec> out = new ArrayList<>();
        String text = raw == null ? "" : raw.trim();
        if (text.startsWith("[") || text.startsWith("{")) {
            try {
                JSONArray arr;
                if (text.startsWith("[")) arr = new JSONArray(text);
                else {
                    JSONObject root = new JSONObject(text);
                    arr = root.optJSONArray("cookies");
                    if (arr == null) arr = root.optJSONArray("data");
                    if (arr == null) arr = root.optJSONArray("exportedCookies");
                }
                if (arr != null) {
                    for (int i = 0; i < arr.length(); i++) {
                        JSONObject o = arr.optJSONObject(i);
                        if (o == null) continue;
                        CookieSpec c = new CookieSpec();
                        c.name = o.optString("name", "").trim();
                        c.value = String.valueOf(o.opt("value") == null ? "" : o.opt("value"));
                        c.domain = o.optString("domain", o.optString("host", "")).trim();
                        c.path = o.optString("path", "/").trim();
                        if (c.path.isEmpty()) c.path = "/";
                        c.secure = o.has("secure") ? o.optBoolean("secure", true) : true;
                        c.httpOnly = o.optBoolean("httpOnly", o.optBoolean("http_only", false));
                        c.sameSite = o.optString("sameSite", o.optString("same_site", "")).trim();
                        Object exp = o.opt("expirationDate");
                        if (exp == null) exp = o.opt("expires");
                        if (exp instanceof Number) c.expirationSeconds = ((Number) exp).longValue();
                        else if (exp != null) {
                            try { c.expirationSeconds = (long) Double.parseDouble(String.valueOf(exp)); } catch (Exception ignored) {}
                        }
                        if (!c.name.isEmpty()) out.add(c);
                    }
                }
            } catch (Exception ignored) {}
            if (!out.isEmpty()) return out;
        }
        return parseTextCookies(text, loginUrl);
    }

    private List<CookieSpec> parseTextCookies(String text, String loginUrl) {
        ArrayList<CookieSpec> out = new ArrayList<>();
        String normalizedText = text.replace('\r', '\n');
        StringBuilder cookieLines = new StringBuilder();
        String[] lines = normalizedText.split("\\n");
        for (String line : lines) {
            String t = line.trim();
            if (t.isEmpty()) continue;
            String lower = t.toLowerCase(Locale.US);
            if (lower.startsWith("set-cookie:")) {
                CookieSpec c = parseSetCookie(t.substring(t.indexOf(':') + 1).trim());
                if (c != null) out.add(c);
            } else if (lower.startsWith("cookie:")) {
                if (cookieLines.length() > 0) cookieLines.append(';');
                cookieLines.append(t.substring(t.indexOf(':') + 1).trim());
            } else if (t.contains("=") && (t.contains(";") || lines.length == 1)) {
                if (cookieLines.length() > 0) cookieLines.append(';');
                cookieLines.append(t);
            }
        }
        if (cookieLines.length() == 0 && normalizedText.contains("=")) cookieLines.append(normalizedText);
        String merged = cookieLines.toString().replace('\n', ';').replace('\t', ' ');
        String host = hostOf(loginUrl);
        for (String part : merged.split(";")) {
            CookieSpec c = parseNameValue(part.trim());
            if (c == null) continue;
            c.domain = host;
            c.path = "/";
            out.add(c);
        }
        return out;
    }

    private CookieSpec parseSetCookie(String line) {
        String[] parts = line.split(";");
        CookieSpec c = parseNameValue(parts.length > 0 ? parts[0].trim() : "");
        if (c == null) return null;
        for (int i = 1; i < parts.length; i++) {
            String attr = parts[i].trim();
            String lower = attr.toLowerCase(Locale.US);
            int eq = attr.indexOf('=');
            String val = eq >= 0 ? attr.substring(eq + 1).trim() : "";
            if (lower.startsWith("domain=")) c.domain = val;
            else if (lower.startsWith("path=")) c.path = val.isEmpty() ? "/" : val;
            else if (lower.startsWith("expires=")) c.expiresText = val;
            else if (lower.startsWith("max-age=")) {
                try { c.expirationSeconds = System.currentTimeMillis() / 1000 + Long.parseLong(val); } catch (Exception ignored) {}
            } else if (lower.equals("secure")) c.secure = true;
            else if (lower.equals("httponly")) c.httpOnly = true;
            else if (lower.startsWith("samesite=")) c.sameSite = val;
        }
        return c;
    }

    private CookieSpec parseNameValue(String item) {
        if (item == null) return null;
        item = item.trim();
        if (item.isEmpty() || !item.contains("=")) return null;
        String lower = item.toLowerCase(Locale.US);
        if (lower.startsWith("path=") || lower.startsWith("domain=") || lower.startsWith("expires=") || lower.startsWith("max-age=") || lower.equals("secure") || lower.equals("httponly") || lower.startsWith("samesite=")) return null;
        int eq = item.indexOf('=');
        CookieSpec c = new CookieSpec();
        c.name = item.substring(0, eq).trim();
        c.value = item.substring(eq + 1).trim();
        return c.name.isEmpty() ? null : c;
    }

    private String targetUrlForCookie(CookieSpec c, String fallbackUrl) {
        String domain = c.domain == null ? "" : c.domain.trim();
        while (domain.startsWith(".")) domain = domain.substring(1);
        if (domain.isEmpty()) return fallbackUrl;
        return "https://" + domain + (c.path == null || c.path.isEmpty() ? "/" : c.path);
    }

    private String toSetCookieHeader(CookieSpec c) {
        StringBuilder sb = new StringBuilder();
        sb.append(c.name).append("=").append(c.value);
        sb.append("; Path=").append(c.path == null || c.path.isEmpty() ? "/" : c.path);
        if (c.domain != null && !c.domain.trim().isEmpty()) sb.append("; Domain=").append(c.domain.trim());
        if (c.expirationSeconds > 0) sb.append("; Expires=").append(httpDate(c.expirationSeconds));
        else if (c.expiresText != null && !c.expiresText.isEmpty()) sb.append("; Expires=").append(c.expiresText);
        if (c.secure) sb.append("; Secure");
        if (c.httpOnly) sb.append("; HttpOnly");
        String ss = normalizeSameSite(c.sameSite);
        if (!ss.isEmpty()) sb.append("; SameSite=").append(ss);
        return sb.toString();
    }

    private String normalizeSameSite(String sameSite) {
        if (sameSite == null) return "";
        String s = sameSite.trim().toLowerCase(Locale.US);
        if (s.isEmpty() || "unspecified".equals(s)) return "";
        if ("no_restriction".equals(s) || "none".equals(s)) return "None";
        if ("lax".equals(s)) return "Lax";
        if ("strict".equals(s)) return "Strict";
        return sameSite.trim();
    }

    private String httpDate(long seconds) {
        try {
            SimpleDateFormat f = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US);
            f.setTimeZone(TimeZone.getTimeZone("GMT"));
            return f.format(new Date(seconds * 1000L));
        } catch (Exception e) { return ""; }
    }

    private void clearWebCookies() {
        CookieManager cm = CookieManager.getInstance();
        cm.removeAllCookies(value -> handler.post(() -> {
            cm.flush();
            SessionStore.put(WebLoginActivity.this, "web_cookie", "");
            SessionStore.put(WebLoginActivity.this, "web_cookie_raw", "");
            SessionStore.put(WebLoginActivity.this, "web_cookie_url", "");
            SessionStore.putBool(WebLoginActivity.this, "web_cookie_imported", false);
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
        String saved = SessionStore.get(this, "web_cookie", "");
        boolean imported = SessionStore.getBool(this, "web_cookie_imported", false);
        if (imported && saved.length() > cookie.length()) {
            cookie = saved;
        } else {
            SessionStore.put(this, "web_cookie", cookie);
            SessionStore.put(this, "web_cookie_url", url);
        }
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
