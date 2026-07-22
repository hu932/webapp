package com.codex.ajieandroid;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.CookieManager;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.LinearLayout;
import android.widget.TextView;

public class WebLoginActivity extends Activity {
    private TextView status;
    private WebView webView;

    @SuppressLint("SetJavaScriptEnabled")
    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        status = new TextView(this);
        status.setText("??????? Cookie");
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
            @Override public void onPageFinished(WebView view, String url) {
                String host = Uri.parse(url).getHost();
                if (host != null && host.contains("shopee")) {
                    String cookie = cm.getCookie(url);
                    if (cookie != null && !cookie.isEmpty()) {
                        SessionStore.put(WebLoginActivity.this, "web_cookie", cookie);
                        SessionStore.put(WebLoginActivity.this, "web_cookie_url", url);
                        status.setText("Cookie ???: " + host);
                    }
                }
            }
        });
        webView.loadUrl(SessionStore.get(this, "web_login_url", SessionStore.DEFAULT_WEB_LOGIN));
    }

    @Override protected void onDestroy() {
        if (webView != null) webView.destroy();
        super.onDestroy();
    }
}
