package com.codex.ajieandroid;

import android.content.Context;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;

public final class ApiClient {
    public interface Callback { void done(JSONObject json, Exception err); }

    private final Context context;
    private final String serverUrl;

    public ApiClient(Context context) {
        this.context = context.getApplicationContext();
        this.serverUrl = SessionStore.get(context, "server_url", SessionStore.DEFAULT_SERVER);
    }

    public void postAsync(JSONObject body, Callback cb) {
        new Thread(() -> {
            try { cb.done(post(body), null); }
            catch (Exception e) { cb.done(null, e); }
        }, "ajie-api").start();
    }

    public JSONObject post(JSONObject body) throws Exception {
        JSONObject common = DeviceInfo.common(context);
        Iterator<String> keys = common.keys();
        while (keys.hasNext()) {
            String k = keys.next();
            if (!body.has(k)) body.put(k, common.get(k));
        }

        URL u = new URL(serverUrl);
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setRequestMethod("POST");
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(30000);
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        conn.setRequestProperty("Accept", "application/json, text/plain, */*");
        String token = SessionStore.get(context, "token", "");
        if (!token.isEmpty()) conn.setRequestProperty("Authorization", "Bearer " + token);

        byte[] data = body.toString().getBytes(StandardCharsets.UTF_8);
        conn.setFixedLengthStreamingMode(data.length);
        try (OutputStream os = conn.getOutputStream()) { os.write(data); }

        int code = conn.getResponseCode();
        InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
        String resp = readAll(is);
        JSONObject out;
        try { out = new JSONObject(resp); }
        catch (Exception parse) {
            out = new JSONObject();
            out.put("success", false);
            out.put("ok", false);
            out.put("code", String.valueOf(code));
            out.put("msg", "\u670d\u52a1\u5668\u8fd4\u56de\u4e86\u975e JSON \u5185\u5bb9");
            out.put("raw", resp);
        }
        out.put("_http", code);
        return out;
    }

    public static boolean ok(JSONObject json) {
        if (json == null) return false;
        if (json.optBoolean("success", false) || json.optBoolean("ok", false)) return true;
        String code = json.optString("code", "");
        return "200".equals(code) || "0".equals(code);
    }

    public static String compact(JSONObject json) {
        String s = json == null ? "" : json.toString();
        return s.length() > 1200 ? s.substring(0, 1200) + "..." : s;
    }

    private static String readAll(InputStream is) throws Exception {
        if (is == null) return "";
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append('\n');
        }
        return sb.toString().trim();
    }
}
