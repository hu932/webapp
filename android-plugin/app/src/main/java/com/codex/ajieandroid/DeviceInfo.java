package com.codex.ajieandroid;

import android.content.Context;
import android.os.Build;
import android.provider.Settings;
import org.json.JSONException;
import org.json.JSONObject;
import java.security.MessageDigest;

public final class DeviceInfo {
    private DeviceInfo() {}

    public static String androidId(Context c) {
        String id = Settings.Secure.getString(c.getContentResolver(), Settings.Secure.ANDROID_ID);
        return id == null ? "" : id;
    }

    public static String fingerprintKey(Context c) {
        String raw = androidId(c) + "|" + Build.BRAND + "|" + Build.MODEL + "|" + Build.VERSION.SDK_INT;
        String hash = sha256(raw);
        return hash.length() >= 16 ? hash.substring(0, 16) : hash;
    }

    public static String defaultAccount(Context c) {
        return "android-" + fingerprintKey(c);
    }

    public static JSONObject common(Context c) throws JSONException {
        JSONObject o = new JSONObject();
        o.put("platform", "android");
        o.put("client", "ajie-android");
        o.put("client_label", "Ajie \u5b89\u5353\u52a9\u624b");
        o.put("device_type", "Android " + Build.VERSION.RELEASE);
        o.put("device_label", Build.MANUFACTURER + " " + Build.MODEL);
        o.put("device_id", androidId(c));
        o.put("fingerprint_key", fingerprintKey(c));
        o.put("username", SessionStore.username(c));
        o.put("appVersion", "v1.1.3");
        o.put("version", "1.1.3");
        o.put("version_code", 6);
        return o;
    }

    private static String sha256(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] b = md.digest(s.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte x : b) sb.append(String.format("%02x", x));
            return sb.toString();
        } catch (Exception e) {
            return Integer.toHexString(s.hashCode()) + "0000000000000000";
        }
    }
}
