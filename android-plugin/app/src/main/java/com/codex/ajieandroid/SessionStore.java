package com.codex.ajieandroid;

import android.content.Context;
import android.content.SharedPreferences;

public final class SessionStore {
    private static final String PREF = "ajie_android_plugin";
    public static final String DEFAULT_SERVER = "http://103.146.231.72:2036/decrypt_proxy.php";
    public static final String DEFAULT_WEB_LOGIN = "https://shopee.tw/";

    private SessionStore() {}

    public static SharedPreferences sp(Context c) {
        return c.getApplicationContext().getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    public static String get(Context c, String key, String def) {
        return sp(c).getString(key, def);
    }

    public static void put(Context c, String key, String val) {
        sp(c).edit().putString(key, val == null ? "" : val).apply();
    }

    public static boolean getBool(Context c, String key, boolean def) {
        return sp(c).getBoolean(key, def);
    }

    public static void putBool(Context c, String key, boolean val) {
        sp(c).edit().putBoolean(key, val).apply();
    }

    public static String username(Context c) {
        String u = get(c, "username", "").trim();
        return u.equals(DeviceInfo.defaultAccount(c)) ? "" : u;
    }
}
