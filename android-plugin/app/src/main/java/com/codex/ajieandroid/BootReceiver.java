package com.codex.ajieandroid;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

public class BootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        if (intent == null || !Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) return;
        if (SessionStore.get(context, "web_cookie", "").isEmpty()) return;
        Intent it = new Intent(context, TaskWorkerService.class).setAction(TaskWorkerService.ACTION_START);
        if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(it); else context.startService(it);
    }
}
