package com.timerz9turbo.app.shizuku;

oneway interface IGhostlockCallback {
    void onLog(String line);
    void onComplete(int exitCode);
}
