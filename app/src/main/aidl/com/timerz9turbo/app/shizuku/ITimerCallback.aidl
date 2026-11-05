package com.timerz9turbo.app.shizuku;

oneway interface ITimerCallback {
    void onLog(String line);
    void onComplete(int exitCode);
}
