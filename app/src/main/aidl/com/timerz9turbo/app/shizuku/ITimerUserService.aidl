package com.timerz9turbo.app.shizuku;

import com.timerz9turbo.app.shizuku.ITimerCallback;

interface ITimerUserService {
    void destroy() = 16777114;
    void runTimer(boolean safeMode, @nullable String debugDir, @nullable String managerPackage, ITimerCallback callback) = 2;
    void runDiagnose(ITimerCallback callback) = 3;
}
