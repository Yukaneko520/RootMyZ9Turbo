package com.timerz9turbo.app.shizuku;

import com.timerz9turbo.app.shizuku.IGhostlockCallback;
import com.timerz9turbo.app.shizuku.IGhostlockStatusCallback;

interface IGhostlockUserService {
    void destroy() = 16777114;
    void runExploit(int primaryCpu, int consumerCpu, boolean safeMode, boolean forceAttack, in byte[] profileBlob, @nullable String debugDir, IGhostlockCallback callback, IGhostlockStatusCallback statusCallback) = 2;
    void runExploitAsManager(int primaryCpu, int consumerCpu, boolean safeMode, boolean forceAttack, in byte[] profileBlob, @nullable String debugDir, @nullable String managerPackage, IGhostlockCallback callback, IGhostlockStatusCallback statusCallback) = 3;
    void runDiagnose(IGhostlockCallback callback) = 4;
    String shell(String cmd) = 5;
}
