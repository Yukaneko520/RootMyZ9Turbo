package com.timerz9turbo.app.adb

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

internal class AdbRootCoordinator(
    private val context: Context,
    private val connection: AdbConnectionManager,
) {
    /** Manual Run path. Returns 0 only when KernelSU was confirmed. */
    suspend fun runManual(
        safeMode: Boolean,
        managerPackage: String?,
        diagnose: Boolean,
        onLog: (String) -> Unit,
    ): Int = withContext(Dispatchers.IO) {
        val client = try {
            connection.connectForUse(readTimeoutMs = 30_000)
        } catch (error: Exception) {
            onLog("<s> error: ADB is not ready: ${error.message}")
            return@withContext 1
        }
        client.use {
            val runner = AdbTimerRunner(context, it)
            if (diagnose) return@withContext runner.diagnose(onLog)
            if (managerPackage.isNullOrBlank()) {
                onLog("<s> error: select a root manager first")
                return@withContext 1
            }
            val code = runner.run(safeMode, managerPackage, onLog)
            if (code == 0) {
                if (waitForRoot(it, onLog)) closeAdbPort(it, onLog)
                else onLog("[!] root shell is unavailable; the ADB port could not be closed")
            }
            code
        }
    }

    private suspend fun waitForRoot(client: AdbClient, onLog: (String) -> Unit): Boolean {
        repeat(10) { attempt ->
            val result = runCatching {
                client.exec("su -c id", timeoutMs = 4_000)
            }.getOrNull()
            if (result != null && result.exitCode == 0 && result.output.contains("uid=0")) {
                onLog("[+] root shell available")
                return true
            }
            if (attempt < 9) delay(700)
        }
        return false
    }

    /**
     * Turns the adb TCP listener off again.
     *
     * Only `service.adb.tcp.port` is touched: it is the non-persistent override
     * for this boot, so setting -1 disables the listener without changing the
     * user's saved `persist.adb.tcp.port`.  adbd re-reads the property on
     * start, so every adbd instance is killed and init respawns it without a
     * TCP listener.
     */
    private suspend fun closeAdbPort(client: AdbClient, onLog: (String) -> Unit): Boolean {
        val stop = "su -c 'setprop service.adb.tcp.port -1; " +
            "killall -9 adbd 2>/dev/null; true'"
        onLog("<s> stopping adbd to close the ADB TCP port")
        runCatching { client.exec(stop, timeoutMs = 3_000) }
            .onFailure { error ->
                onLog("<s> adbd stop: connection dropped (${error.message}) " +
                    "- expected when adbd is killed")
            }

        if (!adbPortOpen()) {
            onLog("[+] ADB TCP port closed")
            return true
        }

        // init respawns adbd; give it time to come up without the listener.
        repeat(8) {
            delay(500)
            if (!adbPortOpen()) {
                onLog("[+] ADB TCP port closed")
                return true
            }
        }
        onLog("[!] ADB TCP port is still open; reboot to close it")
        return false
    }
}
