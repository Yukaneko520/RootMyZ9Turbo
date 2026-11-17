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

    private suspend fun closeAdbPort(client: AdbClient, onLog: (String) -> Unit): Boolean {
        val detached = "su -c 'setsid sh -c \"sleep 1; setprop service.adb.tcp.port -1; iptables -D INPUT -p tcp --dport 5555 ! -i lo -j DROP 2>/dev/null; ip6tables -D INPUT -p tcp --dport 5555 ! -i lo -j DROP 2>/dev/null; setprop ctl.restart adbd\" >/dev/null 2>&1 &'"
        runCatching {
            client.exec(detached, timeoutMs = 5_000)
        }
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
