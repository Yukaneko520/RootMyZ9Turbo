package com.timerz9turbo.app.shizuku

import android.content.Context
import android.os.Process
import androidx.annotation.Keep
import com.timerz9turbo.app.data.KsudLibrary
import com.timerz9turbo.app.data.ManagerScanner
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

@Keep
class TimerUserService(private val context: Context) : ITimerUserService.Stub() {
    private val running = AtomicBoolean(false)

    override fun runTimer(safeMode: Boolean, debugDir: String?, managerPackage: String?, callback: ITimerCallback) =
        execute(callback) {
            withTemporaryKsud(File("/data/local/tmp/ksud"), callback::onLog) { daemon ->
                val timer = installTimer()
                val resolved = requireNotNull(ManagerScanner.resolveKsud(context.packageManager, managerPackage)) {
                    "No unambiguous ksud daemon found in the selected root manager"
                }
                KsudLibrary.stage(resolved.file, daemon).also {
                    callback.onLog("<s> ksud copied: ${resolved.file.absolutePath} -> ${it.absolutePath}")
                }
                require(daemon.canExecute()) { "ksud is not executable: ${daemon.absolutePath}" }
                File("/data/local/tmp/su_manager_pkg").writeText(resolved.packageName + "\n")
                File("/data/local/tmp/ksud_path").writeText(daemon.absolutePath + "\n")
                callback.onLog("<s> SU manager resolved: ${resolved.packageName}")
                callback.onLog("<s> ksud resolved: ${daemon.absolutePath}")
                callback.onLog("[*] safemode ${if (safeMode) "ON" else "OFF"}")
                val workDir = File("/data/local/tmp/timerZ9").apply {
                    require(isDirectory || mkdirs()) { "cannot create $absolutePath" }
                }
                val logFile = File(workDir, "timer.log")
                require(!logFile.exists() || logFile.delete()) { "cannot clear previous Timer log" }
                callback.onLog("<b> starting timer: ${timer.absolutePath} fake${if (safeMode) " safemode" else ""}")
                // Detach so the parked native process continues holding its credential page.
                val command = "cd /data/local/tmp && setsid ${timer.absolutePath} fake" +
                    (if (safeMode) " safemode" else "") + " >${logFile.absolutePath} 2>&1 </dev/null &"
                require(Runtime.getRuntime().exec(arrayOf("/system/bin/sh", "-c", command)).waitFor() == 0) {
                    "cannot launch Timer"
                }
                val loaded = try {
                    awaitTimerLoaded(logFile) { line -> runCatching { callback.onLog(line) } }
                } finally {
                    if (!debugDir.isNullOrBlank() && logFile.isFile) runCatching {
                        File(debugDir).mkdirs()
                        logFile.copyTo(File(debugDir, "timer-${System.currentTimeMillis()}.log"), overwrite = true)
                    }
                }
                require(loaded) { "SukiSU/KernelSU failed (KSU_LOADED not seen; reboot then retry)" }
                callback.onLog("[+] KSU_LOADED - parked zombie holds fake-cred page; reboot to clean")
                0
            }
        }

    override fun runDiagnose(callback: ITimerCallback) = execute(callback) {
        val timer = installTimer()
        callback.onLog("[*] diagnose: timer ids (no UAF, safe to retry)")
        val process = ProcessBuilder(timer.absolutePath, "ids").directory(File("/data/local/tmp"))
            .redirectErrorStream(true).start()
        process.inputStream.bufferedReader().useLines { lines ->
            lines.filter { it.isNotBlank() }.forEach { callback.onLog(it) }
        }
        val code = process.waitFor()
        runCatching {
            val dmesg = ProcessBuilder("/system/bin/sh", "-c", "dmesg 2>&1 | tail -50")
                .redirectErrorStream(true).start()
            val text = dmesg.inputStream.bufferedReader().use { it.readText() }
            dmesg.waitFor()
            if (text.contains("Permission denied") || text.isBlank()) {
                callback.onLog("[*] kernel log not permitted, skipped")
            } else text.lines().takeLast(20).forEach { callback.onLog("[k] $it") }
        }
        code
    }

    private fun installTimer(): File {
        val asset = timerAssetFor(System.getProperty("os.version", "").orEmpty())
        return context.assets.open(asset).use { KsudLibrary.stage(it, File("/data/local/tmp/timer")) }
    }

    private fun execute(callback: ITimerCallback, operation: () -> Int) {
        if (!running.compareAndSet(false, true)) {
            callback.onLog("<s> error: another Timer operation is already running")
            callback.onComplete(1)
            return
        }
        Thread({
            val code = runCatching {
                require(Process.myUid() == Process.SHELL_UID) { "UserService must run as shell (uid 2000)" }
                require(Regex("(?m)^Seccomp:\\s*0$").containsMatchIn(File("/proc/self/status").readText())) {
                    "Shizuku UserService is still seccomp-filtered"
                }
                callback.onLog("<s> Shizuku ready: uid=${Process.myUid()} Seccomp=0")
                callback.onLog("<s> kernel: ${System.getProperty("os.version")}")
                operation()
            }.getOrElse {
                runCatching { callback.onLog("<s> error: ${it.message}") }
                1
            }
            running.set(false)
            runCatching { callback.onComplete(code) }
        }, "timerz9-shizuku").start()
    }

    override fun destroy() { if (!running.get()) kotlin.system.exitProcess(0) }
}

internal fun timerAssetFor(release: String): String = if ("6.1.124" in release) "timer-6.1.124" else "timer"

internal fun withTemporaryKsud(file: File, onLog: (String) -> Unit, operation: (File) -> Int): Int = try {
    operation(file)
} finally {
    if (file.exists()) {
        val removed = file.delete()
        runCatching { onLog(if (removed) "[ksu] temporary ksud removed" else "[!] cannot remove temporary ksud") }
    }
}
