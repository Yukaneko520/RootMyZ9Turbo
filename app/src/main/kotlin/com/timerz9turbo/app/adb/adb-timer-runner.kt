package com.timerz9turbo.app.adb

import android.content.Context
import com.timerz9turbo.app.data.ManagerScanner
import com.timerz9turbo.app.shizuku.TimerTiming
import com.timerz9turbo.app.shizuku.kernelVersionFromOutput
import com.timerz9turbo.app.shizuku.timerAssetFor

/**
 * Runs the existing Timer native backend through the local adb shell instead
 * of a Shizuku UserService. The binary orchestration mirrors TimerUserService.
 */
internal class AdbTimerRunner(
    private val context: Context,
    private val client: AdbClient,
) {
    fun run(safeMode: Boolean, managerPackage: String?, onLog: (String) -> Unit): Int {
        val resolved = ManagerScanner.resolveKsud(context.packageManager, managerPackage)
            ?: throw IllegalStateException("No unambiguous ksud in the selected root manager")
        val asset = timerAssetFor(System.getProperty("os.version", "").orEmpty())
        val apkPath = context.applicationInfo.sourceDir
        val completion = "/data/local/tmp/timerZ9/complete-${System.nanoTime()}.bin"
        val logFile = "/data/local/tmp/timerZ9/timer-adb.log"
        try {
            onLog("<s> ADB shell ready; staging native payload")
            runRemote("mkdir -p /data/local/tmp/timerZ9")
            runRemote("cp ${q(resolved.file.absolutePath)} $KSUD_REMOTE && chmod 755 $KSUD_REMOTE")
            ensureTimerBinary(onLog)
            runRemote("printf '%s\\n' ${q(resolved.packageName)} > $SU_PACKAGE_REMOTE")
            runRemote("printf '%s\\n' $KSUD_REMOTE > $KSUD_PATH_REMOTE")
            onLog("<s> SU manager: ${resolved.packageName}")
            onLog("<s> ksud: $KSUD_REMOTE")
            onLog("[*] safemode ${if (safeMode) "ON" else "OFF"}")
            runRemote("rm -f ${q(completion)} ${q(logFile)}; : > ${q(completion)}; : > ${q(logFile)}")
            onLog("<b> starting timer via ADB: $TIMER_REMOTE fake${if (safeMode) " safemode" else ""}")

            val script = """
                cd /data/local/tmp
                TIMERZ9_COMPLETION_PATH=${q(completion)} setsid $TIMER_REMOTE fake${if (safeMode) " safemode" else ""} >${q(logFile)} 2>&1 </dev/null &
                tail -n +1 -f ${q(logFile)} &
                TL=${'$'}!
                i=0
                while [ ! -s ${q(completion)} ] && [ ${'$'}i -lt ${TimerTiming.COMPLETION_POLLS} ]; do sleep 0.25; i=${'$'}((i+1)); done
                sleep 0.5
                kill ${'$'}TL 2>/dev/null
                sleep 0.1
                kill -9 ${'$'}TL 2>/dev/null
                wait ${'$'}TL 2>/dev/null || true
                if [ -s ${q(completion)} ]; then
                    printf '\n__TZ9_COMPLETE__%s\n' "${'$'}(od -An -t u1 ${q(completion)} | tr -d ' ')"
                else
                    printf '\n__TZ9_TIMEOUT__\n'
                fi
            """.trimIndent()
            var completionValue: String? = null
            var timedOut = false
            client.shell(script, timeoutMs = TimerTiming.SHELL_TIMEOUT_MS.toInt()) { line ->
                when {
                    line == "__TZ9_TIMEOUT__" -> timedOut = true
                    line.startsWith("__TZ9_COMPLETE__") ->
                        completionValue = line.removePrefix("__TZ9_COMPLETE__").trim()

                    else -> onLog(line)
                }
            }
            if (timedOut) {
                onLog("[!] Timer did not complete within ${TimerTiming.LOG_WATCH_MS / 1000}s")
                return 1
            }
            if (completionValue != "1") {
                onLog("[!] Timer completion event: ${completionValue ?: "missing"}")
                return 1
            }
            if (!confirmKernel(onLog)) {
                onLog("[!] KernelSU not confirmed by kernel API (reboot then retry)")
                return 1
            }
            onLog("[+] KernelSU confirmed; native credential holder remains parked")
            return 0
        } finally {
            runCatching {
                runRemote("rm -f $KSUD_REMOTE $SU_PACKAGE_REMOTE $KSUD_PATH_REMOTE ${q(completion)}")
            }
        }
    }

    fun diagnose(onLog: (String) -> Unit): Int {
        runRemote("mkdir -p /data/local/tmp")
        ensureTimerBinary()
        onLog("[*] diagnose: timer ids via ADB (no UAF, safe to retry)")
        onLog("<s> ${grepSeccomp()}")
        val result = client.exec("cd /data/local/tmp && ./timer ids", timeoutMs = 30_000)
        result.output.lineSequence().filter { it.isNotBlank() }.forEach(onLog)
        if (result.exitCode != 0) onLog("[!] timer ids exit=${result.exitCode}")
        runCatching {
            val dmesg = client.exec("dmesg 2>&1 | tail -50", timeoutMs = 10_000)
            if (dmesg.output.contains("Permission denied") || dmesg.output.isBlank()) {
                onLog("[*] kernel log not permitted, skipped")
            } else {
                dmesg.output.lineSequence().filter { it.isNotBlank() }.toList().takeLast(20)
                    .forEach { onLog("[k] $it") }
            }
        }
        return result.exitCode
    }

    /**
     * Stages the payload matching the running kernel.
     *
     * This must overwrite unconditionally.  A previous run (or an older app
     * version) leaves `/data/local/tmp/timer` behind, and the binary is
     * intentionally detached: it parks while holding a credential page, so it
     * outlives the app process.  Skipping the copy when the file merely exists
     * silently ran the *previous* native build -- the log still looked normal
     * but none of the new plant-recovery fixes were active.
     */
    private fun ensureTimerBinary(onLog: (String) -> Unit = {}) {
        val asset = timerAssetFor(System.getProperty("os.version", "").orEmpty())
        val cacheDir = context.externalCacheDir ?: context.cacheDir
        val tempFile = java.io.File(cacheDir, "timer_stage")
        try {
            context.assets.open(asset).use { input ->
                tempFile.outputStream().use { output -> input.copyTo(output) }
            }
            runRemote("cp ${q(tempFile.absolutePath)} $TIMER_REMOTE && chmod 755 $TIMER_REMOTE")
            onLog("<s> timer staged: $asset -> $TIMER_REMOTE")
        } finally {
            tempFile.delete()
        }
        // The copy is unconditional, so a silent mismatch means the write
        // failed on the device.  Surface the build tag actually on disk.
        runCatching {
            val probe = client.exec("$TIMER_REMOTE build", timeoutMs = 10_000)
            probe.output.lineSequence().filter { it.startsWith("timer ") }
                .take(2).forEach { onLog("<s> $it") }
        }
    }

    /**
     * Waits for the manager to report a positive kernel version.
     *
     * A module that is loaded but not yet initialised answers
     * `Kernel Version: 0`, so this polls for the shared confirmation window
     * instead of sampling three times in ~1.5 s.  Getting this wrong reports a
     * fully-rooted run as "KernelSU not confirmed".
     */
    private fun confirmKernel(onLog: (String) -> Unit): Boolean {
        val deadline = System.nanoTime() + TimerTiming.CONFIRM_WATCH_MS * 1_000_000L
        while (true) {
            val probe = runCatching {
                client.exec("$KSUD_REMOTE debug version", timeoutMs = 6_000)
            }.getOrNull()
            val version = probe?.let { kernelVersionFromOutput(it.output) }
            if (probe != null && probe.exitCode == 0 && version != null) {
                onLog("[ksu] kernel confirmed: version=$version")
                return true
            }
            if (System.nanoTime() >= deadline) return false
            Thread.sleep(500)
        }
    }

    private fun grepSeccomp(): String = runCatching {
        client.exec("grep -E '^(Uid|Seccomp):' /proc/self/status", timeoutMs = 5_000).output.trim()
    }.getOrDefault("status unavailable")

    private fun runRemote(command: String) {
        val result = client.exec(command)
        check(result.exitCode == 0) {
            "ADB command failed (${result.exitCode}): ${result.output.trim().take(200)}"
        }
    }

    private fun q(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    private companion object {
        const val TIMER_REMOTE = "/data/local/tmp/timer"
        const val KSUD_REMOTE = "/data/local/tmp/ksud"
        const val SU_PACKAGE_REMOTE = "/data/local/tmp/su_manager_pkg"
        const val KSUD_PATH_REMOTE = "/data/local/tmp/ksud_path"
    }
}
