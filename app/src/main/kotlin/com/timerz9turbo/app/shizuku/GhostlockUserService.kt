package com.timerz9turbo.app.shizuku

import android.content.Context
import android.os.Process
import androidx.annotation.Keep
import com.timerz9turbo.app.data.ManagerScanner
import java.io.File
import java.io.RandomAccessFile
import java.util.concurrent.atomic.AtomicBoolean

/**
 * TimerZ9Turbo Shizuku service: same GhostLock plumbing (MiUIX UI, ManagerScanner
 * with NO default, safemode flag, debugDir, colored log via callback), but the
 * exploit backend is CVE-2026-98260 Timer backport for V2352GA (6.1.145), NOT
 * libghostlock.so. Profile blob / CPU params are accepted for API stability
 * and logged, then ignored (Timer uses hardcoded V2352GA offsets + tracefs).
 */
@Keep
class GhostlockUserService(private val context: Context) : IGhostlockUserService.Stub() {
    private val running = AtomicBoolean(false)

    override fun runExploit(
        primaryCpu: Int,
        consumerCpu: Int,
        safeMode: Boolean,
        forceAttack: Boolean,
        profileBlob: ByteArray,
        debugDir: String?,
        callback: IGhostlockCallback,
        statusCallback: IGhostlockStatusCallback,
    ) = runExploitAsManager(primaryCpu, consumerCpu, safeMode, forceAttack, profileBlob, debugDir, null, callback, statusCallback)

    override fun runExploitAsManager(
        primaryCpu: Int,
        consumerCpu: Int,
        safeMode: Boolean,
        forceAttack: Boolean,
        profileBlob: ByteArray,
        debugDir: String?,
        managerPackage: String?,
        callback: IGhostlockCallback,
        statusCallback: IGhostlockStatusCallback,
    ) {
        if (!running.compareAndSet(false, true)) {
            callback.onLog("<s> error: another Timer process is already running")
            callback.onComplete(1)
            return
        }
        Thread({
            val exitCode = runCatching {
                require(Process.myUid() == Process.SHELL_UID) {
                    "Shizuku UserService uid=${Process.myUid()}, expected ${Process.SHELL_UID}"
                }
                val status = File("/proc/self/status").readText()
                require(Regex("(?m)^Seccomp:\\s*0$").containsMatchIn(status)) {
                    "Shizuku UserService is still seccomp-filtered"
                }
                val release = System.getProperty("os.version", "").orEmpty()
                callback.onLog("<s> Shizuku ready: uid=${Process.myUid()} Seccomp=0")
                callback.onLog("<s> kernel: $release (TimerZ9Turbo V2352GA backport, profile-free)")
                callback.onLog("[*] Timer CVE-2026-98260 (6.1.145-maybe-dirty PD2352), vr.ko precise disable, no mount, no system RW")

                // Install the Timer backport binary matching the running kernel
                // (6.1.124 vs 6.1.145 hardcoded-offset builds); ksud comes
                // from the selected SU manager (DFRoot pattern), never embedded.
                val timerAsset = timerAssetFor(release)
                callback.onLog("<s> timer backend: $timerAsset ($release)")
                val timerBin = File("/data/local/tmp/timer")
                runCatching { installAsset(timerAsset, timerBin) }
                require(timerBin.isFile) { "missing Timer binary after install" }
                Runtime.getRuntime().exec(arrayOf("/system/bin/chmod", "755", timerBin.absolutePath)).waitFor()

                // SU manager: DFRoot/GhostLock logic — chosen package first, else auto (BUILTIN order).
                // NO hardcoded SukiSU default: null/blank means auto-detect.
                val pm = context.packageManager
                val chosen = managerPackage?.takeIf { it.isNotBlank() }
                val ksudPath = ManagerScanner.resolvePackages(chosen)
                    .asSequence()
                    .map { pkg ->
                        runCatching {
                            File(pm.getApplicationInfo(pkg, 0).nativeLibraryDir, "libksud.so")
                        }.getOrNull()?.takeIf { it.isFile }
                    }
                    .firstOrNull { it != null }
                // Persist choice for ksu_stage.sh (reads flag file, no hardcode).
                File("/data/local/tmp/su_manager_pkg").writeText((chosen ?: "") + "\n")
                // Exact ksud path (PackageManager-resolved): pm(1) has no binder access in kernel context.
                runCatching {
                    val ksudFlag = File("/data/local/tmp/ksud_path")
                    if (ksudPath != null) ksudFlag.writeText(ksudPath.absolutePath + "\n")
                    else if (ksudFlag.exists()) ksudFlag.delete()
                }
                if (chosen != null) callback.onLog("<s> SU manager selected: $chosen") else callback.onLog("<s> SU manager: auto-detect (${ManagerScanner.BUILTIN.joinToString()})")
                ksudPath?.let { callback.onLog("<s> ksud resolved: ${it.absolutePath}") }
        
                // Safemode (DFRoot logic): flag file read by ksu_stage.sh before late-load.
                val safeFlag = File("/data/local/tmp/safemode_enable")
                if (safeMode) {
                    safeFlag.writeText("1\n")
                    callback.onLog("[*] safemode ON: will disable /data/adb/modules/* on load")
                } else {
                    runCatching { if (safeFlag.exists()) safeFlag.delete() }
                    callback.onLog("[*] safemode OFF")
                }

                val workDir = File("/data/local/tmp/timerZ9").apply {
                    require(isDirectory || mkdirs()) { "cannot create $absolutePath" }
                }
                val timerLog = File(workDir, "timer.log")
                if (timerLog.exists()) runCatching { timerLog.delete() }

                callback.onLog("<b> starting timer: ${timerBin.absolutePath} fake")
                // One-shot fake: full chain (vr de-tag + KSU late-load). Detached so the
                // parked zombie (fake-cred page holder) survives; reboot is the only cleanup.
                val cmd = "cd /data/local/tmp && setsid ${timerBin.absolutePath} fake >${timerLog.absolutePath} 2>&1 </dev/null &"
                Runtime.getRuntime().exec(arrayOf("/system/bin/sh", "-c", cmd)).waitFor()

                // Tail timer.log -> callback (GhostLock tones come from [+/-/*/!] markers).
                var offset = 0L
                val deadline = System.currentTimeMillis() + 150000
                var loaded = false
                var lastLine = ""
                while (System.currentTimeMillis() < deadline) {
                    if (timerLog.isFile) {
                        RandomAccessFile(timerLog, "r").use { h ->
                            if (offset > h.length()) offset = 0
                            h.seek(offset)
                            while (true) {
                                val line = h.readLine() ?: break
                                // readLine strips \n but keeps \r on some builds
                                val clean = line.trimEnd('\r')
                                if (clean.isNotEmpty()) {
                                    runCatching { callback.onLog(clean) }
                                    lastLine = clean
                                    if (clean.contains("KSU_LOADED")) loaded = true
                                }
                            }
                            offset = h.filePointer
                        }
                    }
                    if (loaded) break
                    // Terminal failure: timer parked, KSU_LOADED will never come (fail fast so X re-enables).
                    if (lastLine.contains("ksud missing")
                        || lastLine.contains("did not reach euid")
                        || lastLine.contains("cred write did not land")
                        || lastLine.contains("parking without reap")
                    ) break
                    Thread.sleep(500)
                }
                if (!loaded) {
                    // Mirror log to debugDir if requested (Advanced > Export kernel log uses dmesg separately).
                    if (!debugDir.isNullOrEmpty()) {
                        runCatching {
                            File(debugDir).mkdirs()
                            timerLog.copyTo(File(debugDir, "timer-${System.currentTimeMillis()}.log"), overwrite = true)
                        }
                    }
                    require(loaded) { "SukiSU/KernelSU failed (KSU_LOADED not seen; reboot then retry)" }
                }
                // Copy success log to debugDir as well.
                if (!debugDir.isNullOrEmpty()) {
                    runCatching {
                        File(debugDir).mkdirs()
                        timerLog.copyTo(File(debugDir, "timer-${System.currentTimeMillis()}.log"), overwrite = true)
                    }
                }
                callback.onLog("[+] KSU_LOADED - parked zombie holds fake-cred page; reboot to clean")
                0
            }.getOrElse { error ->
                runCatching { callback.onLog("<s> error: ${error.message}") }
                1
            }
            running.set(false)
            runCatching { callback.onComplete(exitCode) }
        }, "timerz9-shizuku-runner").start()
    }

    override fun runDiagnose(callback: IGhostlockCallback) {
        Thread({
            val code = runCatching {
                val timerBin = File("/data/local/tmp/timer")
                // Always (re)install: the other kernel's binary may be present.
                runCatching { installAsset(timerAssetFor(System.getProperty("os.version", "").orEmpty()), timerBin) }
                Runtime.getRuntime().exec(arrayOf("/system/bin/chmod", "755", timerBin.absolutePath)).waitFor()
                require(timerBin.isFile) { "timer binary missing; press Prepare first" }
                callback.onLog("[*] diagnose: timer ids (no UAF, safe to retry)")
                val p = ProcessBuilder("/system/bin/sh", "-c", "${timerBin.absolutePath} ids 2>&1")
                    .directory(File("/data/local/tmp"))
                    .redirectErrorStream(true)
                    .start()
                val out = p.inputStream.bufferedReader().readText()
                p.waitFor()
                out.lines().forEach { line ->
                    if (line.isNotBlank()) runCatching { callback.onLog(line) }
                }
                // dmesg attempt (may be denied on user builds; skipped per spec).
                runCatching {
                    val d = ProcessBuilder("/system/bin/sh", "-c", "dmesg 2>&1 | tail -50")
                        .redirectErrorStream(true).start()
                    val dt = d.inputStream.bufferedReader().readText()
                    d.waitFor()
                    if (dt.contains("Permission denied") || dt.isBlank()) {
                        callback.onLog("[*] kernel log not permitted, skipped")
                    } else {
                        dt.lines().takeLast(20).forEach { callback.onLog("[k] $it") }
                    }
                }
                0
            }.getOrElse { e ->
                runCatching { callback.onLog("[-] diagnose failed: ${e.message}") }
                1
            }
            runCatching { callback.onComplete(code) }
        }, "timerz9-diagnose").start()
    }

    /** Per-kernel Timer backend (hardcoded offsets differ per build). */
    private fun timerAssetFor(release: String): String =
        if ("6.1.124" in release) "timer-6.1.124" else "timer"

    private fun installAsset(name: String, dst: File) {
        context.assets.open(name).use { input ->
            // ETXTBSY-safe: write tmp then rename (old binary may be mapped by a parked process).
            val tmp = File(dst.absolutePath + ".new")
            tmp.outputStream().use { output -> input.copyTo(output) }
            Runtime.getRuntime().exec(arrayOf("/system/bin/sh", "-c", "chmod 755 ${tmp.absolutePath} && mv -f ${tmp.absolutePath} ${dst.absolutePath}")).waitFor()
        }
    }

    override fun shell(cmd: String): String = try {
        ProcessBuilder("/system/bin/sh", "-c", cmd)
            .redirectErrorStream(true)
            .start()
            .inputStream.bufferedReader().readText().trim()
    } catch (_: Throwable) {
        ""
    }

    override fun destroy() {
        if (!running.get()) kotlin.system.exitProcess(0)
    }
}
