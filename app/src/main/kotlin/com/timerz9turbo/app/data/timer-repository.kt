package com.timerz9turbo.app.data

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.SystemClock
import androidx.core.content.edit
import com.timerz9turbo.app.BuildConfig
import com.timerz9turbo.app.BuildInfo
import com.timerz9turbo.app.adb.AdbConnectionManager
import com.timerz9turbo.app.adb.AdbKeyManager
import com.timerz9turbo.app.adb.AdbRootCoordinator
import com.timerz9turbo.app.adb.AdbRootPreferences
import com.timerz9turbo.app.adb.AdbSetupManager
import com.timerz9turbo.app.domain.model.AdbLinkStatus
import com.timerz9turbo.app.domain.model.AdbRootSettings
import com.timerz9turbo.app.domain.model.AdbSetupSnapshot
import com.timerz9turbo.app.domain.model.DebugSettings
import com.timerz9turbo.app.domain.model.SetupActionResult
import com.timerz9turbo.app.domain.model.TimerSnapshot
import com.timerz9turbo.app.adb.ShellResult
import com.timerz9turbo.app.adb.defaultExecuteSu
import com.timerz9turbo.app.shizuku.ShizukuTimerRunner
import com.timerz9turbo.app.shizuku.knownKernelProfile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

class TimerRepository internal constructor(
    context: Context,
    suRunner: (String) -> ShellResult,
) {
    constructor(context: Context) : this(context, ::defaultExecuteSu)

    private companion object { const val PREF_KERNEL_ONLY_MATCH = "kernel_only_match" }
    private val context = context.applicationContext
    // Preserve manager and debug preferences from existing installations.
    private val preferences = this.context.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE)
    private val runner = ShizukuTimerRunner(this.context)
    private val adbPreferences = AdbRootPreferences(this.context)
    private val adbKeys = AdbKeyManager(this.context)
    private val adbConnection = AdbConnectionManager(this.context, adbPreferences, adbKeys)
    private val adbSetup = AdbSetupManager(this.context, adbPreferences, adbKeys, adbConnection, suRunner)
    private val adbCoordinator = AdbRootCoordinator(this.context, adbConnection)
    private var safeModeEnabled = false

    fun snapshot(): TimerSnapshot {
        val snap = timerDeviceSnapshot(safeModeEnabled, runner.status())
        // Kernel-only match: a known kernel string is sufficient, the device model is not checked.
        return snap.copy(kernelSupported = snap.kernelSupported ||
            (kernelOnlyMatchEnabled() && knownKernelProfile(snap.kernelRelease) != null))
    }
    fun setSafeModeEnabled(enabled: Boolean) { safeModeEnabled = enabled }
    fun kernelOnlyMatchEnabled(): Boolean = preferences.getBoolean(PREF_KERNEL_ONLY_MATCH, false)
    fun setKernelOnlyMatchEnabled(enabled: Boolean) { preferences.edit { putBoolean(PREF_KERNEL_ONLY_MATCH, enabled) } }
    fun selectedManagerPackage(): String? = preferences.getString(ManagerScanner.PREF_KEY, null)?.takeIf { it.isNotBlank() }
    fun setSelectedManagerPackage(pkg: String?) { preferences.edit { putString(ManagerScanner.PREF_KEY, pkg) } }

    suspend fun installedManagers(): List<ManagerScanner.Candidate> = withContext(Dispatchers.IO) {
        ManagerScanner.scan(context.packageManager, context.packageName)
    }

    fun debugSettings() = DebugSettings(
        exportEnabled = preferences.getBoolean("debug_export_enabled", true),
        exportLocation = normalizeDebugLocation(preferences.getString("debug_export_location", null)),
    )

    fun setDebugExportEnabled(enabled: Boolean) { preferences.edit { putBoolean("debug_export_enabled", enabled) } }
    fun setDebugExportLocation(location: String, treeUri: String? = null) {
        treeUri?.let {
            context.contentResolver.takePersistableUriPermission(Uri.parse(it),
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
        }
        preferences.edit {
            putString("debug_export_location", normalizeDebugLocation(location))
            putString("debug_export_tree_uri", treeUri)
        }
    }
    fun requestShizukuPermission() = runner.requestPermission()
    fun setShizukuStatusListener(listener: (() -> Unit)?) = runner.setStatusListener(listener)
    fun close() = runner.close()

    fun adbSettings(): AdbRootSettings = adbPreferences.settings()
    fun adbLocalSnapshot(): AdbSetupSnapshot = adbSetup.localSnapshot()
    fun adbLinkStatus(): AdbLinkStatus = adbConnection.status()
    fun setAdbManualEnabled(enabled: Boolean) { adbPreferences.manualAdbEnabled = enabled }

    suspend fun adbRefreshSetup(): AdbSetupSnapshot = adbSetup.snapshot()

    internal suspend fun adbApplyPersistPort(): SetupActionResult = adbSetup.applyPersistPort()
    internal suspend fun adbInstallKey(): SetupActionResult = adbSetup.installKey()
    internal suspend fun adbResetSetup(): SetupActionResult = adbSetup.resetSetup()

    fun uptimeCooldownSeconds(): Int = preferences.getInt("uptime_cooldown_seconds", 60)
    fun setUptimeCooldownSeconds(seconds: Int) {
        preferences.edit { putInt("uptime_cooldown_seconds", seconds) }
    }

    suspend fun run(diagnose: Boolean, onLog: (String) -> Unit): Int =
        runLogged("Shizuku", if (diagnose) "diagnose" else "timer", diagnose, onLog) { log, debugDir ->
            if (diagnose) runner.runDiagnose(log) else runner.run(
                safeModeEnabled,
                debugDir,
                selectedManagerPackage(),
                log,
            )
        }

    suspend fun runAdb(diagnose: Boolean, safeMode: Boolean, onLog: (String) -> Unit): Int =
        runLogged("ADB", if (diagnose) "diagnose" else "timer", diagnose, onLog) { log, _ ->
            adbCoordinator.runManual(safeMode, selectedManagerPackage(), diagnose, log)
        }

    private suspend fun runLogged(
        mode: String,
        kind: String,
        diagnose: Boolean,
        onLog: (String) -> Unit,
        execute: suspend ((String) -> Unit, String?) -> Int,
    ): Int {
        val settings = debugSettings()
        val archive = if (settings.exportEnabled) runCatching {
            DebugAttackLog.open(context, kind, settings.exportLocation,
                preferences.getString("debug_export_tree_uri", null)?.let(Uri::parse))
        }.getOrNull() else null
        if (settings.exportEnabled && archive == null) onLog("<k> warning: cannot create debug log; choose Save location again")
        var writeFailureReported = false
        val log: (String) -> Unit = { line ->
            val previouslyUsedFallback = archive?.usedFallback
            val write = runCatching { archive?.append(line) }
            if (write.isFailure && !writeFailureReported) {
                writeFailureReported = true
                onLog("<k> warning: cannot write debug log; file logging unavailable")
            }
            if (write.isSuccess && archive != null && previouslyUsedFallback == false && archive.usedFallback) {
                onLog("<k> warning: SAF log write failed; continuing debug log: ${archive.folderPath}/${archive.displayName}")
            }
            onLog(line)
        }
        return try {
            if (archive?.usedFallback == true) {
                log("<k> warning: cannot write to selected SAF folder; using MediaStore Downloads")
            }
            log("<k> TimerZ9Turbo ${BuildConfig.VERSION_NAME}+${BuildConfig.VERSION_CODE} build ${BuildInfo.BUILD_TIME_LABEL}")
            log("<k> Device: ${Build.MANUFACTURER} ${Build.MODEL} (${Build.DEVICE})")
            log("<k> Root mode: $mode")
            log("<k> Binary timer path: /data/local/tmp/timer")

            if (!diagnose) {
                val cooldownSec = uptimeCooldownSeconds()
                val uptimeSec = SystemClock.elapsedRealtime() / 1000L
                val remaining = if (cooldownSec > 0 && uptimeSec < cooldownSec) cooldownSec - uptimeSec else 0L
                if (remaining > 0L) {
                    log("<k> Uptime cooldown: scheduled (${remaining}s remaining | uptime: ${uptimeSec}s / target: ${cooldownSec}s)")
                    log("<s> Waiting for uptime cooldown (${remaining}s remaining)...")
                    for (sec in remaining downTo 1) {
                        if (sec == remaining || sec % 10L == 0L || sec <= 5L) {
                            log("<s> Countdown: ${sec}s...")
                        }
                        delay(1000L)
                    }
                    val finishedUptime = SystemClock.elapsedRealtime() / 1000L
                    log("[+] Cooldown completed (uptime: ${finishedUptime}s), starting payload")
                } else if (cooldownSec > 0) {
                    log("<k> Uptime cooldown: none (uptime: ${uptimeSec}s >= target: ${cooldownSec}s)")
                } else {
                    log("<k> Uptime cooldown: disabled (0s)")
                }
            } else {
                log("<k> Uptime cooldown: skipped (diagnose mode)")
            }

            if (!diagnose && kernelOnlyMatchEnabled()) log("<s> warning: kernel-only match on, device model not checked")
            archive?.let { log("<k> debug log: ${it.folderPath}/${it.displayName}") }
            execute(log, archive?.folderFile?.absolutePath)
        } finally {
            runCatching { archive?.close() }
        }
    }
}

internal fun normalizeDebugLocation(value: String?): String = value?.trim()?.trim('/')?.replace(Regex("/{2,}"), "/")
    ?.takeIf { path -> path.isNotEmpty() && path.split('/').none { it == "." || it == ".." } }
    ?: DebugSettings().exportLocation
