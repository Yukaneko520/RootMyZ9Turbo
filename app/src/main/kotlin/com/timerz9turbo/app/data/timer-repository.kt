package com.timerz9turbo.app.data

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.edit
import com.timerz9turbo.app.BuildConfig
import com.timerz9turbo.app.BuildInfo
import com.timerz9turbo.app.domain.model.DebugSettings
import com.timerz9turbo.app.domain.model.TimerSnapshot
import com.timerz9turbo.app.shizuku.ShizukuTimerRunner
import com.timerz9turbo.app.shizuku.knownKernelProfile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class TimerRepository(context: Context) {
    private companion object { const val PREF_KERNEL_ONLY_MATCH = "kernel_only_match" }
    private val context = context.applicationContext
    // Preserve manager and debug preferences from existing installations.
    private val preferences = this.context.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE)
    private val runner = ShizukuTimerRunner(this.context)
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

    suspend fun run(diagnose: Boolean, onLog: (String) -> Unit): Int {
        val settings = debugSettings()
        val archive = if (settings.exportEnabled) runCatching {
            DebugAttackLog.open(context, if (diagnose) "diagnose" else "timer", settings.exportLocation,
                preferences.getString("debug_export_tree_uri", null)?.let(Uri::parse))
        }.getOrNull() else null
        if (settings.exportEnabled && archive == null) onLog("<k> warning: cannot create debug log; choose Save location again")
        val log: (String) -> Unit = { line ->
            runCatching { archive?.append(line) }
            onLog(line)
        }
        return try {
            log("<k> TimerZ9Turbo ${BuildConfig.VERSION_NAME}+${BuildConfig.VERSION_CODE} build ${BuildInfo.BUILD_TIME_LABEL}")
            if (!diagnose && kernelOnlyMatchEnabled()) log("<s> warning: kernel-only match on, device model not checked")
            archive?.let { log("<k> debug log: ${it.folderPath}/${it.displayName}") }
            if (diagnose) runner.runDiagnose(log) else runner.run(
                safeModeEnabled,
                archive?.folderFile?.absolutePath,
                selectedManagerPackage(),
                log,
            )
        } finally {
            runCatching { archive?.close() }
        }
    }
}

internal fun normalizeDebugLocation(value: String?): String = value?.trim()?.trim('/')?.replace(Regex("/{2,}"), "/")
    ?.takeIf { path -> path.isNotEmpty() && path.split('/').none { it == "." || it == ".." } }
    ?: DebugSettings().exportLocation
