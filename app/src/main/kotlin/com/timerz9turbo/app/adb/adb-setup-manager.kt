package com.timerz9turbo.app.adb

import android.content.Context
import com.timerz9turbo.app.R
import com.timerz9turbo.app.domain.model.AdbLinkStatus
import com.timerz9turbo.app.domain.model.AdbSetupSnapshot
import com.timerz9turbo.app.domain.model.SetupActionResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

internal data class ShellResult(val exitCode: Int, val output: String)

internal fun defaultExecuteSu(script: String, timeoutMs: Int = 10_000): ShellResult = runCatching {
    val process = ProcessBuilder("su", "-c", script).start()
    val out = process.inputStream.bufferedReader().readText() + process.errorStream.bufferedReader().readText()
    val finished = process.waitFor(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
    if (!finished) {
        process.destroyForcibly()
        ShellResult(-1, "su execution timed out")
    } else {
        ShellResult(process.exitValue(), out.trim())
    }
}.getOrElse { ShellResult(-1, it.message.orEmpty().ifBlank { "Root (su) not available" }) }

internal class AdbSetupManager(
    private val context: Context,
    private val preferences: AdbRootPreferences,
    private val keys: AdbKeyManager,
    private val connection: AdbConnectionManager,
    private val suRunner: (String) -> ShellResult = ::defaultExecuteSu,
) {
    suspend fun snapshot(): AdbSetupSnapshot = withContext(Dispatchers.IO) {
        val localKey = runCatching { keys.ensure() }.getOrNull()
        var persist: String? = null
        var service: String? = null
        var error: String? = null

        try {
            val shell = executeShell(
                "getprop persist.adb.tcp.port; " +
                    "echo __TZ9_SEP__; getprop service.adb.tcp.port"
            )
            val parts = shell.output.split("__TZ9_SEP__")
            if (parts.size >= 2) {
                persist = parts[0].trim()
                service = parts[1].trim()
            } else if (shell.exitCode != 0) {
                error = "setup query failed (${shell.exitCode}): ${shell.output.trim().take(200)}"
            }
        } catch (linkError: Exception) {
            error = linkError.message.orEmpty().take(300)
        }

        val status = connection.status(ignoreManualSwitch = true)
        val keyAuthorized = status == AdbLinkStatus.READY
        if (keyAuthorized) {
            preferences.keyAuthorized = true
            if (preferences.keyRejected) preferences.keyRejected = false
        } else if (status == AdbLinkStatus.UNAUTHORIZED) {
            preferences.keyAuthorized = false
            preferences.keyRejected = true
            preferences.setupComplete = false
        }

        var allowed = runCatching {
            android.provider.Settings.Global.getString(context.contentResolver, "adb_allowed_connection_time")
        }.getOrNull()?.trim()?.takeIf { it.isNotEmpty() && it != "null" }
            ?: runCatching {
                android.provider.Settings.Global.getLong(context.contentResolver, "adb_allowed_connection_time").toString()
            }.getOrNull()

        if (allowed == null && status == AdbLinkStatus.READY) {
            allowed = runCatching {
                connection.connectForSetup(readTimeoutMs = 2_000).use { client ->
                    val res = client.exec("settings get global adb_allowed_connection_time", timeoutMs = 2_000)
                    if (res.exitCode == 0) res.output.trim().takeIf { it.isNotEmpty() && it != "null" } else null
                }
            }.getOrNull()
        }

        val snapshot = AdbSetupSnapshot(
            persistPort = persist,
            servicePort = service,
            keyFingerprint = localKey?.fingerprint,
            keyFingerprintSha256 = localKey?.sha256Fingerprint,
            adbKeyInstalled = preferences.keyAuthorized,
            adbKeyAuthorized = preferences.keyAuthorized,
            keyRejected = (preferences.keyRejected || status == AdbLinkStatus.UNAUTHORIZED) && !keyAuthorized,
            allowedConnectionTime = allowed,
            linkStatus = status,
            error = error,
        )
        preferences.setupComplete = snapshot.setupComplete
        snapshot
    }

    /** Key and link state that does not need any shell command. */
    fun localSnapshot(): AdbSetupSnapshot {
        val localKey = runCatching { keys.ensure() }.getOrNull()
        val status = connection.status(ignoreManualSwitch = true)
        if (status == AdbLinkStatus.READY) {
            preferences.keyAuthorized = true
            if (preferences.keyRejected) preferences.keyRejected = false
        } else if (status == AdbLinkStatus.UNAUTHORIZED) {
            preferences.keyAuthorized = false
            preferences.keyRejected = true
            preferences.setupComplete = false
        }
        val allowed = runCatching {
            android.provider.Settings.Global.getString(context.contentResolver, "adb_allowed_connection_time")
        }.getOrNull()?.trim()?.takeIf { it.isNotEmpty() && it != "null" }
            ?: runCatching {
                android.provider.Settings.Global.getLong(context.contentResolver, "adb_allowed_connection_time").toString()
            }.getOrNull()
        return AdbSetupSnapshot(
            keyFingerprint = localKey?.fingerprint,
            keyFingerprintSha256 = localKey?.sha256Fingerprint,
            adbKeyAuthorized = preferences.keyAuthorized,
            keyRejected = (preferences.keyRejected || status == AdbLinkStatus.UNAUTHORIZED) && status != AdbLinkStatus.READY,
            allowedConnectionTime = allowed,
            linkStatus = status,
            linkDetail = if (localKey == null) "ADB key is not generated yet" else "",
        )
    }

    /**
     * Applies TCP port 5555 configuration using Root (su).
     * Sets persist.adb.tcp.port=5555, clears service.adb.tcp.port, and restarts adbd.
     */
    suspend fun applyPersistPort(): SetupActionResult = withContext(Dispatchers.IO) {
        try {
            val script = "setprop persist.adb.tcp.port ${AdbSetupSnapshot.ADB_TCP_PORT} && " +
                "setprop service.adb.tcp.port '' && " +
                "setprop ctl.restart adbd"
            val res = suRunner(script)
            if (res.exitCode != 0) {
                val detail = res.output.ifBlank { context.getString(R.string.adb_root_required_apply) }
                return@withContext SetupActionResult(false, detail.take(300))
            }
            restartAdbd()
            SetupActionResult(true)
        } catch (error: Exception) {
            SetupActionResult(false, error.message.orEmpty().take(300))
        }
    }

    /**
     * Authorizes the ADB key via classic ADB protocol handshake.
     */
    suspend fun installKey(): SetupActionResult = withContext(Dispatchers.IO) {
        try {
            keys.ensure()
            val restartFailed = preferences.keyRejected && !restartAdbd()
            val result = connection.authorize()
            if (result.status == AdbLinkStatus.READY) {
                preferences.keyRejected = false
                preferences.keyAuthorized = true
                SetupActionResult(true)
            } else {
                if (result.status == AdbLinkStatus.UNAUTHORIZED) {
                    preferences.keyRejected = true
                    preferences.keyAuthorized = false
                    preferences.setupComplete = false
                }
                val detail = if (restartFailed) {
                    context.getString(R.string.adb_key_manual_retry)
                } else if (result.status == AdbLinkStatus.UNREACHABLE && result.detail.isBlank()) {
                    context.getString(R.string.adb_status_unreachable)
                } else if (result.status == AdbLinkStatus.UNAUTHORIZED && result.detail.isBlank()) {
                    context.getString(R.string.adb_key_rejected)
                } else {
                    result.detail
                }
                SetupActionResult(false, detail.take(300))
            }
        } catch (error: Exception) {
            SetupActionResult(false, error.message.orEmpty().take(300))
        }
    }

    /**
     * Resets ADB setup using Root (su).
     * Clears persist.adb.tcp.port, service.adb.tcp.port, deletes adb_allowed_connection_time,
     * and restarts adbd.
     */
    suspend fun resetSetup(): SetupActionResult = withContext(Dispatchers.IO) {
        try {
            val script = "setprop persist.adb.tcp.port '' && " +
                "setprop service.adb.tcp.port '' && " +
                "settings delete global adb_allowed_connection_time; " +
                "setprop ctl.restart adbd"
            val res = suRunner(script)
            if (res.exitCode != 0) {
                val detail = res.output.ifBlank { context.getString(R.string.adb_root_required_reset) }
                preferences.setupComplete = false
                return@withContext SetupActionResult(false, detail.take(300))
            }
            preferences.setupComplete = false
            SetupActionResult(true)
        } catch (e: Exception) {
            preferences.setupComplete = false
            SetupActionResult(false, e.message.orEmpty().take(300))
        }
    }

    private suspend fun restartAdbd(): Boolean {
        val ok = runCatching { suRunner("setprop ctl.restart adbd").exitCode == 0 }
            .getOrDefault(false)
        if (ok) {
            delay(300)
            for (i in 0 until 14) {
                if (adbPortOpen()) return true
                delay(200)
            }
        } else {
            delay(900)
        }
        return ok
    }

    private fun executeShell(script: String, timeoutMs: Int = 10_000): ShellResult {
        // 1. If ADB client is connected on loopback, execute via ADB shell
        val adbRes = runCatching {
            connection.connectForSetup(readTimeoutMs = timeoutMs).use { client ->
                val result = client.exec(script, timeoutMs = timeoutMs)
                ShellResult(result.exitCode, result.output)
            }
        }.getOrNull()
        if (adbRes != null) return adbRes

        // 2. Fallback to standard local ProcessBuilder
        return runCatching {
            val process = ProcessBuilder("/system/bin/sh", "-c", script).start()
            val out = process.inputStream.bufferedReader().readText() + process.errorStream.bufferedReader().readText()
            process.waitFor(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
            ShellResult(process.exitValue(), out)
        }.getOrElse { ShellResult(-1, it.message.orEmpty()) }
    }
}
