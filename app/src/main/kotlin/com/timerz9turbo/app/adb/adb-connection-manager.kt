package com.timerz9turbo.app.adb

import android.content.Context
import com.timerz9turbo.app.domain.model.AdbLinkStatus
import com.timerz9turbo.app.domain.model.AdbProbeResult
import java.io.IOException

internal class AdbConnectionManager(
    @Suppress("UNUSED_PARAMETER") context: Context,
    private val preferences: AdbRootPreferences,
    private val keys: AdbKeyManager,
) {
    fun status(ignoreManualSwitch: Boolean = false): AdbLinkStatus {
        if (!ignoreManualSwitch) {
            if (!preferences.manualAdbEnabled) return AdbLinkStatus.DISABLED
            if (!preferences.setupComplete) return AdbLinkStatus.NOT_CONFIGURED
        }
        val authenticator = keys.authenticator() ?: return AdbLinkStatus.NOT_CONFIGURED
        return try {
            AdbClient(
                authenticator = authenticator,
                connectTimeoutMs = 1_500,
                defaultReadTimeoutMs = 2_500,
            ).use { it.connect() }
            AdbLinkStatus.READY
        } catch (_: AdbUnauthorizedException) {
            AdbLinkStatus.UNAUTHORIZED
        } catch (_: AdbKeyUnavailableException) {
            AdbLinkStatus.NOT_CONFIGURED
        } catch (_: IOException) {
            AdbLinkStatus.UNREACHABLE
        } catch (_: Exception) {
            AdbLinkStatus.UNREACHABLE
        }
    }

    /** Setup may use the link before the manual switch is turned on. */
    fun connectForSetup(readTimeoutMs: Int = 20_000): AdbClient {
        val authenticator = keys.authenticator() ?: throw AdbKeyUnavailableException()
        return AdbClient(
            authenticator = authenticator,
            connectTimeoutMs = 2_500,
            defaultReadTimeoutMs = readTimeoutMs,
        ).also { it.connect() }
    }

    /**
     * One authorization attempt: adbd forwards the public key to system_server,
     * which shows the prompt. Blocks until the user answers or it times out,
     * so never call this from status/probe.
     */
    fun authorize(readTimeoutMs: Int = 95_000): AdbProbeResult {
        val authenticator = keys.authenticator()
            ?: return AdbProbeResult(AdbLinkStatus.NOT_CONFIGURED, "ADB key is not generated yet")
        return try {
            AdbClient(
                authenticator = authenticator,
                connectTimeoutMs = 2_500,
                defaultReadTimeoutMs = readTimeoutMs,
                requestAuthorization = true,
            ).use { it.connect() }
            AdbProbeResult(AdbLinkStatus.READY)
        } catch (error: AdbUnauthorizedException) {
            AdbProbeResult(AdbLinkStatus.UNAUTHORIZED, error.message.orEmpty())
        } catch (error: AdbKeyUnavailableException) {
            AdbProbeResult(AdbLinkStatus.NOT_CONFIGURED, error.message.orEmpty())
        } catch (error: Exception) {
            AdbProbeResult(AdbLinkStatus.UNREACHABLE, error.message.orEmpty())
        }
    }

    fun connectForUse(readTimeoutMs: Int = 30_000): AdbClient {
        if (!preferences.manualAdbEnabled) throw AdbProtocolException("Manual ADB root is disabled")
        if (!preferences.setupComplete) throw AdbProtocolException("ADB setup is incomplete")
        return connectForSetup(readTimeoutMs)
    }

    fun probe(): AdbProbeResult {
        val current = status(ignoreManualSwitch = true)
        if (current != AdbLinkStatus.READY) return AdbProbeResult(current)
        return try {
            connectForSetup(readTimeoutMs = 8_000).use { client ->
                val result = client.exec("id; grep -E '^Seccomp:' /proc/self/status", timeoutMs = 5_000)
                AdbProbeResult(current, result.output.trim())
            }
        } catch (error: AdbUnauthorizedException) {
            AdbProbeResult(AdbLinkStatus.UNAUTHORIZED, error.message.orEmpty())
        } catch (error: Exception) {
            AdbProbeResult(AdbLinkStatus.UNREACHABLE, error.message.orEmpty())
        }
    }
}
