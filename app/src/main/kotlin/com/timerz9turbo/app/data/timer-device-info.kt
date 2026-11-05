package com.timerz9turbo.app.data

import android.annotation.SuppressLint
import android.os.Build
import com.timerz9turbo.app.domain.model.ShizukuStatus
import com.timerz9turbo.app.domain.model.TimerSnapshot
import java.util.Locale

internal fun timerDeviceSnapshot(safeMode: Boolean, status: ShizukuStatus): TimerSnapshot {
    val identifiers = "${systemProperty("ro.product.device")} ${Build.DEVICE} ${Build.PRODUCT} ${Build.MODEL}".uppercase(Locale.ROOT)
    return TimerSnapshot(
        deviceName = resolveDeviceName(), kernelRelease = System.getProperty("os.version", "unknown").orEmpty(),
        socName = resolveSocName(), androidVersion = "${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
        kernelSupported = identifiers.contains("PD2352") || identifiers.contains("V2352"),
        safeModeEnabled = safeMode, shizukuStatus = status,
    )
}

@SuppressLint("PrivateApi")
private fun systemProperty(key: String): String = try {
    val properties = Class.forName("android.os.SystemProperties")
    properties.getMethod("get", String::class.java).invoke(null, key) as? String ?: ""
} catch (_: Throwable) {
    ""
}

private fun validDeviceName(value: String?): String? =
    value?.trim()?.takeIf { it.isNotEmpty() && !it.contains("unknown", true) && !it.contains("null", true) }

private fun resolveDeviceName(): String {
    val manufacturer = Build.MANUFACTURER.orEmpty()
    return validDeviceName(systemProperty("ro.vivo.market.name")) ?: listOfNotNull(
        manufacturer, Build.BRAND.orEmpty().takeIf { !it.equals(manufacturer, true) }, Build.MODEL.orEmpty(),
    ).filter { it.isNotBlank() }.joinToString(" ")
}

private fun resolveSocName(): String = listOf(
    systemProperty("ro.soc.manufacturer"),
    systemProperty("ro.soc.model"),
).mapNotNull(::validDeviceName).joinToString(" ").ifBlank { "unknown" }

