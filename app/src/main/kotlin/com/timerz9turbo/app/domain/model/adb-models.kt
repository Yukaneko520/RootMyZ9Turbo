package com.timerz9turbo.app.domain.model

/** State of the loopback ADB link used by the Shizuku-free root path. */
enum class AdbLinkStatus {
    /** Manual ADB root is disabled. */
    DISABLED,

    /** The key or the one-time setup is missing. */
    NOT_CONFIGURED,

    /** Nothing is listening on 127.0.0.1:5555. */
    UNREACHABLE,

    /** adbd answered but rejected the app key. */
    UNAUTHORIZED,

    /** adbd accepted the app key. */
    READY,
}

enum class AdbSetupCheck { UNKNOWN, OK, WARN, FAIL }

/**
 * Snapshot of the one-time setup. Nullable values mean "not checked yet";
 * an empty string is a real adb property value.
 */
data class AdbSetupSnapshot(
    val persistPort: String? = null,
    val servicePort: String? = null,
    val keyFingerprint: String? = null,
    val keyFingerprintSha256: String? = null,
    val adbKeyInstalled: Boolean = false,
    val adbKeyAuthorized: Boolean = false,
    val keyRejected: Boolean = false,
    val allowedConnectionTime: String? = null,
    val linkStatus: AdbLinkStatus = AdbLinkStatus.DISABLED,
    val linkDetail: String = "",
    val busy: Boolean = false,
    val error: String? = null,
) {
    val portOk: Boolean get() = persistPort == ADB_TCP_PORT.toString()
    val servicePortEmpty: Boolean get() = servicePort.isNullOrEmpty()

    // A READY link proves adbd/system_server accepted the key.
    // If UNAUTHORIZED or rejected, key is definitely not accepted.
    val keyOk: Boolean get() = !keyFingerprint.isNullOrBlank() &&
        linkStatus != AdbLinkStatus.UNAUTHORIZED &&
        !keyRejected &&
        (linkStatus == AdbLinkStatus.READY || adbKeyInstalled || adbKeyAuthorized)

    val allowedTimeOk: Boolean get() = allowedConnectionTime == "0" || allowedConnectionTime?.toLongOrNull() == 0L

    /** Conditions persisted for the next reboot. Root is checked only for this boot. */
    val setupComplete: Boolean get() = portOk && servicePortEmpty && keyOk

    companion object {
        const val ADB_TCP_PORT = 5555
    }
}

data class AdbRootSettings(
    val manualEnabled: Boolean = false,
    val setupComplete: Boolean = false,
    val keyAuthorized: Boolean = false,
)

internal data class SetupActionResult(val ok: Boolean, val detail: String = "")

internal data class AdbProbeResult(val status: AdbLinkStatus, val detail: String = "")
