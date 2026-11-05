package com.timerz9turbo.app.domain.model

data class TimerSnapshot(
    val deviceName: String,
    val kernelRelease: String,
    val socName: String,
    val androidVersion: String,
    val kernelSupported: Boolean,
    val safeModeEnabled: Boolean,
    val shizukuStatus: ShizukuStatus,
)

enum class ShizukuStatus { NOT_RUNNING, PERMISSION_REQUIRED, READY }
enum class LogTone { Default, Error, Success, Warning, Progress, Kotlin, Shizuku }
data class LogEntry(val text: String, val tone: LogTone)

data class DebugSettings(
    val exportEnabled: Boolean = true,
    val exportLocation: String = "Download/timerZ9Turbo-log",
)
