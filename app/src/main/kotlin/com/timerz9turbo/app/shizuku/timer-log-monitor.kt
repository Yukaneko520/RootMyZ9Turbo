package com.timerz9turbo.app.shizuku

import java.io.File
import java.io.RandomAccessFile

/**
 * Streams the native log while the run is active, then requires both the
 * native completion byte and a positive kernel version from the manager.
 *
 * The native completion byte means the native run finished; it does not mean
 * the KernelSU module has registered its proc node yet.  `debug version`
 * answers `Kernel Version: 0` for a module that is loaded but not initialised,
 * so the confirmation is retried for a bounded window instead of being taken
 * from a single sample.  A single sample made a fully-rooted run report
 * "KernelSU not confirmed" whenever it landed in that window.
 */
internal fun awaitTimerLoaded(
    file: File,
    completion: File,
    confirmKernel: () -> Boolean,
    onLog: (String) -> Unit,
): Boolean {
    var offset = 0L
    val deadline = System.nanoTime() + TimerTiming.LOG_WATCH_MS * 1_000_000L
    var nativeCompleted = false
    var confirmDeadline = 0L
    while (System.nanoTime() < deadline) {
        if (file.isFile) RandomAccessFile(file, "r").use { log ->
            if (offset > log.length()) offset = 0
            log.seek(offset)
            while (true) {
                val line = (log.readLine() ?: break).trimEnd('\r')
                if (line.isBlank()) continue
                onLog(line)
            }
            offset = log.filePointer
        }
        if (!nativeCompleted && completion.isFile && completion.length() > 0L) {
            val completed = completion.length() == 1L && completion.inputStream().use { it.read() == 1 }
            if (!completed) return false
            nativeCompleted = true
            confirmDeadline = System.nanoTime() + TimerTiming.CONFIRM_WATCH_MS * 1_000_000L
        }
        if (nativeCompleted) {
            if (confirmKernel()) return true
            if (System.nanoTime() >= confirmDeadline) return false
        }
        Thread.sleep(500)
    }
    return false
}

internal fun kernelVersionFromOutput(output: String): Int? =
    Regex("(?m)^Kernel Version:\\s*([0-9]+)\\s*$").find(output)
        ?.groupValues?.get(1)?.toIntOrNull()?.takeIf { it > 0 }
