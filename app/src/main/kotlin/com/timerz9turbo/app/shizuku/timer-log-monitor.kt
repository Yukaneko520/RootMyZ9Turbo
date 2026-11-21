package com.timerz9turbo.app.shizuku

import java.io.File
import java.io.RandomAccessFile

/**
 * Streams the native log while the run is active, then requires both the
 * native completion byte and a positive kernel version from the manager.
 *
 * The completion byte means the native run finished.  The native stage script
 * already waits for `ksud late-load` to exit before the child does, so one
 * positive `debug version` sample is enough; a zero answer means the module is
 * not registered and every recorded run that reported it also carried a
 * native failure signature.
 */
internal fun awaitTimerLoaded(
    file: File,
    completion: File,
    confirmKernel: () -> Boolean,
    onLog: (String) -> Unit,
): Boolean {
    var offset = 0L
    val deadline = System.nanoTime() + TimerTiming.LOG_WATCH_MS * 1_000_000L
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
        // The native holder writes one byte (1) when its run ends; log wording is irrelevant.
        if (completion.isFile && completion.length() > 0L) {
            val completed = completion.length() == 1L && completion.inputStream().use { it.read() == 1 }
            return completed && confirmKernel()
        }
        Thread.sleep(500)
    }
    return false
}

internal fun kernelVersionFromOutput(output: String): Int? =
    Regex("(?m)^Kernel Version:\\s*([0-9]+)\\s*$").find(output)
        ?.groupValues?.get(1)?.toIntOrNull()?.takeIf { it > 0 }
