package com.timerz9turbo.app.shizuku

import java.io.File
import java.io.RandomAccessFile

internal fun awaitTimerLoaded(
    file: File,
    completion: File,
    confirmKernel: () -> Boolean,
    onLog: (String) -> Unit,
): Boolean {
    var offset = 0L
    val deadline = System.nanoTime() + 150_000_000_000L
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
