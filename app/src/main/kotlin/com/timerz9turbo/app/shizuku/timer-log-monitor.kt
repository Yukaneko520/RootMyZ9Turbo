package com.timerz9turbo.app.shizuku

import java.io.File
import java.io.RandomAccessFile

internal fun awaitTimerLoaded(file: File, onLog: (String) -> Unit): Boolean {
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
                if (line.contains("KSU_LOADED")) return true
                // The credential holder can park while the detached ksud worker is still finishing.
                if (line.contains("parking without reap") && !line.contains("fake cred page held; reboot to clean"))
                    return false
                if (listOf("KSU_MISSING", "manager package missing", "ksud missing", "did not reach euid", "cred write did not land")
                    .any(line::contains)) return false
            }
            offset = log.filePointer
        }
        Thread.sleep(500)
    }
    return false
}
