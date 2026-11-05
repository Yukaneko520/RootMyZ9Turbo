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
                if (listOf("KSU_MISSING", "ksud missing", "did not reach euid", "cred write did not land", "parking without reap")
                    .any(line::contains)) return false
            }
            offset = log.filePointer
        }
        Thread.sleep(500)
    }
    return false
}
