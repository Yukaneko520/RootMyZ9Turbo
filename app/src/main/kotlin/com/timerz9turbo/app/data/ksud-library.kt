package com.timerz9turbo.app.data

import java.io.DataInputStream
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING

/** Resolves release builds whose packaged daemon name is randomized. */
object KsudLibrary {
    private val markers = listOf("ksud::", "late-load", "allow-shell", "/data/adb/ksud")
    private val overlap = markers.maxOf { it.length } - 1

    fun find(nativeLibraryDir: String?): File? {
        if (nativeLibraryDir.isNullOrBlank()) return null
        val directory = File(nativeLibraryDir)
        File(directory, "libksud.so").takeIf { it.isFile }?.let { return it }
        // Two matches are ambiguous; never choose an arbitrary daemon.
        return directory.listFiles().orEmpty().asSequence()
            .filter { it.isFile && it.extension == "so" && isRenamedDaemon(it) }
            .take(2).toList().singleOrNull()
    }

    private fun isRenamedDaemon(file: File): Boolean = runCatching {
        DataInputStream(file.inputStream().buffered()).use { input ->
            val header = ByteArray(20)
            input.readFully(header)
            // Timer is ARM64-only; ELF64 little-endian AArch64, executable or PIE.
            if (header[0] != 0x7f.toByte() || header[1] != 'E'.code.toByte() ||
                header[2] != 'L'.code.toByte() || header[3] != 'F'.code.toByte() ||
                header[4] != 2.toByte() || header[5] != 1.toByte() ||
                header[16].toInt() !in 2..3 || header[17] != 0.toByte() ||
                header[18] != 0xb7.toByte() || header[19] != 0.toByte()
            ) return@use false

            val found = BooleanArray(markers.size)
            val buffer = ByteArray(32 * 1024)
            var tail = ""
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                val text = tail + String(buffer, 0, count, Charsets.ISO_8859_1)
                markers.forEachIndexed { index, marker ->
                    if (!found[index] && text.contains(marker)) found[index] = true
                }
                if (found.all { it }) return@use true
                // Retain split strings without loading an entire library into memory.
                tail = text.takeLast(overlap)
            }
            false
        }
    }.getOrDefault(false)

    /** Same-directory rename keeps Timer from observing a partially copied daemon. */
    fun stage(source: File, destination: File): File {
        val temporary = File(destination.absolutePath + ".new")
        try {
            source.inputStream().use { input -> temporary.outputStream().use { output -> input.copyTo(output) } }
            check(temporary.setReadable(true, false)) { "Cannot make ksud readable" }
            check(temporary.setWritable(false, false) && temporary.setWritable(true, true)) {
                "Cannot set ksud write permissions"
            }
            check(temporary.setExecutable(true, false)) { "Cannot make ksud executable" }
            Files.move(temporary.toPath(), destination.toPath(), ATOMIC_MOVE, REPLACE_EXISTING)
            return destination
        } finally {
            temporary.delete()
        }
    }
}
