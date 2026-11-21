package com.timerz9turbo.app.data

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Guards the packaged native payloads.
 *
 * The exploit binaries are built from `timer-native` and copied into assets by
 * `timer-native/build-timer.cmd`. A stale or truncated copy silently runs the
 * previous code on a device, which is exactly the failure this test prevents.
 */
class TimerAssetTest {
    private val assets = File("src/main/assets")

    private fun asset(name: String) = File(assets, name)

    @Test
    fun `every mapped kernel profile ships a native binary`() {
        for (name in listOf("timer", "timer-6.1.57", "timer-6.1.124")) {
            assertTrue("missing asset $name", asset(name).isFile)
        }
    }

    @Test
    fun `native payloads are static ARM64 executables`() {
        for (name in listOf("timer", "timer-6.1.57", "timer-6.1.124")) {
            val file = asset(name)
            val header = file.inputStream().use { it.readNBytes(20) }
            assertEquals("$name is not ELF", 0x7f, header[0].toInt())
            assertEquals("$name is not ELF", 'E'.code, header[1].toInt())
            assertEquals("$name is not ELF", 'L'.code, header[2].toInt())
            assertEquals("$name is not ELF", 'F'.code, header[3].toInt())
            assertEquals("$name is not 64-bit", 2, header[4].toInt())
            assertEquals("$name is not little-endian", 1, header[5].toInt())
            // e_type ET_EXEC (2) for these static binaries; e_machine AArch64.
            assertEquals("$name is not an executable", 2, header[16].toInt())
            assertEquals("$name is not AArch64", 0xb7, header[18].toInt() and 0xff)
            assertEquals("$name is second AArch64 byte", 0, header[19].toInt())
        }
    }

    @Test
    fun `payloads are large enough to contain the full backend`() {
        for (name in listOf("timer", "timer-6.1.57", "timer-6.1.124")) {
            val size = asset(name).length()
            assertTrue("$name looks truncated ($size bytes)", size > 300_000L)
        }
    }

    @Test
    fun `per-profile payloads differ from each other`() {
        val hashes = listOf("timer", "timer-6.1.57", "timer-6.1.124").map { name ->
            java.security.MessageDigest.getInstance("SHA-256")
                .digest(asset(name).readBytes())
                .joinToString("") { "%02x".format(it) }
        }
        assertEquals("profile payloads must not be copies of one binary", 3, hashes.toSet().size)
    }
}
