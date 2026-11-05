package com.timerz9turbo.app.data

import java.io.File
import java.io.IOException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class KsudLibraryTest {
    @get:Rule val temporary = TemporaryFolder()
    private val markers = listOf("ksud::", "late-load", "allow-shell", "/data/adb/ksud")

    private fun header() = ByteArray(64).apply {
        this[0] = 0x7f; this[1] = 'E'.code.toByte(); this[2] = 'L'.code.toByte()
        this[3] = 'F'.code.toByte(); this[4] = 2; this[5] = 1
        this[16] = 3; this[18] = 0xb7.toByte()
    }

    private fun library(name: String = "librandom.so", content: ByteArray =
        header() + markers.joinToString("\u0000").toByteArray(),
    ) = File(temporary.root, name).apply { writeBytes(content) }

    @Test
    fun `legacy name wins even when renamed candidates are ambiguous`() {
        val legacy = library("libksud.so", "legacy".toByteArray())
        library("libone.so")
        library("libtwo.so")
        assertEquals(legacy, KsudLibrary.find(temporary.root.path))
    }

    @Test
    fun `renamed daemon is selected without relying on filename length`() {
        val daemon = library("libany-release-name.so")
        library("libjni.so", header() + "late-load\u0000package-name".toByteArray())
        assertEquals(daemon, KsudLibrary.find(temporary.root.path))
    }

    @Test
    fun `text containing all markers is rejected without ELF header`() {
        library(content = markers.joinToString("\u0000").toByteArray())
        assertNull(KsudLibrary.find(temporary.root.path))
    }

    @Test
    fun `wrong architecture is rejected`() {
        library(content = header().apply { this[18] = 0x3e } + markers.joinToString("\u0000").toByteArray())
        assertNull(KsudLibrary.find(temporary.root.path))
    }

    @Test
    fun `each content marker is required`() {
        markers.forEach { missing ->
            library(content = header() + markers.filterNot { it == missing }.joinToString("\u0000").toByteArray())
            assertNull("Accepted daemon without $missing", KsudLibrary.find(temporary.root.path))
        }
    }

    @Test
    fun `markers spanning read buffers are detected`() {
        val padding = ByteArray(20 + 32 * 1024 - 3 - 64)
        val daemon = library(content = header() + padding + markers.joinToString("\u0000").toByteArray())
        assertEquals(daemon, KsudLibrary.find(temporary.root.path))
    }

    @Test
    fun `multiple matching daemons are rejected`() {
        library("libone.so")
        library("libtwo.so")
        assertNull(KsudLibrary.find(temporary.root.path))
    }

    @Test
    fun `missing and truncated libraries are rejected`() {
        assertNull(KsudLibrary.find(null))
        assertNull(KsudLibrary.find(File(temporary.root, "absent").path))
        library(content = byteArrayOf(0x7f, 0x45, 0x4c, 0x46))
        assertNull(KsudLibrary.find(temporary.root.path))
    }

    @Test
    fun `staging replaces the previous daemon and removes the temporary file`() {
        val source = library()
        val destination = File(temporary.root, "ksud").apply { writeText("previous manager") }
        assertEquals(destination, KsudLibrary.stage(source, destination))
        assertArrayEquals(source.readBytes(), destination.readBytes())
        assertTrue(destination.canRead())
        assertTrue(destination.canExecute())
        assertFalse(File(destination.path + ".new").exists())
    }

    @Test
    fun `staging a missing source preserves the previous daemon`() {
        val destination = File(temporary.root, "ksud").apply { writeText("previous manager") }
        assertThrows(IOException::class.java) {
            KsudLibrary.stage(File(temporary.root, "missing"), destination)
        }
        assertEquals("previous manager", destination.readText())
        assertFalse(File(destination.path + ".new").exists())
    }

    @Test
    fun `failed rename cleans up the prepared file`() {
        val source = library()
        val destination = temporary.newFolder("ksud")
        File(destination, "keep").writeText("existing")
        assertThrows(IOException::class.java) { KsudLibrary.stage(source, destination) }
        assertEquals("existing", File(destination, "keep").readText())
        assertFalse(File(destination.path + ".new").exists())
    }

    @Test
    fun `a broken input stream preserves the installed executable`() {
        val input = library().inputStream().apply { close() }
        val destination = File(temporary.root, "timer").apply { writeText("previous executable") }
        assertThrows(IOException::class.java) { KsudLibrary.stage(input, destination) }
        assertEquals("previous executable", destination.readText())
        assertFalse(File(destination.path + ".new").exists())
    }
}
