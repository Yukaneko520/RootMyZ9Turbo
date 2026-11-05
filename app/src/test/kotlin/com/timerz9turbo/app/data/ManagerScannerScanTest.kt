package com.timerz9turbo.app.data

import android.app.Application
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.io.File

/** Covers the platform-facing scan(): package enumeration, self/system
 * filtering, and libksud.so detection through a real PackageManager. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ManagerScannerScanTest {
    private lateinit var pm: PackageManager
    private lateinit var app: Application

    @Before
    fun setUp() {
        app = RuntimeEnvironment.getApplication() as Application
        pm = app.packageManager
    }

    private fun install(pkg: String, system: Boolean, ksud: Boolean): File {
        // Each package gets its own lib dir so ksud presence is independent.
        val dir = File(app.cacheDir, "libs-${pkg}-${System.nanoTime()}").apply { mkdirs() }
        val info = ApplicationInfo().apply {
            packageName = pkg
            flags = if (system) ApplicationInfo.FLAG_SYSTEM else 0
            nativeLibraryDir = dir.absolutePath
        }
        if (ksud) File(dir, "libksud.so").writeText("stub")
        shadowOf(pm).installPackage(
            PackageInfo().apply {
                packageName = pkg
                applicationInfo = info
            },
        )
        return dir
    }

    private fun writeRenamedDaemon(dir: File, name: String): File {
        val header = ByteArray(64).apply {
            this[0] = 0x7f; this[1] = 'E'.code.toByte()
            this[2] = 'L'.code.toByte(); this[3] = 'F'.code.toByte()
            this[4] = 2; this[5] = 1; this[16] = 3; this[18] = 0xb7.toByte()
        }
        return File(dir, name).apply {
            writeBytes(header + "ksud::\u0000late-load\u0000allow-shell\u0000/data/adb/ksud".toByteArray())
        }
    }

    @Test
    fun `scan keeps user apps and drops self and system apps`() {
        install("me.weishu.kernelsu", system = false, ksud = true)
        install("com.example.no-ksud", system = false, ksud = false)
        install("com.android.settings", system = true, ksud = false)

        val result = ManagerScanner.scan(pm, "com.timerz9turbo.app")
        // User apps without libksud stay visible for the show-all section.
        assertEquals(
            listOf("me.weishu.kernelsu", "com.example.no-ksud"),
            result.map { it.packageName },
        )
        assertTrue(result[0].hasKsud)
        assertTrue(result[0].builtin)
        assertFalse(result[1].hasKsud)
    }

    @Test
    fun `scan drops the self package even if it ships libksud`() {
        install("com.timerz9turbo.app", system = false, ksud = true)
        assertTrue(ManagerScanner.scan(pm, "com.timerz9turbo.app").isEmpty())
    }

    @Test
    fun `scan reports hasKsud false when the lib dir is empty`() {
        install("com.example.bare", system = false, ksud = false)
        val result = ManagerScanner.scan(pm, "com.timerz9turbo.app")
        assertEquals(1, result.size)
        assertFalse(result[0].hasKsud)
        assertFalse(result[0].builtin)
    }

    @Test
    fun `scan detects a renamed daemon by its ELF content`() {
        val dir = install("com.sukisu.ultra", system = false, ksud = false)
        writeRenamedDaemon(dir, "libfdbqiupsrx.so")
        assertTrue(ManagerScanner.scan(pm, "com.timerz9turbo.app").single().hasKsud)
    }

    @Test
    fun `scan does not depend on the randomized name length`() {
        val dir = install("com.sukisu.ultra", system = false, ksud = false)
        writeRenamedDaemon(dir, "libfuture-daemon.so")
        assertTrue(ManagerScanner.scan(pm, "com.timerz9turbo.app").single().hasKsud)
    }

    @Test
    fun `scan rejects ambiguous renamed daemons`() {
        val dir = install("com.sukisu.ultra", system = false, ksud = false)
        writeRenamedDaemon(dir, "libfirst.so")
        writeRenamedDaemon(dir, "libsecond.so")
        assertFalse(ManagerScanner.scan(pm, "com.timerz9turbo.app").single().hasKsud)
    }

    @Test
    fun `resolve keeps the actual package with a renamed daemon`() {
        val dir = install("com.sukisu.ultra", system = false, ksud = false)
        val daemon = writeRenamedDaemon(dir, "libfdbqiupsrx.so")
        assertEquals(
            ManagerScanner.ResolvedKsud("com.sukisu.ultra", daemon),
            ManagerScanner.resolveKsud(pm, "com.sukisu.ultra"),
        )
    }

    @Test
    fun `resolve does not substitute another installed manager for an unavailable selection`() {
        val dir = install("com.sukisu.ultra", system = false, ksud = false)
        writeRenamedDaemon(dir, "libfdbqiupsrx.so")
        assertNull(ManagerScanner.resolveKsud(pm, "com.example.uninstalled"))
    }

    @Test
    fun `resolve requires an explicit manager even when a compatible one is installed`() {
        install("me.weishu.kernelsu", system = false, ksud = true)
        assertNull(ManagerScanner.resolveKsud(pm, null))
        assertNull(ManagerScanner.resolveKsud(pm, ""))
        assertNull(ManagerScanner.resolveKsud(pm, "  "))
    }

    @Test
    fun `resolve uses the selected custom manager rather than a known manager`() {
        install("me.weishu.kernelsu", system = false, ksud = true)
        val dir = install("custom.manager", system = false, ksud = false)
        val daemon = writeRenamedDaemon(dir, "librandom.so")
        assertEquals(
            ManagerScanner.ResolvedKsud("custom.manager", daemon),
            ManagerScanner.resolveKsud(pm, "custom.manager"),
        )
    }
}
