package com.timerz9turbo.app.shizuku

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class TimerRuntimeTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test
    fun `selects the backend matching the existing kernel mapping`() {
        assertEquals("timer-6.1.124", timerAssetFor("6.1.124-android14-11-maybe-dirty"))
        assertEquals("timer", timerAssetFor("6.1.145-android14-11-maybe-dirty"))
    }

    @Test(timeout = 3000)
    fun `success is accepted only after the native loaded marker`() {
        val log = temporary.newFile().apply { writeText("[*] starting\r\n\nKSU_LOADED\r\n") }
        val lines = mutableListOf<String>()
        assertTrue(awaitTimerLoaded(log, lines::add))
        assertEquals(listOf("[*] starting", "KSU_LOADED"), lines)
    }

    @Test(timeout = 3000)
    fun `a terminal failure is not hidden by later diagnostics`() {
        val log = temporary.newFile().apply { writeText("[ksu] ksud missing\nextra diagnostics\n") }
        val lines = mutableListOf<String>()
        assertFalse(awaitTimerLoaded(log, lines::add))
        assertEquals(listOf("[ksu] ksud missing"), lines)
    }

    @Test(timeout = 3000)
    fun `missing module ends monitoring immediately`() {
        val log = temporary.newFile().apply { writeText("KSU_MISSING\n") }
        assertFalse(awaitTimerLoaded(log) {})
    }

    @Test(timeout = 3000)
    fun `missing selected manager ends monitoring immediately`() {
        val log = temporary.newFile().apply { writeText("[ksu] manager package missing\n") }
        assertFalse(awaitTimerLoaded(log) {})
    }

    @Test(timeout = 3000)
    fun `credential holder parking does not stop monitoring the detached ksud worker`() {
        val log = temporary.newFile().apply {
            writeText(
                "[ksu] waiting for late-load to finish\n" +
                    "[+] child exit status=0\n" +
                    "[!] fake cred page held; reboot to clean -- parking without reap (zombie held)\n" +
                    "[ksu] late-load finished\nKSU_LOADED\n"
            )
        }
        val lines = mutableListOf<String>()
        assertTrue(awaitTimerLoaded(log, lines::add))
        assertEquals("KSU_LOADED", lines.last())
    }

    @Test(timeout = 3000)
    fun `parking after a failed native stage remains a terminal failure`() {
        val log = temporary.newFile().apply {
            writeText("[!] fake cred write failed -- parking without reap (zombie held)\n")
        }
        assertFalse(awaitTimerLoaded(log) {})
    }

    @Test
    fun `temporary ksud stays available until the operation completes then is removed`() {
        val daemon = temporary.newFile().apply { writeText("staged payload") }
        val result = withTemporaryKsud(daemon, {}) {
            assertEquals("staged payload", it.readText())
            0
        }
        assertEquals(0, result)
        assertFalse(daemon.exists())
    }

    @Test
    fun `temporary ksud is removed without hiding the original failure`() {
        val daemon = temporary.newFile()
        val failure = IllegalStateException("late-load failed")
        try {
            withTemporaryKsud(daemon, { error("callback disconnected") }) { throw failure }
            throw AssertionError("Failure was swallowed")
        } catch (caught: IllegalStateException) {
            org.junit.Assert.assertSame(failure, caught)
        }
        assertFalse(daemon.exists())
    }
}
