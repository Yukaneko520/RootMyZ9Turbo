package com.timerz9turbo.app.shizuku

import java.io.File
import kotlin.concurrent.thread
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class TimerRuntimeTest {
    @get:Rule val temporary = TemporaryFolder()

    private fun completed() = temporary.newFile().apply { writeBytes(byteArrayOf(1)) }

    @Test
    fun `selects the backend matching the existing kernel mapping`() {
        assertEquals("timer-6.1.57", timerAssetFor("6.1.57-android14-11-maybe-dirty"))
        assertEquals("timer-6.1.124", timerAssetFor("6.1.124-android14-11-maybe-dirty"))
        assertEquals("timer", timerAssetFor("6.1.145-android14-11-maybe-dirty"))
    }

    @Test(timeout = 3000)
    fun `success log cannot bypass kernel confirmation`() {
        val log = temporary.newFile().apply { writeText("[*] starting\r\n\nKSU_LOADED\r\n") }
        val lines = mutableListOf<String>()
        assertFalse(awaitTimerLoaded(log, completed(), confirmKernel = { false }, onLog = lines::add))
        assertEquals(listOf("[*] starting", "KSU_LOADED"), lines)
    }

    @Test(timeout = 3000)
    fun `native completion and kernel confirmation work without any logs`() {
        assertTrue(awaitTimerLoaded(temporary.newFile(), completed(), confirmKernel = { true }) {})
    }

    @Test(timeout = 3000)
    fun `human log wording cannot override the actual kernel state`() {
        for (message in listOf("KSU_MISSING", "manager package missing", "parking without reap", "new wording")) {
            val log = temporary.newFile().apply { writeText(message + "\n") }
            assertTrue(awaitTimerLoaded(log, completed(), confirmKernel = { true }) {})
        }
    }

    @Test(timeout = 3000)
    fun `invalid completion events never trigger kernel confirmation`() {
        for (event in listOf(byteArrayOf(0), byteArrayOf(1, 1), "1".toByteArray())) {
            val completion = temporary.newFile().apply { writeBytes(event) }
            var probes = 0
            assertFalse(awaitTimerLoaded(temporary.newFile(), completion, confirmKernel = { probes++; true }) {})
            assertEquals(0, probes)
        }
    }

    @Test(timeout = 3000)
    fun `an empty completion file stays pending until native writes the event`() {
        val completion = temporary.newFile()
        var probes = 0
        val writer = thread(isDaemon = true) {
            Thread.sleep(100)
            completion.writeBytes(byteArrayOf(1))
        }
        try {
            assertTrue(awaitTimerLoaded(temporary.newFile(), completion, confirmKernel = { probes++; true }) {})
            assertEquals(1, probes)
        } finally {
            writer.join()
        }
    }

    @Test
    fun `only a positive kernel version confirms the loaded driver`() {
        assertEquals(41150, kernelVersionFromOutput("Kernel Version: 41150\r\n"))
        assertNull(kernelVersionFromOutput("Kernel Version: 0\n"))
        assertNull(kernelVersionFromOutput("ksud 4.3.0-r2 (uapi: 6)\n"))
        assertNull(kernelVersionFromOutput("Kernel Version: -1\n"))
        assertNull(kernelVersionFromOutput("Kernel Version: 9999999999999\n"))
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
