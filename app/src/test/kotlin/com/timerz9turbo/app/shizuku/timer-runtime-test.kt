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
}
